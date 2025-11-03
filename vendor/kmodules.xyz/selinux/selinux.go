/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package selinux

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opencontainers/selinux/go-selinux"
	"github.com/opencontainers/selinux/go-selinux/label"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// SELinuxLabelTranslator translates v1.SELinuxOptions of a process to SELinux file label.
type SELinuxLabelTranslator interface {
	// SELinuxOptionsToFileLabel returns SELinux file label for given SELinuxOptions
	// of a container process.
	// When Role, User or Type are empty, they're read from the system defaults.
	// It returns "" and no error on platforms that do not have SELinux enabled
	// or don't support SELinux at all.
	SELinuxOptionsToFileLabel(opts *v1.SELinuxOptions) (string, error)

	// SELinuxEnabled returns true when the OS has enabled SELinux support.
	SELinuxEnabled() bool
}

// Real implementation of the interface.
// On Linux with SELinux enabled it translates. Otherwise it always returns an empty string and no error.
type translator struct{}

var _ SELinuxLabelTranslator = &translator{}

// NewSELinuxLabelTranslator returns new SELinuxLabelTranslator for the platform.
func NewSELinuxLabelTranslator() SELinuxLabelTranslator {
	return &translator{}
}

// SELinuxOptionsToFileLabel returns SELinux file label for given SELinuxOptions
// of a container process.
// When Role, User or Type are empty, they're read from the system defaults.
// It returns "" and no error on platforms that do not have SELinux enabled
// or don't support SELinux at all.
func (l *translator) SELinuxOptionsToFileLabel(opts *v1.SELinuxOptions) (string, error) {
	if opts == nil {
		return "", nil
	}

	args := contextOptions(opts)
	if len(args) == 0 {
		return "", nil
	}

	processLabel, fileLabel, err := label.InitLabels(args)
	if err != nil {
		// In theory, this should be unreachable. InitLabels can fail only when args contain an unknown option,
		// and all options returned by contextOptions are known.
		return "", &SELinuxLabelTranslationError{msg: err.Error()}
	}
	// InitLabels() may allocate a new unique SELinux label in kubelet memory. The label is *not* allocated
	// in the container runtime. Clear it to avoid memory problems.
	// ReleaseLabel on non-allocated label is NOOP.
	selinux.ReleaseLabel(processLabel)

	return fileLabel, nil
}

// Convert SELinuxOptions to []string accepted by label.InitLabels
func contextOptions(opts *v1.SELinuxOptions) []string {
	if opts == nil {
		return nil
	}
	args := make([]string, 0, 3)
	if opts.User != "" {
		args = append(args, "user:"+opts.User)
	}
	if opts.Role != "" {
		args = append(args, "role:"+opts.Role)
	}
	if opts.Type != "" {
		args = append(args, "type:"+opts.Type)
	}
	if opts.Level != "" {
		args = append(args, "level:"+opts.Level)
	}
	return args
}

func (l *translator) SELinuxEnabled() bool {
	return selinux.GetEnabled()
}

// Fake implementation of the interface for unit tests.
type fakeTranslator struct{}

var _ SELinuxLabelTranslator = &fakeTranslator{}

// NewFakeSELinuxLabelTranslator returns a fake translator for unit tests.
// It imitates a real translator on platforms that do not have SELinux enabled
// or don't support SELinux at all.
func NewFakeSELinuxLabelTranslator() SELinuxLabelTranslator {
	return &fakeTranslator{}
}

// SELinuxOptionsToFileLabel returns SELinux file label for given options.
func (l *fakeTranslator) SELinuxOptionsToFileLabel(opts *v1.SELinuxOptions) (string, error) {
	if opts == nil {
		return "", nil
	}
	// Fill empty values from "system defaults" (taken from Fedora Linux).
	user := opts.User
	if user == "" {
		user = "system_u"
	}

	role := opts.Role
	if role == "" {
		role = "object_r"
	}

	// opts is context of the *process* to run in a container. Translate
	// process type "container_t" to file label type "container_file_t".
	// (The rest of the context is the same for processes and files).
	fileType := opts.Type
	if fileType == "" || fileType == "container_t" {
		fileType = "container_file_t"
	}

	level := opts.Level
	if level == "" {
		// If empty, level is allocated randomly.
		level = "s0:c998,c999"
	}

	ctx := fmt.Sprintf("%s:%s:%s:%s", user, role, fileType, level)
	return ctx, nil
}

func (l *fakeTranslator) SELinuxEnabled() bool {
	return true
}

type SELinuxLabelTranslationError struct {
	msg string
}

func (e *SELinuxLabelTranslationError) Error() string {
	return e.msg
}

func IsSELinuxLabelTranslationError(err error) bool {
	var seLinuxError *SELinuxLabelTranslationError
	return errors.As(err, &seLinuxError)
}

// MultipleSELinuxLabelsError tells that one volume in a pod is mounted in multiple containers and each has a different SELinux label.
type MultipleSELinuxLabelsError struct {
	labels []string
}

func (e *MultipleSELinuxLabelsError) Error() string {
	return fmt.Sprintf("multiple SELinux labels found: %s", strings.Join(e.labels, ","))
}

func (e *MultipleSELinuxLabelsError) Labels() []string {
	return e.labels
}

func IsMultipleSELinuxLabelsError(err error) bool {
	var multiError *MultipleSELinuxLabelsError
	return errors.As(err, &multiError)
}

// GetMountSELinuxLabel returns SELinux labels that should be used to mount the given volume volumeSpec and podSecurityContext.
// It expects effectiveSELinuxContainerLabels as returned by volumeutil.GetPodVolumeNames, i.e. with all SELinuxOptions
// from all containers that use the volume in the pod, potentially expanded with PodSecurityContext.SELinuxOptions,
// if container's SELinuxOptions are nil.
// It does not evaluate the volume access mode! It's up to the caller to check SELinuxMount feature gate,
// it may need to bump different metrics based on feature gates / access modes / label anyway.
func GetMountSELinuxLabel(effectiveSELinuxContainerLabels []*v1.SELinuxOptions, seLinuxTranslator SELinuxLabelTranslator) (string, error) {
	if !seLinuxTranslator.SELinuxEnabled() {
		return "", nil
	}

	// Collect all SELinux options from all containers that use this volume.
	// A set will squash any duplicities.
	labels := sets.New[string]()
	for _, containerLabel := range effectiveSELinuxContainerLabels {
		lbl, err := seLinuxTranslator.SELinuxOptionsToFileLabel(containerLabel)
		if err != nil {
			fullErr := fmt.Errorf("failed to construct SELinux label from context %q: %w", containerLabel, err)
			return "", fullErr
		}
		labels.Insert(lbl)
	}

	// Ensure that all containers use the same SELinux label.
	if labels.Len() > 1 {
		// This volume is used with more than one SELinux label in the pod.
		return "", &MultipleSELinuxLabelsError{labels: labels.UnsortedList()}
	}
	if labels.Len() == 0 {
		return "", nil
	}

	lbl, _ := labels.PopAny()
	return lbl, nil
}

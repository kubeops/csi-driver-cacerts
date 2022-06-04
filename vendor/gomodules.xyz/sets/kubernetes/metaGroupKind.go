package kubernetes

import (
	"reflect"
	"sort"

	"gomodules.xyz/sets"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// sets.MetaGroupKind is a set of metav1.GroupKinds, implemented via map[metav1.GroupKind]struct{} for minimal memory consumption.
type MetaGroupKind map[metav1.GroupKind]sets.Empty

// NewMetaGroupKind creates a MetaGroupKind from a list of values.
func NewMetaGroupKind(items ...metav1.GroupKind) MetaGroupKind {
	ss := make(MetaGroupKind, len(items))
	ss.Insert(items...)
	return ss
}

// MetaGroupKindKeySet creates a MetaGroupKind from a keys of a map[metav1.GroupKind](? extends interface{}).
// If the value passed in is not actually a map, this will panic.
func MetaGroupKindKeySet(theMap interface{}) MetaGroupKind {
	v := reflect.ValueOf(theMap)
	ret := MetaGroupKind{}

	for _, keyValue := range v.MapKeys() {
		ret.Insert(keyValue.Interface().(metav1.GroupKind))
	}
	return ret
}

// Insert adds items to the set.
func (s MetaGroupKind) Insert(items ...metav1.GroupKind) MetaGroupKind {
	for _, item := range items {
		s[item] = sets.Empty{}
	}
	return s
}

// Delete removes all items from the set.
func (s MetaGroupKind) Delete(items ...metav1.GroupKind) MetaGroupKind {
	for _, item := range items {
		delete(s, item)
	}
	return s
}

// Has returns true if and only if item is contained in the set.
func (s MetaGroupKind) Has(item metav1.GroupKind) bool {
	_, contained := s[item]
	return contained
}

// HasAll returns true if and only if all items are contained in the set.
func (s MetaGroupKind) HasAll(items ...metav1.GroupKind) bool {
	for _, item := range items {
		if !s.Has(item) {
			return false
		}
	}
	return true
}

// HasAny returns true if any items are contained in the set.
func (s MetaGroupKind) HasAny(items ...metav1.GroupKind) bool {
	for _, item := range items {
		if s.Has(item) {
			return true
		}
	}
	return false
}

// Difference returns a set of objects that are not in s2
// For example:
// s1 = {a1, a2, a3}
// s2 = {a1, a2, a4, a5}
// s1.Difference(s2) = {a3}
// s2.Difference(s1) = {a4, a5}
func (s MetaGroupKind) Difference(s2 MetaGroupKind) MetaGroupKind {
	result := NewMetaGroupKind()
	for key := range s {
		if !s2.Has(key) {
			result.Insert(key)
		}
	}
	return result
}

// Union returns a new set which includes items in either s1 or s2.
// For example:
// s1 = {a1, a2}
// s2 = {a3, a4}
// s1.Union(s2) = {a1, a2, a3, a4}
// s2.Union(s1) = {a1, a2, a3, a4}
func (s1 MetaGroupKind) Union(s2 MetaGroupKind) MetaGroupKind {
	result := NewMetaGroupKind()
	for key := range s1 {
		result.Insert(key)
	}
	for key := range s2 {
		result.Insert(key)
	}
	return result
}

// Intersection returns a new set which includes the item in BOTH s1 and s2
// For example:
// s1 = {a1, a2}
// s2 = {a2, a3}
// s1.Intersection(s2) = {a2}
func (s1 MetaGroupKind) Intersection(s2 MetaGroupKind) MetaGroupKind {
	var walk, other MetaGroupKind
	result := NewMetaGroupKind()
	if s1.Len() < s2.Len() {
		walk = s1
		other = s2
	} else {
		walk = s2
		other = s1
	}
	for key := range walk {
		if other.Has(key) {
			result.Insert(key)
		}
	}
	return result
}

// IsSuperset returns true if and only if s1 is a superset of s2.
func (s1 MetaGroupKind) IsSuperset(s2 MetaGroupKind) bool {
	for item := range s2 {
		if !s1.Has(item) {
			return false
		}
	}
	return true
}

// Equal returns true if and only if s1 is equal (as a set) to s2.
// Two sets are equal if their membership is identical.
// (In practice, this means same elements, order doesn't matter)
func (s1 MetaGroupKind) Equal(s2 MetaGroupKind) bool {
	return len(s1) == len(s2) && s1.IsSuperset(s2)
}

type sortableSliceOfMetaGroupKind []metav1.GroupKind

func (s sortableSliceOfMetaGroupKind) Len() int           { return len(s) }
func (s sortableSliceOfMetaGroupKind) Less(i, j int) bool { return lessMetaGroupKind(s[i], s[j]) }
func (s sortableSliceOfMetaGroupKind) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// List returns the contents as a sorted metav1.GroupKind slice.
func (s MetaGroupKind) List() []metav1.GroupKind {
	res := make(sortableSliceOfMetaGroupKind, 0, len(s))
	for key := range s {
		res = append(res, key)
	}
	sort.Sort(res)
	return []metav1.GroupKind(res)
}

// UnsortedList returns the slice with contents in random order.
func (s MetaGroupKind) UnsortedList() []metav1.GroupKind {
	res := make([]metav1.GroupKind, 0, len(s))
	for key := range s {
		res = append(res, key)
	}
	return res
}

// Returns a single element from the set.
func (s MetaGroupKind) PopAny() (metav1.GroupKind, bool) {
	for key := range s {
		s.Delete(key)
		return key, true
	}
	var zeroValue metav1.GroupKind
	return zeroValue, false
}

// Len returns the size of the set.
func (s MetaGroupKind) Len() int {
	return len(s)
}

func lessMetaGroupKind(lhs, rhs metav1.GroupKind) bool {
	if lhs.Group < rhs.Group {
		return true
	}
	if lhs.Group > rhs.Group {
		return false
	}
	if lhs.Kind < rhs.Kind {
		return true
	}
	if lhs.Kind > rhs.Kind {
		return false
	}
	return false
}

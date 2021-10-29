package kubernetes

import (
	"reflect"
	"sort"

	"gomodules.xyz/sets"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// sets.GroupKind is a set of schema.GroupKinds, implemented via map[schema.GroupKind]struct{} for minimal memory consumption.
type GroupKind map[schema.GroupKind]sets.Empty

// NewGroupKind creates a GroupKind from a list of values.
func NewGroupKind(items ...schema.GroupKind) GroupKind {
	ss := make(GroupKind, len(items))
	ss.Insert(items...)
	return ss
}

// GroupKindKeySet creates a GroupKind from a keys of a map[schema.GroupKind](? extends interface{}).
// If the value passed in is not actually a map, this will panic.
func GroupKindKeySet(theMap interface{}) GroupKind {
	v := reflect.ValueOf(theMap)
	ret := GroupKind{}

	for _, keyValue := range v.MapKeys() {
		ret.Insert(keyValue.Interface().(schema.GroupKind))
	}
	return ret
}

// Insert adds items to the set.
func (s GroupKind) Insert(items ...schema.GroupKind) GroupKind {
	for _, item := range items {
		s[item] = sets.Empty{}
	}
	return s
}

// Delete removes all items from the set.
func (s GroupKind) Delete(items ...schema.GroupKind) GroupKind {
	for _, item := range items {
		delete(s, item)
	}
	return s
}

// Has returns true if and only if item is contained in the set.
func (s GroupKind) Has(item schema.GroupKind) bool {
	_, contained := s[item]
	return contained
}

// HasAll returns true if and only if all items are contained in the set.
func (s GroupKind) HasAll(items ...schema.GroupKind) bool {
	for _, item := range items {
		if !s.Has(item) {
			return false
		}
	}
	return true
}

// HasAny returns true if any items are contained in the set.
func (s GroupKind) HasAny(items ...schema.GroupKind) bool {
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
func (s GroupKind) Difference(s2 GroupKind) GroupKind {
	result := NewGroupKind()
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
func (s1 GroupKind) Union(s2 GroupKind) GroupKind {
	result := NewGroupKind()
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
func (s1 GroupKind) Intersection(s2 GroupKind) GroupKind {
	var walk, other GroupKind
	result := NewGroupKind()
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
func (s1 GroupKind) IsSuperset(s2 GroupKind) bool {
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
func (s1 GroupKind) Equal(s2 GroupKind) bool {
	return len(s1) == len(s2) && s1.IsSuperset(s2)
}

type sortableSliceOfGroupKind []schema.GroupKind

func (s sortableSliceOfGroupKind) Len() int           { return len(s) }
func (s sortableSliceOfGroupKind) Less(i, j int) bool { return lessGroupKind(s[i], s[j]) }
func (s sortableSliceOfGroupKind) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// List returns the contents as a sorted schema.GroupKind slice.
func (s GroupKind) List() []schema.GroupKind {
	res := make(sortableSliceOfGroupKind, 0, len(s))
	for key := range s {
		res = append(res, key)
	}
	sort.Sort(res)
	return []schema.GroupKind(res)
}

// UnsortedList returns the slice with contents in random order.
func (s GroupKind) UnsortedList() []schema.GroupKind {
	res := make([]schema.GroupKind, 0, len(s))
	for key := range s {
		res = append(res, key)
	}
	return res
}

// Returns a single element from the set.
func (s GroupKind) PopAny() (schema.GroupKind, bool) {
	for key := range s {
		s.Delete(key)
		return key, true
	}
	var zeroValue schema.GroupKind
	return zeroValue, false
}

// Len returns the size of the set.
func (s GroupKind) Len() int {
	return len(s)
}

func lessGroupKind(lhs, rhs schema.GroupKind) bool {
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

package kubernetes

import (
	"reflect"
	"sort"

	"gomodules.xyz/sets"
	"k8s.io/apimachinery/pkg/types"
)

// sets.NamespacedName is a set of types.NamespacedNames, implemented via map[types.NamespacedName]struct{} for minimal memory consumption.
type NamespacedName map[types.NamespacedName]sets.Empty

// NewNamespacedName creates a NamespacedName from a list of values.
func NewNamespacedName(items ...types.NamespacedName) NamespacedName {
	ss := make(NamespacedName, len(items))
	ss.Insert(items...)
	return ss
}

// NamespacedNameKeySet creates a NamespacedName from a keys of a map[types.NamespacedName](? extends interface{}).
// If the value passed in is not actually a map, this will panic.
func NamespacedNameKeySet(theMap interface{}) NamespacedName {
	v := reflect.ValueOf(theMap)
	ret := NamespacedName{}

	for _, keyValue := range v.MapKeys() {
		ret.Insert(keyValue.Interface().(types.NamespacedName))
	}
	return ret
}

// Insert adds items to the set.
func (s NamespacedName) Insert(items ...types.NamespacedName) NamespacedName {
	for _, item := range items {
		s[item] = sets.Empty{}
	}
	return s
}

// Delete removes all items from the set.
func (s NamespacedName) Delete(items ...types.NamespacedName) NamespacedName {
	for _, item := range items {
		delete(s, item)
	}
	return s
}

// Has returns true if and only if item is contained in the set.
func (s NamespacedName) Has(item types.NamespacedName) bool {
	_, contained := s[item]
	return contained
}

// HasAll returns true if and only if all items are contained in the set.
func (s NamespacedName) HasAll(items ...types.NamespacedName) bool {
	for _, item := range items {
		if !s.Has(item) {
			return false
		}
	}
	return true
}

// HasAny returns true if any items are contained in the set.
func (s NamespacedName) HasAny(items ...types.NamespacedName) bool {
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
func (s NamespacedName) Difference(s2 NamespacedName) NamespacedName {
	result := NewNamespacedName()
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
func (s1 NamespacedName) Union(s2 NamespacedName) NamespacedName {
	result := NewNamespacedName()
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
func (s1 NamespacedName) Intersection(s2 NamespacedName) NamespacedName {
	var walk, other NamespacedName
	result := NewNamespacedName()
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
func (s1 NamespacedName) IsSuperset(s2 NamespacedName) bool {
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
func (s1 NamespacedName) Equal(s2 NamespacedName) bool {
	return len(s1) == len(s2) && s1.IsSuperset(s2)
}

type sortableSliceOfNamespacedName []types.NamespacedName

func (s sortableSliceOfNamespacedName) Len() int           { return len(s) }
func (s sortableSliceOfNamespacedName) Less(i, j int) bool { return lessNamespacedName(s[i], s[j]) }
func (s sortableSliceOfNamespacedName) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// List returns the contents as a sorted types.NamespacedName slice.
func (s NamespacedName) List() []types.NamespacedName {
	res := make(sortableSliceOfNamespacedName, 0, len(s))
	for key := range s {
		res = append(res, key)
	}
	sort.Sort(res)
	return []types.NamespacedName(res)
}

// UnsortedList returns the slice with contents in random order.
func (s NamespacedName) UnsortedList() []types.NamespacedName {
	res := make([]types.NamespacedName, 0, len(s))
	for key := range s {
		res = append(res, key)
	}
	return res
}

// Returns a single element from the set.
func (s NamespacedName) PopAny() (types.NamespacedName, bool) {
	for key := range s {
		s.Delete(key)
		return key, true
	}
	var zeroValue types.NamespacedName
	return zeroValue, false
}

// Len returns the size of the set.
func (s NamespacedName) Len() int {
	return len(s)
}

func lessNamespacedName(lhs, rhs types.NamespacedName) bool {
	if lhs.Namespace < rhs.Namespace {
		return true
	}
	if lhs.Namespace > rhs.Namespace {
		return false
	}
	if lhs.Name < rhs.Name {
		return true
	}
	if lhs.Name > rhs.Name {
		return false
	}
	return false
}

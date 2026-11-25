// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"sort"
	"strings"
)

// PermissionMatrixEntry is one effective grant cell: Subject (a concrete
// user ID unless ExpandSubjects is false) can perform Action on Resource in
// Domain, with the original RBAC Effect ("allow" or "deny").
type PermissionMatrixEntry struct {
	Organization string `json:"organization"`
	Subject      string `json:"subject"`
	Domain       string `json:"domain,omitempty"`
	Resource     string `json:"resource"`
	Action       string `json:"action"`
	Effect       string `json:"effect"`
}

// PermissionMatrix is the normalized set of effective permission cells of one
// organization. It is the parity contract checked before/after migration.
type PermissionMatrix struct {
	Organization string                  `json:"organization"`
	Entries      []PermissionMatrixEntry `json:"entries"`
	index        map[string]struct{}
}

// NewPermissionMatrix creates an empty matrix for the organization.
func NewPermissionMatrix(organization string) *PermissionMatrix {
	return &PermissionMatrix{Organization: organization, index: map[string]struct{}{}}
}

// MatrixEntryKey is the stable identity of a matrix cell. Effect is included
// so allow and deny grants remain distinguishable.
func MatrixEntryKey(e PermissionMatrixEntry) string {
	return strings.Join([]string{e.Organization, e.Subject, e.Domain, e.Resource, e.Action, normalizeEffect(e.Effect)}, "\x00")
}

// DecisionKey identifies a (subject, domain, resource, action) decision
// regardless of effect.
func DecisionKey(subject, domain, resource, action string) string {
	return strings.Join([]string{subject, domain, resource, action}, "\x00")
}

func normalizeEffect(effect string) string {
	effect = strings.ToLower(strings.TrimSpace(effect))
	if effect == "" {
		return "allow"
	}
	return effect
}

// Add inserts a cell, de-duplicating identical entries.
func (m *PermissionMatrix) Add(entry PermissionMatrixEntry) {
	if m.index == nil {
		m.index = map[string]struct{}{}
	}
	if entry.Organization == "" {
		entry.Organization = m.Organization
	}
	entry.Effect = normalizeEffect(entry.Effect)
	key := MatrixEntryKey(entry)
	if _, ok := m.index[key]; ok {
		return
	}
	m.index[key] = struct{}{}
	m.Entries = append(m.Entries, entry)
}

// AddGrant is a positional shorthand for Add.
func (m *PermissionMatrix) AddGrant(subject, domain, resource, action, effect string) {
	m.Add(PermissionMatrixEntry{
		Organization: m.Organization,
		Subject:      subject,
		Domain:       domain,
		Resource:     resource,
		Action:       action,
		Effect:       effect,
	})
}

// Normalize returns the matrix with de-duplicated, deterministically sorted
// entries. It is safe to call before comparing matrices.
func (m *PermissionMatrix) Normalize() *PermissionMatrix {
	if m == nil {
		return NewPermissionMatrix("")
	}
	if m.index == nil {
		m.index = map[string]struct{}{}
	}
	seen := map[string]struct{}{}
	entries := make([]PermissionMatrixEntry, 0, len(m.Entries))
	for _, e := range m.Entries {
		if e.Organization == "" {
			e.Organization = m.Organization
		}
		e.Effect = normalizeEffect(e.Effect)
		key := MatrixEntryKey(e)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		ki := strings.Join([]string{entries[i].Subject, entries[i].Domain, entries[i].Resource, entries[i].Action, entries[i].Effect}, "|")
		kj := strings.Join([]string{entries[j].Subject, entries[j].Domain, entries[j].Resource, entries[j].Action, entries[j].Effect}, "|")
		return ki < kj
	})
	m.Entries = entries
	m.index = seen
	return m
}

// SortedEntries returns the normalized entries without mutating the receiver.
func (m *PermissionMatrix) SortedEntries() []PermissionMatrixEntry {
	clone := NewPermissionMatrix(m.Organization)
	clone.Entries = append(clone.Entries, m.Entries...)
	return clone.Normalize().Entries
}

// Equal reports whether two matrices contain exactly the same cells.
func (m *PermissionMatrix) Equal(other *PermissionMatrix) bool {
	if m == nil || other == nil {
		return m == other
	}
	a := m.SortedEntries()
	b := other.SortedEntries()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if MatrixEntryKey(a[i]) != MatrixEntryKey(b[i]) {
			return false
		}
	}
	return true
}

// Equals is an alias for Equal.
func (m *PermissionMatrix) Equals(other *PermissionMatrix) bool {
	return m.Equal(other)
}

// Diff returns the cells only present in m (missing from other) and only
// present in other (missing from m).
func (m *PermissionMatrix) Diff(other *PermissionMatrix) (onlyLeft []PermissionMatrixEntry, onlyRight []PermissionMatrixEntry) {
	left := NewPermissionMatrix(m.Organization)
	if m != nil {
		for _, e := range m.Entries {
			left.Add(e)
		}
	}
	right := NewPermissionMatrix("")
	if other != nil {
		for _, e := range other.Entries {
			right.Add(e)
		}
	}

	for _, e := range left.SortedEntries() {
		if _, ok := right.index[MatrixEntryKey(e)]; !ok {
			onlyLeft = append(onlyLeft, e)
		}
	}
	for _, e := range right.SortedEntries() {
		if _, ok := left.index[MatrixEntryKey(e)]; !ok {
			onlyRight = append(onlyRight, e)
		}
	}
	return onlyLeft, onlyRight
}

// IsAllowed applies deny-override semantics: at least one allow cell and no
// deny cell for the coordinate. An empty effect is treated as allow, matching
// Casdoor's stored policy rows.
func (m *PermissionMatrix) IsAllowed(subject, resource, action string, domain ...string) bool {
	d := ""
	if len(domain) > 0 {
		d = domain[0]
	}
	if m == nil {
		return false
	}
	allowed := false
	for _, e := range m.Entries {
		if e.Subject != subject || e.Resource != resource || e.Action != action || e.Domain != d {
			continue
		}
		switch normalizeEffect(e.Effect) {
		case "deny":
			return false
		default:
			allowed = true
		}
	}
	return allowed
}

// DecisionMatrix collapses effect cells into boolean decisions using
// deny-override. Keys are DecisionKey coordinates.
func (m *PermissionMatrix) DecisionMatrix() map[string]bool {
	decisions := map[string]bool{}
	denied := map[string]bool{}
	for _, e := range m.Entries {
		key := DecisionKey(e.Subject, e.Domain, e.Resource, e.Action)
		if normalizeEffect(e.Effect) == "deny" {
			denied[key] = true
			decisions[key] = false
		} else if !denied[key] {
			decisions[key] = true
		}
	}
	for key := range denied {
		decisions[key] = false
	}
	return decisions
}

// ToUserResourceActions projects the matrix onto user -> resource -> actions,
// which is a common tabular representation of a permission matrix.
func (m *PermissionMatrix) ToUserResourceActions() map[string]map[string][]string {
	result := map[string]map[string][]string{}
	for _, e := range m.SortedEntries() {
		if normalizeEffect(e.Effect) == "deny" {
			continue
		}
		if result[e.Subject] == nil {
			result[e.Subject] = map[string][]string{}
		}
		result[e.Subject][e.Resource] = append(result[e.Subject][e.Resource], e.Action)
	}
	for _, resources := range result {
		for resource, actions := range resources {
			sort.Strings(actions)
			resources[resource] = compactStrings(actions)
		}
	}
	return result
}

func compactStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := values[:0]
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

// PermissionMatricesEqual reports whether two matrices have identical cells.
func PermissionMatricesEqual(a, b *PermissionMatrix) bool {
	return a.Equal(b)
}

// ComparePermissionMatrices returns the cell diff between two matrices.
func ComparePermissionMatrices(a, b *PermissionMatrix) (onlyA []PermissionMatrixEntry, onlyB []PermissionMatrixEntry) {
	return a.Diff(b)
}

// RbacGroupMembers maps a group ID (with or without the "group:" prefix) to
// its concrete user IDs.
type RbacGroupMembers map[string][]string

// BuildRbacPermissionMatrix expands Casdoor roles/permissions into the
// effective user permission matrix of one organization.
//
// Role inheritance (Role.Roles), role groups (Role.Groups) and direct
// role/permission users are expanded with the same closure semantics Casbin
// uses at enforcement time. Group membership is supplied through the optional
// groupMembers argument because Group.Users is not a persisted column.
func BuildRbacPermissionMatrix(organization string, roles []*Role, permissions []*Permission, groupMembers ...RbacGroupMembers) *PermissionMatrix {
	var members RbacGroupMembers
	if len(groupMembers) > 0 {
		members = groupMembers[0]
	}

	index := newRbacRoleIndex(organization, roles, members)
	matrix := NewPermissionMatrix(organization)

	for _, permission := range permissions {
		if permission == nil {
			continue
		}
		owner := firstNonEmpty(permission.Owner, organization)
		domains := permissionDomains(permission.Domains)
		effect := permission.Effect

		subjects := map[string]struct{}{}
		for _, user := range permission.Users {
			subjects[user] = struct{}{}
		}
		for _, group := range permission.Groups {
			for _, user := range index.groupUsers(owner, group) {
				subjects[user] = struct{}{}
			}
		}
		for _, role := range permission.Roles {
			for _, user := range index.roleUsers(owner, role) {
				subjects[user] = struct{}{}
			}
		}

		for subject := range subjects {
			for _, resource := range permission.Resources {
				for _, action := range permission.Actions {
					for _, domain := range domains {
						matrix.AddGrant(subject, domain, resource, action, effect)
					}
				}
			}
		}
	}

	return matrix.Normalize()
}

// BuildPermissionMatrix builds the effective user matrix without external
// group membership data. Group subjects are therefore not expanded to users;
// use BuildRbacPermissionMatrix with RbacGroupMembers for full expansion.
func BuildPermissionMatrix(roles []*Role, permissions []*Permission) *PermissionMatrix {
	organization := ""
	for _, r := range roles {
		if r != nil && r.Owner != "" {
			organization = r.Owner
			break
		}
	}
	if organization == "" {
		for _, p := range permissions {
			if p != nil && p.Owner != "" {
				organization = p.Owner
				break
			}
		}
	}
	return BuildRbacPermissionMatrix(organization, roles, permissions, nil)
}

// BuildRbacSubjectMatrix returns the unexpanded policy-subject matrix, i.e.
// the normalized form of getPolicies(): one cell per declared user/group/role
// subject instead of per concrete end user.
func BuildRbacSubjectMatrix(organization string, permissions []*Permission) *PermissionMatrix {
	matrix := NewPermissionMatrix(organization)
	for _, permission := range permissions {
		if permission == nil {
			continue
		}
		owner := firstNonEmpty(permission.Owner, organization)
		domains := permissionDomains(permission.Domains)
		for _, subject := range permissionPolicySubjects(owner, permission) {
			for _, resource := range permission.Resources {
				for _, action := range permission.Actions {
					for _, domain := range domains {
						matrix.AddGrant(subject, domain, resource, action, permission.Effect)
					}
				}
			}
		}
	}
	return matrix.Normalize()
}

func permissionPolicySubjects(owner string, permission *Permission) []string {
	subjects := make([]string, 0, len(permission.Users)+len(permission.Groups)+len(permission.Roles))
	subjects = append(subjects, permission.Users...)
	for _, group := range permission.Groups {
		subjects = append(subjects, getPermissionGroupSubject(owner, group))
	}
	subjects = append(subjects, permission.Roles...)
	return subjects
}

func permissionDomains(domains []string) []string {
	if len(domains) == 0 {
		return []string{""}
	}
	return domains
}

type rbacRoleIndex struct {
	organization string
	rolesById    map[string]*Role
	rolesByOwner map[string][]*Role
	groups       RbacGroupMembers
}

func newRbacRoleIndex(organization string, roles []*Role, groups RbacGroupMembers) *rbacRoleIndex {
	idx := &rbacRoleIndex{
		organization: organization,
		rolesById:    map[string]*Role{},
		rolesByOwner: map[string][]*Role{},
		groups:       groups,
	}
	for _, role := range roles {
		if role == nil {
			continue
		}
		id := role.GetId()
		idx.rolesById[id] = role
		idx.rolesByOwner[role.Owner] = append(idx.rolesByOwner[role.Owner], role)
	}
	return idx
}

// normalizeRoleRef resolves "*" and bare names against the owner, mirroring
// the Casbin ID conventions used by getRolesInRole.
func (idx *rbacRoleIndex) normalizeRoleRef(owner, roleId string) string {
	if roleId == "*" {
		return owner + "/*"
	}
	if !strings.Contains(roleId, "/") && owner != "" {
		return owner + "/" + roleId
	}
	return roleId
}

func (idx *rbacRoleIndex) normalizeGroupRef(owner, groupId string) string {
	groupId = strings.TrimPrefix(groupId, "group:")
	if groupId == "*" {
		return owner + "/*"
	}
	if !strings.Contains(groupId, "/") && owner != "" {
		return owner + "/" + groupId
	}
	return groupId
}

func (idx *rbacRoleIndex) groupUsers(owner, groupId string) []string {
	fullId := idx.normalizeGroupRef(owner, groupId)

	collect := func(id string) []string {
		if idx.groups == nil {
			return nil
		}
		if users, ok := idx.groups[id]; ok {
			return users
		}
		return idx.groups["group:"+id]
	}

	if strings.HasSuffix(fullId, "/*") {
		groupOwner := strings.TrimSuffix(fullId, "/*")
		users := map[string]struct{}{}
		for groupIdKey := range idx.groups {
			normalized := idx.normalizeGroupRef(groupOwner, groupIdKey)
			if groupOwner != "" && !strings.HasPrefix(normalized, groupOwner+"/") {
				continue
			}
			for _, u := range collect(groupIdKey) {
				users[u] = struct{}{}
			}
		}
		result := make([]string, 0, len(users))
		for u := range users {
			result = append(result, u)
		}
		sort.Strings(result)
		return result
	}

	return collect(fullId)
}

// roleUsers returns every concrete user that inherits the role, expanding
// direct users, role groups and nested child roles with cycle protection.
func (idx *rbacRoleIndex) roleUsers(owner, roleRef string) []string {
	roleId := idx.normalizeRoleRef(owner, roleRef)
	users := map[string]struct{}{}
	idx.collectRoleUsers(roleId, users, map[string]struct{}{})
	result := make([]string, 0, len(users))
	for u := range users {
		result = append(result, u)
	}
	sort.Strings(result)
	return result
}

func (idx *rbacRoleIndex) collectRoleUsers(roleId string, users map[string]struct{}, visited map[string]struct{}) {
	if _, ok := visited[roleId]; ok {
		return
	}
	visited[roleId] = struct{}{}

	if strings.HasSuffix(roleId, "/*") {
		roleOwner := strings.TrimSuffix(roleId, "/*")
		for _, role := range idx.rolesByOwner[roleOwner] {
			idx.collectRoleUsers(role.GetId(), users, visited)
		}
		return
	}

	role := idx.rolesById[roleId]
	if role == nil {
		return
	}

	for _, user := range role.Users {
		users[user] = struct{}{}
	}
	for _, group := range role.Groups {
		for _, user := range idx.groupUsers(role.Owner, group) {
			users[user] = struct{}{}
		}
	}
	for _, childRole := range role.Roles {
		idx.collectRoleUsers(idx.normalizeRoleRef(role.Owner, childRole), users, visited)
	}
}

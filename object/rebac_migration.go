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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/casdoor/casdoor/util"
)

// RoleConversion is the result of converting one RBAC role into ReBAC tuples.
type RoleConversion struct {
	Owner   string           `json:"owner"`
	RoleId  string           `json:"roleId"`
	Role    *Role            `json:"role,omitempty"`
	Tuples  []*RelationTuple `json:"tuples"`
	Success bool             `json:"success"`
	Error   string           `json:"error,omitempty"`
}

// ConvertedRole is an alternative name for RoleConversion.
type ConvertedRole = RoleConversion

// BatchRoleConversionResult reports a batch role conversion.
type BatchRoleConversionResult struct {
	Total       int               `json:"total"`
	Succeeded   int               `json:"succeeded"`
	Failed      int               `json:"failed"`
	Conversions []*RoleConversion `json:"conversions"`
	Tuples      []*RelationTuple  `json:"tuples"`
}

// RebacMigration is the output of an RBAC -> ReBAC migration for one organization.
type RebacMigration struct {
	Organization string                     `json:"organization"`
	Tuples       []*RelationTuple           `json:"tuples"`
	Conversions  []*RoleConversion          `json:"conversions"`
	BatchResult  *BatchRoleConversionResult `json:"batchResult,omitempty"`
	BeforeMatrix *PermissionMatrix          `json:"beforeMatrix,omitempty"`
	AfterMatrix  *PermissionMatrix          `json:"afterMatrix,omitempty"`
	Parity       bool                       `json:"parity"`
	Differences  *MatrixParityReport        `json:"differences,omitempty"`
}

// RebacMigrationResult and MigrationResult are compatibility aliases.
type RebacMigrationResult = RebacMigration
type MigrationResult = RebacMigration

// MatrixParityReport describes matrix differences after migration.
type MatrixParityReport struct {
	Equal   bool                    `json:"equal"`
	Missing []PermissionMatrixEntry `json:"missing"`
	Extra   []PermissionMatrixEntry `json:"extra"`
	Before  int                     `json:"beforeEntries"`
	After   int                     `json:"afterEntries"`
}

// Graph returns a ReBAC graph populated with the migrated tuples.
func (m *RebacMigration) Graph() *RebacGraph {
	tuples := make([]RelationTuple, 0, len(m.Tuples))
	for _, t := range m.Tuples {
		if t != nil {
			tuples = append(tuples, *t)
		}
	}
	return NewRebacGraph(tuples...)
}

// ConvertRoleToTuples maps one role's assignments to membership tuples:
//
//	role:<id>#member@user:<userId>
//	role:<id>#member@group:<groupId>#member
//	role:<id>#member@role:<childId>#member
func ConvertRoleToTuples(role *Role) []*RelationTuple {
	if role == nil {
		return nil
	}

	roleId := role.GetId()
	tuples := []*RelationTuple{}

	for _, user := range role.Users {
		if user == "" {
			continue
		}
		t := NewRelationTuple(RebacObjectRole, roleId, RebacRelationMember, RebacObjectUser, user)
		tuples = append(tuples, &t)
	}

	for _, group := range role.Groups {
		if group == "" {
			continue
		}
		groupId := normalizeMigrationGroupId(role.Owner, group)
		t := NewUsersetTuple(RebacObjectRole, roleId, RebacRelationMember, RebacObjectGroup, groupId, RebacRelationMember)
		tuples = append(tuples, &t)
	}

	for _, child := range role.Roles {
		if child == "" {
			continue
		}
		childId := normalizeMigrationRoleId(role.Owner, child)
		if childId == roleId {
			continue
		}
		t := NewUsersetTuple(RebacObjectRole, roleId, RebacRelationMember, RebacObjectRole, childId, RebacRelationMember)
		tuples = append(tuples, &t)
	}

	return tuples
}

// ConvertRolesToTuples converts a batch of roles and returns all tuples.
func ConvertRolesToTuples(roles []*Role) []*RelationTuple {
	tuples := []*RelationTuple{}
	for _, role := range roles {
		tuples = append(tuples, ConvertRoleToTuples(role)...)
	}
	return DedupTuples(tuples)
}

// BatchConvertRoles converts every role independently and reports per-role status.
func BatchConvertRoles(roles []*Role) *BatchRoleConversionResult {
	result := &BatchRoleConversionResult{Total: len(roles)}
	allTuples := []*RelationTuple{}

	for _, role := range roles {
		conversion := &RoleConversion{Success: true}
		if role == nil {
			conversion.Success = false
			conversion.Error = "role is nil"
			result.Failed++
			result.Conversions = append(result.Conversions, conversion)
			continue
		}

		conversion.Owner = role.Owner
		conversion.RoleId = role.GetId()
		conversion.Role = role
		conversion.Tuples = ConvertRoleToTuples(role)

		result.Succeeded++
		result.Conversions = append(result.Conversions, conversion)
		allTuples = append(allTuples, conversion.Tuples...)
	}

	result.Tuples = DedupTuples(allTuples)
	return result
}

// BatchConvertRbacRoles is an alias for BatchConvertRoles.
func BatchConvertRbacRoles(roles []*Role) *BatchRoleConversionResult {
	return BatchConvertRoles(roles)
}

// ConvertPermissionToTuples maps a permission's resource/action grants onto
// ReBAC relation tuples. Subjects keep their RBAC type (user/group/role).
func ConvertPermissionToTuples(permission *Permission) []*RelationTuple {
	if permission == nil {
		return nil
	}

	owner := permission.Owner
	domains := permissionDomains(permission.Domains)
	effect := normalizeEffect(permission.Effect)
	tuples := []*RelationTuple{}

	appendGrant := func(subjectType, subjectId, subjectRelation string) {
		for _, resource := range permission.Resources {
			for _, action := range permission.Actions {
				for _, domain := range domains {
					t := RelationTuple{
						ObjectType:      RebacObjectResource,
						ObjectId:        resource,
						Relation:        action,
						SubjectType:     subjectType,
						SubjectId:       subjectId,
						SubjectRelation: subjectRelation,
						Domain:          domain,
						Effect:          effect,
					}
					tuples = append(tuples, &t)
				}
			}
		}
	}

	for _, user := range permission.Users {
		appendGrant(RebacObjectUser, user, "")
	}
	for _, group := range permission.Groups {
		appendGrant(RebacObjectGroup, normalizeMigrationGroupId(owner, group), RebacRelationMember)
	}
	for _, role := range permission.Roles {
		appendGrant(RebacObjectRole, normalizeMigrationRoleId(owner, role), RebacRelationMember)
	}

	return tuples
}

// RbacToRebacOptions controls migration materialization.
type RbacToRebacOptions struct {
	// GroupMembers supplies group -> users mappings (full IDs).
	GroupMembers RbacGroupMembers
	// Persist writes the generated tuples to the rebac_tuple table.
	Persist bool
}

// MigrateRbacToRebac converts one organization's roles and permissions into a
// self-contained set of ReBAC relation tuples. Wildcard role/group references
// are materialized against the supplied role set / group membership map so the
// resulting graph expands to exactly the same effective users.
func MigrateRbacToRebac(organization string, roles []*Role, permissions []*Permission, optional ...interface{}) (*RebacMigration, error) {
	opts := RbacToRebacOptions{}
	for _, arg := range optional {
		switch v := arg.(type) {
		case RbacGroupMembers:
			opts.GroupMembers = v
		case map[string][]string:
			opts.GroupMembers = RbacGroupMembers(v)
		case RbacToRebacOptions:
			opts = v
		case *RbacToRebacOptions:
			if v != nil {
				opts = *v
			}
		}
	}

	index := newRbacRoleIndex(organization, roles, opts.GroupMembers)

	migration := &RebacMigration{Organization: organization}
	batch := BatchConvertRoles(roles)
	migration.Conversions = batch.Conversions
	migration.BatchResult = batch

	tuples := []*RelationTuple{}

	// Materialize group membership so the tuple graph is self-contained.
	groupIds := make([]string, 0, len(opts.GroupMembers))
	for groupId := range opts.GroupMembers {
		groupIds = append(groupIds, groupId)
	}
	sort.Strings(groupIds)
	for _, groupRef := range groupIds {
		groupID := index.normalizeGroupRef(organization, groupRef)
		for _, user := range opts.GroupMembers[groupRef] {
			t := NewRelationTuple(RebacObjectGroup, groupID, RebacRelationMember, RebacObjectUser, user)
			tuples = append(tuples, &t)
		}
	}

	// Role tuples, with wildcard child-role references materialized.
	for _, role := range roles {
		if role == nil {
			continue
		}
		roleTuples := ConvertRoleToTuples(role)
		for _, t := range roleTuples {
			if t.SubjectType == RebacObjectRole && t.SubjectId != "" && strings.HasSuffix(t.SubjectId, "/*") {
				owner := strings.TrimSuffix(t.SubjectId, "/*")
				for _, sibling := range index.rolesByOwner[owner] {
					if sibling.GetId() == role.GetId() {
						continue
					}
					tt := NewUsersetTuple(t.ObjectType, t.ObjectId, t.Relation, RebacObjectRole, sibling.GetId(), RebacRelationMember)
					tuples = append(tuples, &tt)
				}
				continue
			}
			if t.SubjectType == RebacObjectGroup && strings.HasSuffix(t.SubjectId, "/*") {
				wildcardOwner := strings.TrimSuffix(t.SubjectId, "/*")
				for _, groupID := range knownGroupIds(index.groups, wildcardOwner) {
					tt := NewUsersetTuple(t.ObjectType, t.ObjectId, t.Relation, RebacObjectGroup, groupID, RebacRelationMember)
					tuples = append(tuples, &tt)
				}
				continue
			}
			tuples = append(tuples, t)
		}
	}

	// Permission grant tuples, with wildcard subjects materialized.
	for _, permission := range permissions {
		if permission == nil {
			continue
		}
		for _, t := range ConvertPermissionToTuples(permission) {
			switch {
			case t.SubjectType == RebacObjectRole && strings.HasSuffix(t.SubjectId, "/*"):
				owner := strings.TrimSuffix(t.SubjectId, "/*")
				for _, sibling := range index.rolesByOwner[owner] {
					tt := *t
					tt.SubjectId = sibling.GetId()
					tuples = append(tuples, &tt)
				}
			case t.SubjectType == RebacObjectGroup && strings.HasSuffix(t.SubjectId, "/*"):
				wildcardOwner := strings.TrimSuffix(t.SubjectId, "/*")
				for _, groupID := range knownGroupIds(index.groups, wildcardOwner) {
					tt := *t
					tt.SubjectId = groupID
					tuples = append(tuples, &tt)
				}
			default:
				tuples = append(tuples, t)
			}
		}
	}

	migration.Tuples = DedupTuples(tuples)

	before := BuildRbacPermissionMatrix(organization, roles, permissions, opts.GroupMembers)
	after := BuildRebacPermissionMatrix(organization, migration.Tuples)
	migration.BeforeMatrix = before
	migration.AfterMatrix = after
	migration.Differences = BuildMatrixParityReport(before, after)
	migration.Parity = migration.Differences.Equal

	if opts.Persist {
		for _, t := range migration.Tuples {
			t.Owner = organization
			t.TupleId = tupleHash(t)
		}
		if _, err := UpsertRebacTuples(migration.Tuples); err != nil {
			return migration, err
		}
	}

	return migration, nil
}

// MigrateRBACToReBAC is an uppercase alias for MigrateRbacToRebac.
func MigrateRBACToReBAC(organization string, roles []*Role, permissions []*Permission, optional ...interface{}) (*RebacMigration, error) {
	return MigrateRbacToRebac(organization, roles, permissions, optional...)
}

// BuildMatrixParityReport compares the before/after matrices.
func BuildMatrixParityReport(before, after *PermissionMatrix) *MatrixParityReport {
	missing, extra := before.Diff(after)
	return &MatrixParityReport{
		Equal:   len(missing) == 0 && len(extra) == 0,
		Missing: missing,
		Extra:   extra,
		Before:  len(before.SortedEntries()),
		After:   len(after.SortedEntries()),
	}
}

// VerifyMatrixParity returns nil when the two matrices are identical.
func VerifyMatrixParity(before, after *PermissionMatrix) error {
	report := BuildMatrixParityReport(before, after)
	if report.Equal {
		return nil
	}
	return fmt.Errorf("permission matrix parity violated: %d missing cells, %d extra cells", len(report.Missing), len(report.Extra))
}

// BuildRebacPermissionMatrix expands migrated grant tuples back into concrete
// user cells using the ReBAC graph.
func BuildRebacPermissionMatrix(organization string, tuples []*RelationTuple) *PermissionMatrix {
	values := make([]RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		if t != nil {
			values = append(values, *t)
		}
	}
	graph := NewRebacGraph(values...)
	return BuildRebacPermissionMatrixFromGraph(organization, graph)
}

// BuildRebacPermissionMatrixFromGraph is the graph-backed variant.
func BuildRebacPermissionMatrixFromGraph(organization string, graph *RebacGraph) *PermissionMatrix {
	matrix := NewPermissionMatrix(organization)
	if graph == nil {
		return matrix.Normalize()
	}

	for _, t := range graph.Tuples() {
		if t.ObjectType != RebacObjectResource {
			continue
		}

		subjects := []string{}
		if t.SubjectType == RebacObjectUser && t.SubjectRelation == "" {
			subjects = append(subjects, t.SubjectId)
		} else if t.SubjectRelation != "" {
			subjects = append(subjects, graph.ExpandUsers(t.SubjectType, t.SubjectId, t.SubjectRelation, t.Domain)...)
		}

		for _, subject := range subjects {
			matrix.AddGrant(subject, t.Domain, t.ObjectId, t.Relation, t.Effect)
		}
	}

	return matrix.Normalize()
}

// CheckRebac allows callers to evaluate a migrated tuple graph directly.
func CheckRebac(tuples []*RelationTuple, userId, action, resource string, domain ...string) bool {
	values := make([]RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		if t != nil {
			values = append(values, *t)
		}
	}
	return NewRebacGraph(values...).IsAllowed(userId, action, RebacObjectResource, resource, domain...)
}

func knownGroupIds(groups RbacGroupMembers, owner string) []string {
	ids := map[string]struct{}{}
	for groupId := range groups {
		normalized := normalizeMigrationGroupId(owner, groupId)
		if owner != "" && !strings.HasPrefix(normalized, owner+"/") {
			continue
		}
		ids[normalized] = struct{}{}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func normalizeMigrationRoleId(owner, roleId string) string {
	if roleId == "*" {
		return util.GetId(owner, RebacWildcard)
	}
	if !strings.Contains(roleId, "/") && owner != "" {
		return util.GetId(owner, roleId)
	}
	return roleId
}

func normalizeMigrationGroupId(owner, groupId string) string {
	groupId = strings.TrimPrefix(groupId, "group:")
	if groupId == "*" {
		return util.GetId(owner, RebacWildcard)
	}
	if !strings.Contains(groupId, "/") && owner != "" {
		return util.GetId(owner, groupId)
	}
	return groupId
}

func tupleHash(t *RelationTuple) string {
	sum := sha256.Sum256([]byte(t.Key()))
	return hex.EncodeToString(sum[:])
}

// GetGroupMembersFromUsers builds the group -> user mapping from Casdoor users.
func GetGroupMembersFromUsers(owner string, users []*User) RbacGroupMembers {
	members := RbacGroupMembers{}
	for _, user := range users {
		if user == nil {
			continue
		}
		userId := user.GetId()
		if owner != "" && user.Owner != owner {
			continue
		}
		for _, groupId := range user.Groups {
			normalized := normalizeMigrationGroupId(user.Owner, groupId)
			members[normalized] = append(members[normalized], userId)
		}
	}
	return members
}

// MigrateOrganizationRbacToRebac loads one organization's roles/permissions
// from the database and runs the migration. When persist is true the tuples are
// upserted into the rebac_tuple table.
func MigrateOrganizationRbacToRebac(owner string, persist bool) (*RebacMigration, error) {
	roles, err := GetRoles(owner)
	if err != nil {
		return nil, err
	}
	permissions, err := GetPermissions(owner)
	if err != nil {
		return nil, err
	}
	users, err := GetUsers(owner)
	if err != nil {
		return nil, err
	}
	groupMembers := GetGroupMembersFromUsers(owner, users)

	return MigrateRbacToRebac(owner, roles, permissions, RbacToRebacOptions{
		GroupMembers: groupMembers,
		Persist:      persist,
	})
}

// MigrateOrganizationToRebac is an alias for MigrateOrganizationRbacToRebac.
func MigrateOrganizationToRebac(owner string, persist bool) (*RebacMigration, error) {
	return MigrateOrganizationRbacToRebac(owner, persist)
}

// MigrateAllOrganizationsRbacToRebac migrates every organization. A single
// organization failure is recorded on its result and does not abort the others.
func MigrateAllOrganizationsRbacToRebac(persist bool) ([]*RebacMigration, error) {
	organizations, err := GetOrganizations("")
	if err != nil {
		return nil, err
	}

	results := make([]*RebacMigration, 0, len(organizations))
	for _, organization := range organizations {
		if organization == nil || organization.Name == "" {
			continue
		}
		migration, migrateErr := MigrateOrganizationRbacToRebac(organization.Name, persist)
		if migrateErr != nil {
			migration = &RebacMigration{
				Organization: organization.Name,
				Parity:       false,
				Differences:  &MatrixParityReport{Equal: false},
			}
			migration.Conversions = []*RoleConversion{{Success: false, Error: migrateErr.Error()}}
		}
		results = append(results, migration)
	}
	return results, nil
}

// VerifyOrganizationsMatrixParity runs a dry migration for every organization
// and returns the per-organization parity report.
func VerifyOrganizationsMatrixParity() (map[string]*MatrixParityReport, error) {
	migrations, err := MigrateAllOrganizationsRbacToRebac(false)
	if err != nil {
		return nil, err
	}
	reports := map[string]*MatrixParityReport{}
	for _, migration := range migrations {
		if migration.Differences == nil {
			migration.Differences = BuildMatrixParityReport(migration.BeforeMatrix, migration.AfterMatrix)
		}
		reports[migration.Organization] = migration.Differences
	}
	return reports, nil
}

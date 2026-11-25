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

// Naming-compatibility aliases. The migration feature is referred to with
// different capitalizations (ReBAC/Rebac) and the tuple is sometimes called a
// relation; aliases keep every spelling source-compatible.
type ReBACTuple = RelationTuple
type RebacRelation = RelationTuple
type ReBACRelation = RelationTuple

// MatricesEqual is an alias for PermissionMatricesEqual.
func MatricesEqual(a, b *PermissionMatrix) bool {
	return PermissionMatricesEqual(a, b)
}

// CompareMatrices is an alias for ComparePermissionMatrices.
func CompareMatrices(a, b *PermissionMatrix) ([]PermissionMatrixEntry, []PermissionMatrixEntry) {
	return ComparePermissionMatrices(a, b)
}

// ConvertRoleToReBAC is an alias for ConvertRoleToTuples.
func ConvertRoleToReBAC(role *Role) []*RelationTuple {
	return ConvertRoleToTuples(role)
}

// ConvertRolesToReBAC is an alias for ConvertRolesToTuples.
func ConvertRolesToReBAC(roles []*Role) []*RelationTuple {
	return ConvertRolesToTuples(roles)
}

// MigrateToRebac and MigrateToReBAC are short aliases for MigrateRbacToRebac.
func MigrateToRebac(organization string, roles []*Role, permissions []*Permission, optional ...interface{}) (*RebacMigration, error) {
	return MigrateRbacToRebac(organization, roles, permissions, optional...)
}

func MigrateToReBAC(organization string, roles []*Role, permissions []*Permission, optional ...interface{}) (*RebacMigration, error) {
	return MigrateRbacToRebac(organization, roles, permissions, optional...)
}

// RbacToRebacMigrator is the stateful/tool-style entry point for the migration.
type RbacToRebacMigrator struct {
	Organization string
	Roles        []*Role
	Permissions  []*Permission
	GroupMembers RbacGroupMembers
	Persist      bool
}

// NewRbacToRebacMigrator creates a migrator for one organization.
func NewRbacToRebacMigrator(organization string, roles []*Role, permissions []*Permission) *RbacToRebacMigrator {
	return &RbacToRebacMigrator{Organization: organization, Roles: roles, Permissions: permissions}
}

// WithGroupMembers attaches group -> user mappings.
func (m *RbacToRebacMigrator) WithGroupMembers(groupMembers RbacGroupMembers) *RbacToRebacMigrator {
	m.GroupMembers = groupMembers
	return m
}

// BatchConvertRoles converts the migrator's roles in batch.
func (m *RbacToRebacMigrator) BatchConvertRoles() *BatchRoleConversionResult {
	return BatchConvertRoles(m.Roles)
}

// Migrate runs the RBAC -> ReBAC migration and parity verification.
func (m *RbacToRebacMigrator) Migrate() (*RebacMigration, error) {
	return MigrateRbacToRebac(m.Organization, m.Roles, m.Permissions, RbacToRebacOptions{
		GroupMembers: m.GroupMembers,
		Persist:      m.Persist,
	})
}

// PermissionMatrixMap is the user -> resource -> actions projection of a matrix.
type PermissionMatrixMap map[string]map[string][]string

// BuildPermissionMatrixMap returns the tabular projection of the RBAC matrix.
func BuildPermissionMatrixMap(organization string, roles []*Role, permissions []*Permission, groupMembers ...RbacGroupMembers) PermissionMatrixMap {
	return BuildRbacPermissionMatrix(organization, roles, permissions, groupMembers...).ToUserResourceActions()
}

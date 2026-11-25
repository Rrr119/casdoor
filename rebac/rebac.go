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

// Package rebac provides the RBAC -> ReBAC migration tool. It is a thin
// facade over github.com/casdoor/casdoor/object so existing Casdoor role and
// permission APIs stay the source of truth.
package rebac

import "github.com/casdoor/casdoor/object"

type (
	// Tuple is a Zanzibar style relation tuple.
	Tuple = object.RelationTuple
	// RelationTuple is an alias of Tuple.
	RelationTuple = object.RelationTuple
	// Graph evaluates tuple relations.
	Graph = object.RebacGraph
	// Matrix is the effective permission matrix.
	Matrix = object.PermissionMatrix
	// MatrixEntry is one matrix cell.
	MatrixEntry = object.PermissionMatrixEntry
	// Migration is the migration result.
	Migration = object.RebacMigration
	// RoleConversion reports one converted role.
	RoleConversion = object.RoleConversion
	// BatchResult reports a batch role conversion.
	BatchResult = object.BatchRoleConversionResult
	// GroupMembers maps group IDs to user IDs.
	GroupMembers = object.RbacGroupMembers
	// Options controls migration.
	Options = object.RbacToRebacOptions
)

const (
	ObjectUser     = object.RebacObjectUser
	ObjectGroup    = object.RebacObjectGroup
	ObjectRole     = object.RebacObjectRole
	ObjectResource = object.RebacObjectResource
	RelationMember = object.RebacRelationMember
)

func NewGraph(tuples ...Tuple) *Graph {
	return object.NewRebacGraph(tuples...)
}

func ParseTuple(text string) (Tuple, error) {
	return object.ParseRelationTuple(text)
}

// Migrate converts one organization's RBAC model to relation tuples.
func Migrate(organization string, roles []*object.Role, permissions []*object.Permission, optional ...interface{}) (*Migration, error) {
	return object.MigrateRbacToRebac(organization, roles, permissions, optional...)
}

// BatchConvertRoles converts a batch of roles to membership tuples.
func BatchConvertRoles(roles []*object.Role) *BatchResult {
	return object.BatchConvertRoles(roles)
}

// BuildRbacMatrix builds the before-migration matrix.
func BuildRbacMatrix(organization string, roles []*object.Role, permissions []*object.Permission, groups ...GroupMembers) *Matrix {
	return object.BuildRbacPermissionMatrix(organization, roles, permissions, groups...)
}

// BuildMatrixFromTuples builds the after-migration matrix.
func BuildMatrixFromTuples(organization string, tuples []*Tuple) *Matrix {
	return object.BuildRebacPermissionMatrix(organization, tuples)
}

// MatricesEqual compares two matrices.
func MatricesEqual(a, b *Matrix) bool {
	return object.PermissionMatricesEqual(a, b)
}

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

package controllers

import (
	"encoding/json"

	"github.com/casdoor/casdoor/object"
)

// RebacMigrationRequest is the body of /api/migrate-rbac-to-rebac. When
// Roles/Permissions are supplied they are migrated directly, otherwise the
// organization's stored roles and permissions are loaded.
type RebacMigrationRequest struct {
	Owner        string                  `json:"owner"`
	Organization string                  `json:"organization"`
	Persist      bool                    `json:"persist"`
	Roles        []*object.Role          `json:"roles"`
	Permissions  []*object.Permission    `json:"permissions"`
	GroupMembers object.RbacGroupMembers `json:"groupMembers"`
}

// BatchConvertRolesRequest is the body of /api/batch-convert-roles.
type BatchConvertRolesRequest struct {
	Owner string         `json:"owner"`
	Roles []*object.Role `json:"roles"`
}

func decodeOptionalBody(c *ApiController, target interface{}) error {
	if len(c.Ctx.Input.RequestBody) == 0 {
		return nil
	}
	return json.Unmarshal(c.Ctx.Input.RequestBody, target)
}

// MigrateRbacToRebac
// @Title MigrateRbacToRebac
// @Tag ReBAC Migration API
// @Description migrate one organization's RBAC roles/permissions to ReBAC relation tuples
// @Param   owner     query    string  false  "The organization owner"
// @Param   body      body     controllers.RebacMigrationRequest  false  "Optional migration input"
// @Success 200 {object} object.RebacMigration
// @router /migrate-rbac-to-rebac [post]
func (c *ApiController) MigrateRbacToRebac() {
	request := &RebacMigrationRequest{}
	if err := decodeOptionalBody(c, request); err != nil {
		c.ResponseError(err.Error())
		return
	}

	owner := c.Ctx.Input.Query("owner")
	owner = firstControllerNonEmpty(owner, request.Owner, request.Organization)
	if owner == "" && len(request.Roles) > 0 {
		owner = request.Roles[0].Owner
	}

	if owner != "" && !c.requireOrganizationPermission(owner) {
		return
	}

	var migration *object.RebacMigration
	var err error

	if len(request.Roles) > 0 || len(request.Permissions) > 0 {
		migration, err = object.MigrateRbacToRebac(owner, request.Roles, request.Permissions, object.RbacToRebacOptions{
			GroupMembers: request.GroupMembers,
			Persist:      request.Persist,
		})
	} else if owner != "" {
		migration, err = object.MigrateOrganizationRbacToRebac(owner, request.Persist)
	} else {
		c.ResponseError("owner is required")
		return
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(migration)
}

// BatchConvertRoles
// @Title BatchConvertRoles
// @Tag ReBAC Migration API
// @Description convert a batch of RBAC roles into ReBAC membership tuples
// @Param   owner  query  string  false  "The organization owner (loads roles when body roles are empty)"
// @Param   body   body   controllers.BatchConvertRolesRequest  false  "Roles to convert"
// @Success 200 {object} object.BatchRoleConversionResult
// @router /batch-convert-roles [post]
func (c *ApiController) BatchConvertRoles() {
	request := &BatchConvertRolesRequest{}
	if err := decodeOptionalBody(c, request); err != nil {
		c.ResponseError(err.Error())
		return
	}

	owner := c.Ctx.Input.Query("owner")
	owner = firstControllerNonEmpty(owner, request.Owner)

	if owner != "" && !c.requireOrganizationPermission(owner) {
		return
	}

	roles := request.Roles
	if len(roles) == 0 && owner != "" {
		var err error
		roles, err = object.GetRoles(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	if len(roles) == 0 {
		c.ResponseError("no roles to convert")
		return
	}

	c.ResponseOk(object.BatchConvertRoles(roles))
}

// GetRebacTuples
// @Title GetRebacTuples
// @Tag ReBAC Migration API
// @Description get persisted ReBAC relation tuples
// @Param   owner  query  string  false  "The organization owner"
// @Success 200 {array} object.RelationTuple
// @router /get-rebac-tuples [get]
func (c *ApiController) GetRebacTuples() {
	owner := c.Ctx.Input.Query("owner")
	tuples, err := object.GetRebacTuples(owner)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(tuples)
}

// GetPermissionMatrix
// @Title GetPermissionMatrix
// @Tag ReBAC Migration API
// @Description build the effective RBAC permission matrix of an organization
// @Param   owner  query  string  true  "The organization owner"
// @Success 200 {object} object.PermissionMatrix
// @router /get-permission-matrix [get]
func (c *ApiController) GetPermissionMatrix() {
	owner := c.Ctx.Input.Query("owner")
	if owner == "" {
		c.ResponseError("owner is required")
		return
	}
	if !c.requireOrganizationPermission(owner) {
		return
	}

	roles, err := object.GetRoles(owner)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	permissions, err := object.GetPermissions(owner)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	users, err := object.GetUsers(owner)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	groupMembers := object.GetGroupMembersFromUsers(owner, users)

	matrix := object.BuildRbacPermissionMatrix(owner, roles, permissions, groupMembers)
	c.ResponseOk(matrix)
}

// VerifyRebacParity
// @Title VerifyRebacParity
// @Tag ReBAC Migration API
// @Description dry-run the migration and compare before/after permission matrices
// @Param   owner  query  string  true  "The organization owner"
// @Success 200 {object} object.MatrixParityReport
// @router /verify-rebac-parity [post]
func (c *ApiController) VerifyRebacParity() {
	owner := c.Ctx.Input.Query("owner")
	if owner == "" && len(c.Ctx.Input.RequestBody) > 0 {
		request := &RebacMigrationRequest{}
		if err := json.Unmarshal(c.Ctx.Input.RequestBody, request); err != nil {
			c.ResponseError(err.Error())
			return
		}
		owner = firstControllerNonEmpty(request.Owner, request.Organization)
	}
	if owner == "" {
		c.ResponseError("owner is required")
		return
	}
	if !c.requireOrganizationPermission(owner) {
		return
	}

	migration, err := object.MigrateOrganizationRbacToRebac(owner, false)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(migration.Differences)
}

func firstControllerNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// MigrateAllRbacToRebac
// @Title MigrateAllRbacToRebac
// @Tag ReBAC Migration API
// @Description migrate every organization's RBAC model to ReBAC relation tuples (global admins only)
// @Param   persist  query  bool  false  "Persist tuples to the rebac_tuple table"
// @Success 200 {array} object.RebacMigration
// @router /migrate-all-rbac-to-rebac [post]
func (c *ApiController) MigrateAllRbacToRebac() {
	if !c.IsGlobalAdmin() {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	persist := c.Ctx.Input.Query("persist") == "true" || c.Ctx.Input.Query("persist") == "1"
	migrations, err := object.MigrateAllOrganizationsRbacToRebac(persist)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(migrations)
}

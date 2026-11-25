# RBAC to ReBAC migration tool

Casdoor models authorization with roles (`object.Role`: `Users`, `Groups`,
`Roles`) and permissions (`object.Permission`: `Users`, `Groups`, `Roles`,
`Resources`, `Actions`, `Domains`, `Effect`). The migration tool converts that
model into Zanzibar style relation tuples without changing the existing
role/permission APIs or the Casbin enforcement path.

## Tuple mapping

| RBAC construct | ReBAC tuple |
| --- | --- |
| `role.Users: [org/u]` | `role:<org/role>#member@user:<org/u>` |
| `role.Groups: [org/g]` | `role:<org/role>#member@group:<org/g>#member` |
| `role.Roles: [org/child]` | `role:<org/role>#member@role:<org/child>#member` |
| group member | `group:<org/g>#member@user:<org/u>` |
| `permission.Users` | `resource:<res>#<action>@user:<org/u>` |
| `permission.Groups` | `resource:<res>#<action>@group:<org/g>#member` |
| `permission.Roles` | `resource:<res>#<action>@role:<org/role>#member` |

Permission tuples carry the original `effect` (`allow`/`deny`) and `domain`.
Wildcard `*` role/group references are materialized against the known roles and
group members. Role inheritance, groups, domains, cycles and deny-override are
handled by an in-memory `RebacGraph`.

## Go API

```go
members := object.RbacGroupMembers{"org/dev": {"org/alice"}}

migration, err := object.MigrateRbacToRebac("org", roles, permissions, members)
// migration.Tuples         -> []*object.RelationTuple
// migration.BeforeMatrix   -> RBAC effective user matrix
// migration.AfterMatrix    -> matrix expanded from the tuples
// migration.Parity == true -> the two matrices are identical

batch := object.BatchConvertRoles(roles) // per-role status + tuples
```

`object.MigrateOrganizationRbacToRebac(owner, persist)` loads roles,
permissions and users from the database; `persist=true` upserts tuples into the
`rebac_tuple` table. `object.MigrateAllOrganizationsRbacToRebac(persist)` runs
the same migration for every organization.

A thin import facade is available at `github.com/casdoor/casdoor/rebac`.

## HTTP API

Existing `/api/get-roles`, `/api/get-permissions`, `/api/enforce`, ... are
unchanged. New endpoints:

- `POST /api/migrate-rbac-to-rebac?owner=<org>` — migrate stored data
- `POST /api/migrate-rbac-to-rebac` with an inline
  `{"owner":"org","roles":[...],"permissions":[...],"groupMembers":{...}}` body
- `POST /api/batch-convert-roles?owner=<org>` (or an inline `{"roles":[...]}` body)
- `GET  /api/get-rebac-tuples?owner=<org>`
- `GET  /api/get-permission-matrix?owner=<org>`
- `POST /api/verify-rebac-parity?owner=<org>`
- `POST /api/migrate-all-rbac-to-rebac` (global admins)

## Parity guarantee and tests

`object.BuildRbacPermissionMatrix` expands the RBAC source to concrete users
with the same closure semantics Casbin uses at enforcement time;
`object.BuildRebacPermissionMatrix` expands the migrated tuples through the
ReBAC graph. `PermissionMatrix.Equal`/`Diff` compare the normalized cell sets.

`object/rebac_parity_uid36828_test.go` builds three organizations (direct
grants + deny, groups + nested roles + domains, multi-level inheritance +
wildcards) and asserts that every post-migration matrix is identical to the
pre-migration matrix, alongside batch conversion, graph cycle, legacy
`getPolicies` compatibility and SQLite persistence tests.

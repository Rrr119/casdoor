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
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/xorm-io/xorm"
)

type rebacParityFixture36828 struct {
	org          string
	roles        []*Role
	permissions  []*Permission
	groupMembers RbacGroupMembers
}

func rebacParityFixtures36828() []rebacParityFixture36828 {
	return []rebacParityFixture36828{
		{
			// Organization 1: direct users, simple roles and an explicit Deny.
			org: "alpha",
			roles: []*Role{
				{
					Owner: "alpha", Name: "admin", IsEnabled: true,
					Users: []string{"alpha/alice"},
				},
				{
					Owner: "alpha", Name: "viewer", IsEnabled: true,
					Users: []string{"alpha/bob", "alpha/carol"},
				},
			},
			permissions: []*Permission{
				{
					Owner: "alpha", Name: "doc-admin", IsEnabled: true,
					Roles:     []string{"alpha/admin"},
					Resources: []string{"doc1"},
					Actions:   []string{"read", "write"},
					Effect:    "Allow",
				},
				{
					Owner: "alpha", Name: "doc-view", IsEnabled: true,
					Roles:     []string{"alpha/viewer"},
					Resources: []string{"doc1"},
					Actions:   []string{"read"},
					Effect:    "Allow",
				},
				{
					Owner: "alpha", Name: "bob-personal", IsEnabled: true,
					Users:     []string{"alpha/bob"},
					Resources: []string{"doc2"},
					Actions:   []string{"write"},
					Effect:    "Allow",
				},
				{
					Owner: "alpha", Name: "carol-no-write", IsEnabled: true,
					Users:     []string{"alpha/carol"},
					Resources: []string{"doc1"},
					Actions:   []string{"write"},
					Effect:    "Deny",
				},
			},
			groupMembers: RbacGroupMembers{},
		},
		{
			// Organization 2: groups, nested roles and domains.
			org: "beta",
			roles: []*Role{
				{
					Owner: "beta", Name: "engineering-role", IsEnabled: true,
					Groups: []string{"beta/engineering"},
				},
				{
					Owner: "beta", Name: "cto", IsEnabled: true,
					Users: []string{"beta/grace"},
					Roles: []string{"beta/engineering-role"},
				},
			},
			permissions: []*Permission{
				{
					Owner: "beta", Name: "cto-docs", IsEnabled: true,
					Roles:     []string{"beta/cto"},
					Domains:   []string{"domainA", "domainB"},
					Resources: []string{"roadmap"},
					Actions:   []string{"read", "approve"},
					Effect:    "Allow",
				},
				{
					Owner: "beta", Name: "oncall-group", IsEnabled: true,
					Groups:    []string{"beta/oncall"},
					Resources: []string{"incident"},
					Actions:   []string{"manage"},
					Effect:    "Allow",
				},
			},
			groupMembers: RbacGroupMembers{
				"beta/engineering": {"beta/dave", "beta/erin"},
				"beta/oncall":      {"beta/dave", "beta/frank"},
			},
		},
		{
			// Organization 3: multi-level role inheritance and wildcard roles.
			org: "gamma",
			roles: []*Role{
				{Owner: "gamma", Name: "intern", IsEnabled: true, Users: []string{"gamma/ivan"}},
				{Owner: "gamma", Name: "senior", IsEnabled: true, Users: []string{"gamma/judy"}, Roles: []string{"gamma/intern"}},
				{Owner: "gamma", Name: "manager", IsEnabled: true, Users: []string{"gamma/karl"}, Roles: []string{"gamma/senior"}},
				{Owner: "gamma", Name: "auditor", IsEnabled: true, Users: []string{"gamma/laura"}},
			},
			permissions: []*Permission{
				{
					Owner: "gamma", Name: "secrets-read", IsEnabled: true,
					Roles:     []string{"gamma/manager"},
					Resources: []string{"secret"},
					Actions:   []string{"read"},
					Effect:    "Allow",
				},
				{
					Owner: "gamma", Name: "audit-all", IsEnabled: true,
					Roles:     []string{"gamma/auditor"},
					Resources: []string{"logs"},
					Actions:   []string{"read"},
					Effect:    "Allow",
				},
				{
					Owner: "gamma", Name: "org-wide-status", IsEnabled: true,
					Roles:     []string{"*"},
					Resources: []string{"status"},
					Actions:   []string{"read"},
					Effect:    "Allow",
				},
			},
			groupMembers: RbacGroupMembers{},
		},
	}
}

func TestRbacToRebacThreeOrgMatrixParity36828(t *testing.T) {
	fixtures := rebacParityFixtures36828()
	if len(fixtures) != 3 {
		t.Fatalf("expected exactly 3 organization fixtures, got %d", len(fixtures))
	}

	for _, fixture := range fixtures {
		t.Run(fixture.org, func(t *testing.T) {
			before := BuildRbacPermissionMatrix(fixture.org, fixture.roles, fixture.permissions, fixture.groupMembers)

			migration, err := MigrateRbacToRebac(fixture.org, fixture.roles, fixture.permissions, fixture.groupMembers)
			if err != nil {
				t.Fatalf("MigrateRbacToRebac() error: %v", err)
			}
			if migration == nil {
				t.Fatal("MigrateRbacToRebac() returned nil migration")
			}

			after := BuildRebacPermissionMatrix(fixture.org, migration.Tuples)

			if !before.Equal(after) {
				missing, extra := before.Diff(after)
				t.Fatalf("matrix mismatch for org %s\nmissing in ReBAC: %#v\nextra in ReBAC: %#v", fixture.org, missing, extra)
			}
			if !migration.Parity {
				t.Fatalf("migration report must state parity, got report: %+v", migration.Differences)
			}
			if err := VerifyMatrixParity(migration.BeforeMatrix, migration.AfterMatrix); err != nil {
				t.Fatalf("VerifyMatrixParity() error: %v", err)
			}

			// The graph evaluator must agree with the matrix decisions.
			graph := migration.Graph()
			for _, entry := range before.Entries {
				got := graph.IsAllowed(entry.Subject, entry.Action, RebacObjectResource, entry.Resource, entry.Domain)
				want := before.IsAllowed(entry.Subject, entry.Resource, entry.Action, entry.Domain)
				if got != want {
					t.Fatalf("graph check %s %s on %s (domain=%q) = %v, want %v", entry.Subject, entry.Action, entry.Resource, entry.Domain, got, want)
				}
			}
		})
	}
}

func TestAlphaOrgMatrixDecisions36828(t *testing.T) {
	alpha := rebacParityFixtures36828()[0]
	matrix := BuildRbacPermissionMatrix(alpha.org, alpha.roles, alpha.permissions, alpha.groupMembers)

	cases := []struct {
		user     string
		resource string
		action   string
		want     bool
	}{
		{"alpha/alice", "doc1", "read", true},
		{"alpha/alice", "doc1", "write", true},
		{"alpha/bob", "doc1", "read", true},
		{"alpha/bob", "doc1", "write", false},
		{"alpha/bob", "doc2", "write", true},
		{"alpha/carol", "doc1", "read", true},
		{"alpha/carol", "doc1", "write", false},
		{"alpha/stranger", "doc1", "read", false},
	}
	for _, tc := range cases {
		if got := matrix.IsAllowed(tc.user, tc.resource, tc.action); got != tc.want {
			t.Fatalf("IsAllowed(%s,%s,%s)=%v want %v", tc.user, tc.resource, tc.action, got, tc.want)
		}
	}
}

func TestBetaGammaInheritanceExpansion36828(t *testing.T) {
	beta := rebacParityFixtures36828()[1]
	matrix := BuildRbacPermissionMatrix(beta.org, beta.roles, beta.permissions, beta.groupMembers)

	roadmapReaders := matrix.ToUserResourceActions()
	users := []string{}
	for user, resources := range roadmapReaders {
		if actions, ok := resources["roadmap"]; ok && containsString(actions, "read") {
			users = append(users, user)
		}
	}
	sort.Strings(users)
	want := []string{"beta/dave", "beta/erin", "beta/grace"}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("roadmap readers = %v, want %v", users, want)
	}

	gamma := rebacParityFixtures36828()[2]
	gammaMatrix := BuildRbacPermissionMatrix(gamma.org, gamma.roles, gamma.permissions, gamma.groupMembers)
	secretReaders := []string{}
	for _, entry := range gammaMatrix.SortedEntries() {
		if entry.Resource == "secret" && entry.Action == "read" {
			secretReaders = append(secretReaders, entry.Subject)
		}
	}
	sort.Strings(secretReaders)
	wantSecret := []string{"gamma/ivan", "gamma/judy", "gamma/karl"}
	if !reflect.DeepEqual(secretReaders, wantSecret) {
		t.Fatalf("secret readers = %v, want %v (transitive role inheritance)", secretReaders, wantSecret)
	}

	statusReaders := []string{}
	for _, entry := range gammaMatrix.SortedEntries() {
		if entry.Resource == "status" && entry.Action == "read" {
			statusReaders = append(statusReaders, entry.Subject)
		}
	}
	sort.Strings(statusReaders)
	wantStatus := []string{"gamma/ivan", "gamma/judy", "gamma/karl", "gamma/laura"}
	if !reflect.DeepEqual(statusReaders, wantStatus) {
		t.Fatalf("wildcard role status readers = %v, want %v", statusReaders, wantStatus)
	}
}

func TestBatchConvertRolesAcrossOrganizations36828(t *testing.T) {
	fixtures := rebacParityFixtures36828()
	for _, fixture := range fixtures {
		result := BatchConvertRoles(fixture.roles)
		if result.Total != len(fixture.roles) {
			t.Fatalf("org %s: Total=%d want %d", fixture.org, result.Total, len(fixture.roles))
		}
		if result.Succeeded != len(fixture.roles) || result.Failed != 0 {
			t.Fatalf("org %s: Succeeded=%d Failed=%d", fixture.org, result.Succeeded, result.Failed)
		}
		if len(result.Conversions) != len(fixture.roles) {
			t.Fatalf("org %s: conversions len=%d", fixture.org, len(result.Conversions))
		}
		if len(result.Tuples) == 0 {
			t.Fatalf("org %s: expected converted tuples", fixture.org)
		}

		byId := map[string]*RoleConversion{}
		for _, conversion := range result.Conversions {
			byId[conversion.RoleId] = conversion
		}

		admin := byId[fixture.org+"/admin"]
		if fixture.org == "alpha" {
			if admin == nil {
				t.Fatal("missing alpha/admin conversion")
			}
			found := false
			for _, tuple := range admin.Tuples {
				if tuple.SubjectType == RebacObjectUser && tuple.SubjectId == "alpha/alice" && tuple.Relation == RebacRelationMember {
					found = true
				}
			}
			if !found {
				t.Fatalf("admin conversion missing alice member tuple: %#v", admin.Tuples)
			}
		}
	}

	nilResult := BatchConvertRoles([]*Role{nil})
	if nilResult.Failed != 1 || nilResult.Succeeded != 0 {
		t.Fatalf("nil role must be reported as failed, got %+v", nilResult)
	}
}

func TestRelationTupleCanonicalRoundTrip36828(t *testing.T) {
	tuple := NewUsersetTuple(RebacObjectResource, "doc1", "read", RebacObjectRole, "alpha/admin", RebacRelationMember).
		WithDomain("domainA").WithEffect("Allow")

	text := tuple.String()
	parsed, err := ParseRelationTuple(text)
	if err != nil {
		t.Fatalf("ParseRelationTuple(%q) error: %v", text, err)
	}
	if parsed.ObjectType != tuple.ObjectType || parsed.ObjectId != tuple.ObjectId || parsed.Relation != tuple.Relation {
		t.Fatalf("object part mismatch: %#v", parsed)
	}
	if parsed.SubjectType != tuple.SubjectType || parsed.SubjectId != tuple.SubjectId || parsed.SubjectRelation != tuple.SubjectRelation {
		t.Fatalf("subject part mismatch: %#v", parsed)
	}
	if parsed.Domain != tuple.Domain {
		t.Fatalf("domain mismatch: %q != %q", parsed.Domain, tuple.Domain)
	}
}

func TestRebacGraphCyclicRoles36828(t *testing.T) {
	tuples := []RelationTuple{
		NewUsersetTuple(RebacObjectRole, "o/a", RebacRelationMember, RebacObjectRole, "o/b", RebacRelationMember),
		NewUsersetTuple(RebacObjectRole, "o/b", RebacRelationMember, RebacObjectRole, "o/a", RebacRelationMember),
		NewRelationTuple(RebacObjectRole, "o/a", RebacRelationMember, RebacObjectUser, "o/user"),
		NewRelationTuple(RebacObjectResource, "r1", "read", RebacObjectUser, "o/user"),
	}
	graph := NewRebacGraph(tuples...)
	if !graph.CheckUser("o/user", "read", RebacObjectResource, "r1") {
		t.Fatal("expected user to be allowed through direct grant")
	}
	users := graph.ExpandUsers(RebacObjectRole, "o/b", RebacRelationMember)
	if !reflect.DeepEqual(users, []string{"o/user"}) {
		t.Fatalf("cycle expansion = %v, want [o/user]", users)
	}
}

// TestSubjectMatrixMatchesLegacyPolicies36828 proves the migration input model
// reads exactly the policy rows the existing permission API/enforcer produces.
func TestSubjectMatrixMatchesLegacyPolicies36828(t *testing.T) {
	permissions := []*Permission{
		{
			Owner: "org", Name: "p1",
			Users:     []string{"org/alice"},
			Groups:    []string{"org/dev"},
			Roles:     []string{"org/admin"},
			Resources: []string{"data1", "data2"},
			Actions:   []string{"read"},
			Effect:    "Allow",
		},
		{
			Owner: "org", Name: "p2",
			Groups:    []string{"org/qa"},
			Domains:   []string{"domain1", "domain2"},
			Resources: []string{"data3"},
			Actions:   []string{"write"},
			Effect:    "Deny",
		},
	}

	matrix := BuildRbacSubjectMatrix("org", permissions)

	legacy := NewPermissionMatrix("org")
	for _, p := range permissions {
		for _, row := range getPolicies(p) {
			if len(p.Domains) > 0 {
				legacy.AddGrant(row[0], row[1], row[2], row[3], row[4])
			} else {
				legacy.AddGrant(row[0], "", row[1], row[2], row[3])
			}
		}
	}
	legacy.Normalize()

	if !matrix.Equal(legacy) {
		missing, extra := matrix.Diff(legacy)
		t.Fatalf("subject matrix diverges from legacy getPolicies\nmissing=%#v\nextra=%#v", missing, extra)
	}

	// The migrated tuples must preserve the exact declared subject kinds/ids.
	for _, p := range permissions {
		tuples := ConvertPermissionToTuples(p)
		if len(tuples) != len(getPolicies(p)) {
			t.Fatalf("permission %s: %d tuples vs %d legacy policies", p.Name, len(tuples), len(getPolicies(p)))
		}
	}
}

func TestEmptyOrganizationMigration36828(t *testing.T) {
	migration, err := MigrateRbacToRebac("empty", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !migration.Parity || len(migration.Tuples) != 0 {
		t.Fatalf("empty org must migrate to zero tuples with parity, got %+v", migration)
	}
	if !migration.BeforeMatrix.Equal(migration.AfterMatrix) {
		t.Fatal("empty matrices must be equal")
	}
}

func TestRebacTuplePersistenceRoundTrip36828(t *testing.T) {
	engine, err := xorm.NewEngine("sqlite", filepath.Join(t.TempDir(), "rebac.db"))
	if err != nil {
		t.Fatalf("open sqlite engine: %v", err)
	}
	if err := engine.Sync2(new(RelationTuple)); err != nil {
		t.Fatalf("sync relation_tuple table: %v", err)
	}

	oldOrmer := ormer
	ormer = &Ormer{Engine: engine}
	defer func() {
		ormer = oldOrmer
		_ = engine.Close()
	}()

	tuples := []*RelationTuple{
		{
			Owner: "alpha", ObjectType: RebacObjectResource, ObjectId: "doc1",
			Relation: "read", SubjectType: RebacObjectUser, SubjectId: "alpha/alice", Effect: "allow",
		},
		{
			Owner: "alpha", ObjectType: RebacObjectRole, ObjectId: "alpha/admin",
			Relation: RebacRelationMember, SubjectType: RebacObjectUser, SubjectId: "alpha/alice",
		},
	}

	if _, err := UpsertRebacTuples(tuples); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	for _, tuple := range tuples {
		if tuple.TupleId == "" {
			t.Fatal("tuple id must be populated")
		}
	}
	// Re-upserting must stay idempotent.
	if _, err := UpsertRebacTuples(tuples); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := GetRebacTuples("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 persisted tuples, got %d", len(got))
	}

	one, err := GetRebacTuple("alpha", tuples[0].TupleId)
	if err != nil || one == nil {
		t.Fatalf("GetRebacTuple() one=%v err=%v", one, err)
	}

	if _, err := DeleteRebacTuples([]*RelationTuple{tuples[0]}); err != nil {
		t.Fatal(err)
	}
	got, _ = GetRebacTuples("alpha")
	if len(got) != 1 {
		t.Fatalf("expected 1 tuple after delete, got %d", len(got))
	}

	if _, err := DeleteRebacTuplesByOwner("alpha"); err != nil {
		t.Fatal(err)
	}
	got, _ = GetRebacTuples("alpha")
	if len(got) != 0 {
		t.Fatalf("expected 0 tuples after owner delete, got %d", len(got))
	}
}

func TestWildcardSubjectsParity36828(t *testing.T) {
	roles := []*Role{
		{Owner: "org", Name: "r1", Users: []string{"org/u1"}},
		{Owner: "org", Name: "r2", Users: []string{"org/u2"}, Roles: []string{"*"}},
	}
	permissions := []*Permission{
		{
			Owner: "org", Name: "all-groups",
			Groups:    []string{"*"},
			Resources: []string{"board"},
			Actions:   []string{"view"},
			Effect:    "Allow",
		},
		{
			Owner: "org", Name: "all-roles",
			Roles:     []string{"*"},
			Resources: []string{"board"},
			Actions:   []string{"edit"},
			Effect:    "Allow",
		},
	}
	groups := RbacGroupMembers{
		"org/g1": {"org/u3"},
		"org/g2": {"org/u4"},
	}

	before := BuildRbacPermissionMatrix("org", roles, permissions, groups)
	migration, err := MigrateRbacToRebac("org", roles, permissions, groups)
	if err != nil {
		t.Fatal(err)
	}
	after := BuildRebacPermissionMatrix("org", migration.Tuples)
	if !before.Equal(after) {
		missing, extra := before.Diff(after)
		t.Fatalf("wildcard parity mismatch\nmissing=%#v\nextra=%#v", missing, extra)
	}

	viewers := map[string]bool{}
	for _, e := range before.Entries {
		if e.Action == "view" {
			viewers[e.Subject] = true
		}
	}
	if !viewers["org/u3"] || !viewers["org/u4"] {
		t.Fatalf("wildcard group must include every group member, got %v", viewers)
	}

	editors := map[string]bool{}
	for _, e := range before.Entries {
		if e.Action == "edit" {
			editors[e.Subject] = true
		}
	}
	// "*" role covers r1 and r2; r2 also inherits every role, but the concrete
	// editor set remains u1 and u2.
	if !editors["org/u1"] || !editors["org/u2"] || len(editors) != 2 {
		t.Fatalf("wildcard role editors = %v, want u1,u2", editors)
	}
}

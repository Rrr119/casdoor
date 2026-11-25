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
	"fmt"
	"sort"
	"strings"
)

// ReBAC relation and object type constants. They describe the userset
// namespaces produced by the RBAC -> ReBAC migration.
const (
	RebacObjectUser     = "user"
	RebacObjectGroup    = "group"
	RebacObjectRole     = "role"
	RebacObjectResource = "resource"

	RebacRelationMember = "member"
	RebacRelationOwner  = "owner"
	RebacRelationViewer = "viewer"

	// RebacWildcard matches every subject of a namespace.
	RebacWildcard = "*"
)

// RelationTuple is a Zanzibar style relation tuple:
//
//	<ObjectType>:<ObjectId>#<Relation>@<SubjectType>:<SubjectId>[#<SubjectRelation>]
//
// SubjectRelation is empty for concrete subjects (typically users) and
// "member" when the subject is itself a userset, e.g. role:org/admin#member.
type RelationTuple struct {
	Owner           string `xorm:"varchar(100) notnull pk" json:"owner"`
	TupleId         string `xorm:"varchar(64) notnull pk" json:"tupleId"`
	ObjectType      string `xorm:"varchar(100)" json:"objectType"`
	ObjectId        string `xorm:"varchar(255)" json:"objectId"`
	Relation        string `xorm:"varchar(100)" json:"relation"`
	SubjectType     string `xorm:"varchar(100)" json:"subjectType"`
	SubjectId       string `xorm:"varchar(255)" json:"subjectId"`
	SubjectRelation string `xorm:"varchar(100)" json:"subjectRelation,omitempty"`
	Domain          string `xorm:"varchar(100)" json:"domain,omitempty"`
	Effect          string `xorm:"varchar(20)" json:"effect,omitempty"`
}

// RebacTuple and Tuple are compatibility aliases for callers that name the
// migrated tuple type differently.
type RebacTuple = RelationTuple
type Tuple = RelationTuple

// NewRelationTuple builds a tuple with a concrete subject.
func NewRelationTuple(objectType, objectId, relation, subjectType, subjectId string) RelationTuple {
	return RelationTuple{
		ObjectType:  objectType,
		ObjectId:    objectId,
		Relation:    relation,
		SubjectType: subjectType,
		SubjectId:   subjectId,
	}
}

// NewUsersetTuple builds a tuple whose subject is a userset (<type>:<id>#<relation>).
func NewUsersetTuple(objectType, objectId, relation, subjectType, subjectId, subjectRelation string) RelationTuple {
	return RelationTuple{
		ObjectType:      objectType,
		ObjectId:        objectId,
		Relation:        relation,
		SubjectType:     subjectType,
		SubjectId:       subjectId,
		SubjectRelation: subjectRelation,
	}
}

// WithDomain returns the tuple scoped to a Casbin domain.
func (t RelationTuple) WithDomain(domain string) RelationTuple {
	t.Domain = domain
	return t
}

// WithEffect returns the tuple carrying the original RBAC policy effect ("allow"/"deny").
func (t RelationTuple) WithEffect(effect string) RelationTuple {
	t.Effect = strings.ToLower(effect)
	return t
}

// Key is the de-duplication identity of a tuple, including domain and effect.
func (t RelationTuple) Key() string {
	return strings.Join([]string{
		t.ObjectType, t.ObjectId, t.Relation,
		t.SubjectType, t.SubjectId, t.SubjectRelation,
		t.Domain, strings.ToLower(t.Effect),
	}, "\x00")
}

// String renders the canonical textual tuple notation.
func (t RelationTuple) String() string {
	subject := fmt.Sprintf("%s:%s", t.SubjectType, t.SubjectId)
	if t.SubjectRelation != "" {
		subject += "#" + t.SubjectRelation
	}
	s := fmt.Sprintf("%s:%s#%s@%s", t.ObjectType, t.ObjectId, t.Relation, subject)
	if t.Domain != "" {
		s = fmt.Sprintf("%s (domain=%s)", s, t.Domain)
	}
	return s
}

// ParseRelationTuple parses the canonical notation produced by String().
func ParseRelationTuple(text string) (RelationTuple, error) {
	t := RelationTuple{}

	if idx := strings.Index(text, " (domain="); idx >= 0 {
		t.Domain = strings.TrimSuffix(text[idx+len(" (domain="):], ")")
		text = text[:idx]
	}

	at := strings.Index(text, "@")
	hash := strings.Index(text, "#")
	if at < 0 || hash < 0 || hash > at {
		return t, fmt.Errorf("invalid relation tuple %q: expected type:id#relation@subject", text)
	}

	objectPart := text[:hash]
	t.Relation = text[hash+1 : at]
	subjectPart := text[at+1:]

	var ok bool
	t.ObjectType, t.ObjectId, ok = cutTypeAndId(objectPart)
	if !ok {
		return t, fmt.Errorf("invalid relation tuple %q: malformed object %q", text, objectPart)
	}

	subjectUsersetHash := strings.Index(subjectPart, "#")
	if subjectUsersetHash >= 0 {
		t.SubjectRelation = subjectPart[subjectUsersetHash+1:]
		subjectPart = subjectPart[:subjectUsersetHash]
	}

	t.SubjectType, t.SubjectId, ok = cutTypeAndId(subjectPart)
	if !ok {
		return t, fmt.Errorf("invalid relation tuple %q: malformed subject %q", text, subjectPart)
	}

	return t, nil
}

func cutTypeAndId(value string) (string, string, bool) {
	idx := strings.Index(value, ":")
	if idx <= 0 || idx == len(value)-1 {
		return "", "", false
	}
	return value[:idx], value[idx+1:], true
}

// RebacGraph is an in-memory relation tuple store with userset expansion.
// It is safe for concurrent reads after construction.
type RebacGraph struct {
	tuples []RelationTuple
	index  map[string][]RelationTuple
}

// NewRebacGraph builds a graph from the given tuples.
func NewRebacGraph(tuples ...RelationTuple) *RebacGraph {
	g := &RebacGraph{index: map[string][]RelationTuple{}}
	g.AddTuples(tuples...)
	return g
}

func tupleObjectKey(objectType, objectId, relation, domain string) string {
	return strings.Join([]string{objectType, objectId, relation, domain}, "\x00")
}

// AddTuples appends tuples to the graph.
func (g *RebacGraph) AddTuples(tuples ...RelationTuple) {
	for _, t := range tuples {
		g.tuples = append(g.tuples, t)
		key := tupleObjectKey(t.ObjectType, t.ObjectId, t.Relation, t.Domain)
		g.index[key] = append(g.index[key], t)
	}
}

// Tuples returns all stored tuples.
func (g *RebacGraph) Tuples() []RelationTuple {
	return g.tuples
}

// CheckUser reports whether userId reaches <objectType>:<objectId>#<relation>
// through direct grants or transitive userset membership.
func (g *RebacGraph) CheckUser(userId, relation, objectType, objectId string, domain ...string) bool {
	d := ""
	if len(domain) > 0 {
		d = domain[0]
	}

	type node struct {
		objectType string
		objectId   string
		relation   string
	}

	visited := map[node]struct{}{}
	queue := []node{{objectType, objectId, relation}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := visited[current]; ok {
			continue
		}
		visited[current] = struct{}{}

		for _, t := range g.tuplesFor(current.objectType, current.objectId, current.relation, d) {
			if t.SubjectType == RebacObjectUser && t.SubjectRelation == "" {
				if t.SubjectId == userId || t.SubjectId == RebacWildcard {
					return true
				}
				continue
			}
			if t.SubjectRelation != "" {
				queue = append(queue, node{t.SubjectType, t.SubjectId, t.SubjectRelation})
			}
		}
	}
	return false
}

// Check is the generic subject check. A concrete user subject is matched
// directly; userset subjects expand through their SubjectRelation.
func (g *RebacGraph) Check(subjectType, subjectId, relation, objectType, objectId string, domain ...string) bool {
	d := ""
	if len(domain) > 0 {
		d = domain[0]
	}
	if subjectType == RebacObjectUser {
		return g.CheckUser(subjectId, relation, objectType, objectId, d)
	}
	users := g.ExpandUsers(subjectType, subjectId, RebacRelationMember, d)
	for _, userId := range users {
		if g.CheckUser(userId, relation, objectType, objectId, d) {
			return true
		}
	}
	return false
}

// IsAllowed applies Casdoor deny-override semantics over migrated grant
// tuples: a matching deny wins, otherwise any matching allow grants access.
func (g *RebacGraph) IsAllowed(userId, relation, objectType, objectId string, domain ...string) bool {
	d := ""
	if len(domain) > 0 {
		d = domain[0]
	}

	allowed := false
	for _, t := range g.tuplesFor(objectType, objectId, relation, d) {
		matched := false
		if t.SubjectType == RebacObjectUser && t.SubjectRelation == "" {
			matched = t.SubjectId == userId || t.SubjectId == RebacWildcard
		} else if t.SubjectRelation != "" {
			for _, member := range g.ExpandUsers(t.SubjectType, t.SubjectId, t.SubjectRelation, d) {
				if member == userId {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}

		if normalizeEffect(t.Effect) == "deny" {
			return false
		}
		allowed = true
	}
	return allowed
}

// ExpandUsers returns the sorted concrete user IDs that reach
// <objectType>:<objectId>#<relation>.
func (g *RebacGraph) ExpandUsers(objectType, objectId, relation string, domain ...string) []string {
	d := ""
	if len(domain) > 0 {
		d = domain[0]
	}

	type node struct {
		objectType string
		objectId   string
		relation   string
	}

	users := map[string]struct{}{}
	visited := map[node]struct{}{}
	queue := []node{{objectType, objectId, relation}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := visited[current]; ok {
			continue
		}
		visited[current] = struct{}{}

		for _, t := range g.tuplesFor(current.objectType, current.objectId, current.relation, d) {
			if t.SubjectType == RebacObjectUser && t.SubjectRelation == "" {
				if t.SubjectId != RebacWildcard {
					users[t.SubjectId] = struct{}{}
				}
				continue
			}
			if t.SubjectRelation != "" {
				queue = append(queue, node{t.SubjectType, t.SubjectId, t.SubjectRelation})
			}
		}
	}

	result := make([]string, 0, len(users))
	for u := range users {
		result = append(result, u)
	}
	sort.Strings(result)
	return result
}

// tuplesFor returns domain-exact tuples plus global (domain-empty) tuples.
func (g *RebacGraph) tuplesFor(objectType, objectId, relation, domain string) []RelationTuple {
	tuples := g.index[tupleObjectKey(objectType, objectId, relation, domain)]
	if domain != "" {
		tuples = append(tuples, g.index[tupleObjectKey(objectType, objectId, relation, "")]...)
	}
	return tuples
}

// DedupTuples de-duplicates tuples by Key while preserving first-seen order.
func DedupTuples(tuples []*RelationTuple) []*RelationTuple {
	seen := map[string]struct{}{}
	result := make([]*RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		if t == nil {
			continue
		}
		key := t.Key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, t)
	}
	return result
}

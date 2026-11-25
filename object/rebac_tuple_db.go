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

// TableName persists relation tuples in the rebac_tuple table.
func (t RelationTuple) TableName() string {
	return "rebac_tuple"
}

// GetRebacTuples returns all relation tuples of an organization. An empty
// owner returns every tuple.
func GetRebacTuples(owner string) ([]*RelationTuple, error) {
	tuples := []*RelationTuple{}
	session := ormer.Engine.Asc("owner", "tuple_id")
	if owner != "" {
		session = session.Where("owner = ?", owner)
	}
	err := session.Find(&tuples)
	return tuples, err
}

// GetRebacTuple returns one tuple by (owner, tupleId).
func GetRebacTuple(owner string, tupleId string) (*RelationTuple, error) {
	tuple := &RelationTuple{Owner: owner, TupleId: tupleId}
	existed, err := ormer.Engine.Get(tuple)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return tuple, nil
}

// AddRebacTuples inserts new tuples, filling deterministic IDs when missing.
func AddRebacTuples(tuples []*RelationTuple) (bool, error) {
	if len(tuples) == 0 {
		return false, nil
	}
	for _, tuple := range tuples {
		if tuple.TupleId == "" {
			tuple.TupleId = tupleHash(tuple)
		}
	}
	_, err := ormer.Engine.Insert(tuples)
	return err == nil, err
}

// UpsertRebacTuples inserts missing tuples and updates existing ones.
func UpsertRebacTuples(tuples []*RelationTuple) (bool, error) {
	for _, tuple := range tuples {
		if tuple.TupleId == "" {
			tuple.TupleId = tupleHash(tuple)
		}

		existed, err := ormer.Engine.Get(&RelationTuple{Owner: tuple.Owner, TupleId: tuple.TupleId})
		if err != nil {
			return false, err
		}
		if existed {
			_, err = ormer.Engine.Where("owner = ? AND tuple_id = ?", tuple.Owner, tuple.TupleId).AllCols().Update(tuple)
		} else {
			_, err = ormer.Engine.Insert(tuple)
		}
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// DeleteRebacTuples removes the given tuples.
func DeleteRebacTuples(tuples []*RelationTuple) (bool, error) {
	if len(tuples) == 0 {
		return false, nil
	}
	for _, tuple := range tuples {
		_, err := ormer.Engine.Delete(tuple)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// DeleteRebacTuplesByOwner clears every tuple of an organization.
func DeleteRebacTuplesByOwner(owner string) (bool, error) {
	_, err := ormer.Engine.Where("owner = ?", owner).Delete(&RelationTuple{})
	return err == nil, err
}

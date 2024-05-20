package redos

import (
	"encoding/json"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
)

type RpmInfoTestSpecial struct {
	Name string
	//SignatureKeyID signatureKeyID
	FixedVersion string
	Arch         string
}

func unmarshalJSONFile(v interface{}, fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return xerrors.Errorf("unable to open a file (%s): %w", fileName, err)
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(v); err != nil {
		return xerrors.Errorf("failed to decode ALT OVAL JSON: %w", err)
	}
	return nil
}

func parseObjects(dir string) (map[string]RpmInfoObject, error) {
	var objects Objects
	if err := unmarshalJSONFile(&objects, filepath.Join(dir, "objects.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal objects: %w", err)
	}
	objs := map[string]RpmInfoObject{}
	for _, obj := range objects.RpmInfoObjects {
		objs[obj.ID] = obj
	}
	return objs, nil
}

func parseStates(dir string) (map[string]RpmInfoState, error) {
	var ss States
	if err := unmarshalJSONFile(&ss, filepath.Join(dir, "states.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal states: %w", err)
	}

	states := map[string]RpmInfoState{}
	for _, state := range ss.RpmInfoState {
		states[state.ID] = state
	}
	return states, nil
}

func parseTests(dir string) (map[string]RpmInfoTestSpecial, error) {
	objects, err := parseObjects(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse objects: %w", err)
	}

	states, err := parseStates(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse states: %w", err)
	}

	var tests Tests
	if err := unmarshalJSONFile(&tests, filepath.Join(dir, "tests.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal states: %w", err)
	}

	rpmTests := map[string]RpmInfoTestSpecial{}
	for _, test := range tests.RPMInfoTests {
		// test.Check should be "at least one"
		//if test.Check != "at least one" {
		//	continue
		//}

		t, err := followTestRefs(test, objects, states)
		if err != nil {
			return nil, xerrors.Errorf("unable to follow test refs: %w", err)
		}
		rpmTests[test.ID] = t
	}
	return rpmTests, nil
}

func followTestRefs(test RpmInfoTest, objects map[string]RpmInfoObject, states map[string]RpmInfoState) (RpmInfoTestSpecial, error) {
	var t RpmInfoTestSpecial

	// Follow object ref
	//if test.Object.ObjectRef == "" {
	if test.Object.StateRef == "" {
		return t, nil
	}

	//pkgName, ok := objects[test.Object.ObjectRef]
	obj, ok := objects[test.Object.StateRef]
	if !ok {
		return t, xerrors.Errorf("invalid tests data, can't find object ref: %s, test ref: %s",
			test.Object.StateRef, test.ID)
		//test.Object.ObjectRef, test.ID)
	}
	t.Name = obj.Name

	// Follow state ref
	if test.State.StateRef == "" {
		return t, nil
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return t, xerrors.Errorf("invalid tests data, can't find ovalstate ref %s, test ref: %s",
			test.State.StateRef, test.ID)
	}

	//t.SignatureKeyID = state.SignatureKeyID
	//
	if state.Arch.Datatype == "string" && (state.Arch.Operation == "pattern match" || state.Arch.Operation == "equals") {
		t.Arch = state.Arch.Text
	}

	if state.Evr.Datatype == "evr_string" && state.Evr.Operation == "less than" {
		t.FixedVersion = state.Evr.Text
	}

	return t, nil
}

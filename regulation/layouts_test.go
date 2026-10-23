package regulation

import (
	"os"
	"path/filepath"
	"testing"
)

// The registry is only worth having if it is checked against reality. This is
// the guard that would have caught the BuddyParam shortfall the first time
// anything opened that table.
func TestRegisteredLayoutsMatchTheRegulation(t *testing.T) {
	savePath := requireSave(t)
	checks, err := VerifyParamLayouts(savePath, optionalParamdexRoot())
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != len(paramLayouts) {
		t.Fatalf("checked %d tables, %d are registered", len(checks), len(paramLayouts))
	}
	singleRow := make(map[string]bool, len(paramLayouts))
	for _, layout := range paramLayouts {
		singleRow[layout.Table] = layout.SingleRow
	}
	for _, check := range checks {
		// A one-row table has no stride to observe, so the registry size comes
		// from the pinned definition instead. The declaration is what makes
		// that acceptable; an undeclared table with no stride still fails.
		if !singleRow[check.Table] && check.ObservedRowSize != check.RegistryRowSize {
			t.Errorf("%s: regulation stride %d, registry %d", check.Table, check.ObservedRowSize, check.RegistryRowSize)
		}
		if singleRow[check.Table] && check.SchemaRowSize != 0 && check.SchemaRowSize != check.RegistryRowSize {
			t.Errorf("%s: single-row table registry %d, definition %d", check.Table, check.RegistryRowSize, check.SchemaRowSize)
		}
		if len(check.Status) >= 8 && check.Status[:8] == "MISMATCH" {
			t.Errorf("%s: %s", check.Table, check.Status)
		}
	}
}

// A stale or short Paramdex definition must be declared, not discovered later.
// This runs only with a pinned checkout available.
func TestPinnedDefinitionsCoverTheirRows(t *testing.T) {
	savePath := requireSave(t)
	root := paramdexRoot(t)
	checks, err := VerifyParamLayouts(savePath, root)
	if err != nil {
		t.Fatal(err)
	}
	shortfalls := 0
	for _, check := range checks {
		if check.SchemaRowSize == 0 {
			t.Errorf("%s: no pinned definition resolved", check.Table)
			continue
		}
		gap := check.RegistryRowSize - check.SchemaRowSize
		if gap != check.SchemaShortfall {
			t.Errorf("%s: definition covers %d of %d bytes, an undeclared shortfall of %d",
				check.Table, check.SchemaRowSize, check.RegistryRowSize, gap)
		}
		if gap > 0 {
			shortfalls++
			if check.Note == "" {
				t.Errorf("%s has a %d-byte shortfall with no explanatory note", check.Table, gap)
			}
		}
	}
	// BuddyParam is the only table whose published definition is known to be
	// short. A second one appearing is a research finding, not a test failure to
	// paper over.
	if shortfalls != 1 {
		t.Errorf("expected exactly one known short definition, found %d", shortfalls)
	}
}

// SpEffectParam and SpEffectVfxParam resolve to definition files with different
// names. Getting that mapping wrong is silent: field decoding degrades to raw
// byte offsets rather than failing.
func TestSchemaNameMappingResolves(t *testing.T) {
	for _, testCase := range []struct{ table, schema string }{
		{"SpEffectParam", "SpEffect"},
		{"SpEffectVfxParam", "SpEffectVfx"},
		{"BuddyParam", "BuddyParam"},
	} {
		layout, present := LayoutFor(testCase.table)
		if !present {
			t.Fatalf("%s is not registered", testCase.table)
		}
		if got := layout.SchemaName(); got != testCase.schema {
			t.Errorf("%s resolves definition %q, expected %q", testCase.table, got, testCase.schema)
		}
	}
}

// The private saves live in the research project; ER_SAVE names another.
func requireSave(t *testing.T) string {
	t.Helper()
	path := os.Getenv("ER_SAVE")
	if path == "" {
		path = filepath.Join("..", "..", "ER_research", "save_file", "memory-1.17.1.dat")
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("private save %s is absent: %v", path, err)
	}
	return path
}

// optionalParamdexRoot is ER_PARAMDEX_ROOT, else the workspace's pinned
// checkout when it is present, else empty.
func optionalParamdexRoot() string {
	if root := os.Getenv("ER_PARAMDEX_ROOT"); root != "" {
		return root
	}
	root := filepath.Join("..", "..", "external", "Paramdex")
	if _, err := os.Stat(root); err != nil {
		return ""
	}
	return root
}

func paramdexRoot(t *testing.T) string {
	t.Helper()
	root := optionalParamdexRoot()
	if root == "" {
		t.Skip("no Paramdex checkout: set ER_PARAMDEX_ROOT")
	}
	return root
}

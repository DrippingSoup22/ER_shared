package regulation

import "testing"

// The bit-packing and version-gate rules are schema-layer behaviour, so the
// test lives beside them rather than reaching across a package boundary.
func TestLayoutPacksBitsAndHonorsVersionGates(t *testing.T) {
	definitions := []paramdexFieldXML{
		{Def: "u8 low:4 = 0"},
		{Def: "dummy8 reserved:4 = 0"},
		{Def: "s16 old = -1", RemovedVersion: 20},
		{Def: "u32 current = 0", FirstVersion: 20},
		{Def: "fixstr label[8] = 0"},
	}
	fields, size, err := layoutParamFields(definitions, 20)
	if err != nil {
		t.Fatal(err)
	}
	if size != 13 {
		t.Fatalf("row size = %d, want 13", size)
	}
	if len(fields) != 4 || fields[0].Offset != 0 || fields[0].BitOffset != 0 || fields[1].Offset != 0 || fields[1].BitOffset != 4 || fields[2].Name != "current" || fields[2].Offset != 1 || fields[3].Offset != 5 {
		t.Fatalf("unexpected field layout: %#v", fields)
	}
}

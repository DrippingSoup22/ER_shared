package regulation

import (
	"fmt"
	"math"
	"testing"
)

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

// Every value written must read back the same through DecodeParamField, a bit
// field must leave its neighbours alone, and a value the field cannot hold is
// refused without touching the row.
func TestEncodeParamFieldRoundTripsAndRefusesWhatCannotFit(t *testing.T) {
	blob := make([]byte, 16)
	blob[12] = 0xFF
	cases := []struct {
		field ParamField
		value float64
	}{
		{ParamField{Name: "a", Type: "s8", Offset: 0, Size: 1}, -128},
		{ParamField{Name: "b", Type: "u16", Offset: 1, Size: 2}, 65535},
		{ParamField{Name: "c", Type: "s32", Offset: 3, Size: 4}, -1},
		{ParamField{Name: "d", Type: "f32", Offset: 7, Size: 4}, 0.05},
		{ParamField{Name: "e", Type: "u8", Offset: 12, Size: 1, BitOffset: 3, BitSize: 3}, 2},
	}
	for _, c := range cases {
		if err := EncodeParamField(blob, c.field, c.value); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeParamField(blob, c.field)
		if err != nil {
			t.Fatal(err)
		}
		if want := c.value; c.field.Type == "f32" && got != float32(want) ||
			c.field.Type != "f32" && fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s reads %v, want %v", c.field.Name, got, c.value)
		}
	}
	if blob[12] != 0xD7 {
		t.Errorf("the bit field's byte is %#x, want its other bits kept: 0xd7", blob[12])
	}
	before := append([]byte(nil), blob...)
	for _, bad := range []struct {
		field ParamField
		value float64
	}{
		{cases[0].field, 128}, {cases[1].field, 1.5}, {cases[2].field, math.NaN()},
		{cases[3].field, 1e39}, {cases[4].field, 8},
		{ParamField{Name: "f", Type: "u8", Offset: 15, Size: 2}, 1},
	} {
		if err := EncodeParamField(blob, bad.field, bad.value); err == nil {
			t.Errorf("%s took %g", bad.field.Name, bad.value)
		}
	}
	if string(before) != string(blob) {
		t.Error("a refused value changed the row")
	}
}

package regulation

import (
	"encoding/binary"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

func realBND4(t *testing.T) []byte {
	t.Helper()
	loaded, err := Load(requireSave(t))
	if err != nil {
		t.Fatal(err)
	}
	return loaded.BND4
}

// The PARAM shape a rebuild assumes, measured on the shipped regulation:
// header, row table, bodies in header order, then a string region that opens
// with the type name, and every row named.
func TestShippedTablesUseTheShapeRebuildsAssume(t *testing.T) {
	bnd4 := realBND4(t)
	for _, name := range []string{"EquipParamGoods", "BuddyParam", "BuddyStoneParam"} {
		layout := MustLayout(name)
		table, err := OpenTable(bnd4, layout)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := readParamGeometry(table); err != nil {
			t.Fatal(err)
		}
		header, err := parseParamHeader(table.Data)
		if err != nil {
			t.Fatal(err)
		}
		named := 0
		for index := range table.Rows {
			base := header.RowTableOffset + index*rowHeaderSize
			if binary.LittleEndian.Uint64(table.Data[base+16:base+24]) != 0 {
				named++
			}
		}
		// Every row is named, so relocating names is never an edge case.
		if named != len(table.Rows) {
			t.Errorf("%s: %d of %d rows carry a name", name, named, len(table.Rows))
		}
	}
}

// The BND4 shape resizing an entry assumes: stored entries, contiguous
// 16-aligned allocations, and every name ahead of every byte of data.
func TestShippedBinderAllocatesEntriesContiguously(t *testing.T) {
	blob := realBND4(t)
	if got := binary.LittleEndian.Uint64(blob[0x20:0x28]); got != bnd4EntryHeaderSize {
		t.Fatalf("entry header size is %#x, want %#x", got, bnd4EntryHeaderSize)
	}
	entries, err := ListBND4Entries(blob)
	if err != nil {
		t.Fatal(err)
	}
	lowestData, highestNameEnd := len(blob), 0
	for index, entry := range entries {
		base := bnd4EntryTableOffset + index*bnd4EntryHeaderSize
		if got := binary.LittleEndian.Uint64(blob[base+16 : base+24]); got != uint64(entry.Size) {
			t.Fatalf("entry %q is compressed (%d stored, %d uncompressed)", entry.Name, entry.Size, got)
		}
		lowestData = min(lowestData, entry.Offset)
		nameEnd := int(binary.LittleEndian.Uint32(blob[base+32 : base+36]))
		for nameEnd+2 <= len(blob) && binary.LittleEndian.Uint16(blob[nameEnd:nameEnd+2]) != 0 {
			nameEnd += 2
		}
		highestNameEnd = max(highestNameEnd, nameEnd+2)
	}
	if highestNameEnd > lowestData {
		t.Errorf("entry names end at %#x, past the first data at %#x", highestNameEnd, lowestData)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Offset < entries[j].Offset })
	for index := 0; index+1 < len(entries); index++ {
		if want := align16(entries[index].Offset + entries[index].Size); want != entries[index+1].Offset {
			t.Fatalf("entry %q ends at %#x but %q starts at %#x",
				entries[index].Name, want, entries[index+1].Name, entries[index+1].Offset)
		}
	}
	if last := entries[len(entries)-1]; last.Offset+last.Size != len(blob) {
		t.Errorf("last entry %q ends at %#x, archive ends at %#x", last.Name, last.Offset+last.Size, len(blob))
	}
}

// The verifiers are the safety property, so each must fail when its claim is
// false.
func TestTheVerifiersRejectFalseClaims(t *testing.T) {
	bnd4 := realBND4(t)
	layout := MustLayout("BuddyParam")
	table, err := OpenTable(bnd4, layout)
	if err != nil {
		t.Fatal(err)
	}
	shipped := rowDigests(table)
	first, second, third := table.Rows[0].ID, table.Rows[1].ID, table.Rows[2].ID

	altered := make(map[int32][32]byte, len(shipped))
	for id := range shipped {
		altered[id] = [32]byte{}
	}
	if err := verifyRowInsertion(bnd4, layout, altered, nil); err == nil || !strings.Contains(err.Error(), "changed during insertion") {
		t.Errorf("a changed row: err = %v", err)
	}

	removed := func(rows ...int32) []byte {
		rebuilt, err := rebuildTableWithoutRows(table, rows)
		if err != nil {
			t.Fatal(err)
		}
		result, err := ReplaceBND4Entry(bnd4, table.Entry, rebuilt)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	// Removing first and third while declaring first and second gets past the
	// row count, so only the by-ID comparison can notice.
	if err := verifyRowRemoval(removed(first, third), layout, shipped, []int32{first, second}); err == nil {
		t.Error("accepted a table still holding a row declared for removal")
	}
	if err := verifyRowRemoval(removed(first, second), layout, shipped, []int32{first}); err == nil {
		t.Error("accepted a table that lost an undeclared row")
	}
}

// An anchored chain lands as one block right after its anchor, every row
// already there keeps its name (the string region moves), and each request
// that cannot be honoured is refused before anything is written.
func TestRowsGoWhereTheyAreToldOrAreRefused(t *testing.T) {
	bnd4 := realBND4(t)
	layout := MustLayout("BuddyParam")
	table, err := OpenTable(bnd4, layout)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int32, len(table.Rows))
	for i, row := range table.Rows {
		ids[i] = row.ID
	}
	last := ids[len(ids)-1]
	anchor, first, second := ids[0], last+1, last+2

	grown, err := InsertRows(bnd4, layout, []RowInsertion{
		{RowID: first, CopyFrom: ids[1], InsertAfter: &anchor},
		{RowID: second, CopyFrom: ids[1], InsertAfter: &first},
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := OpenTable(grown, layout)
	if err != nil {
		t.Fatal(err)
	}
	if got := []int32{after.Rows[0].ID, after.Rows[1].ID, after.Rows[2].ID}; got[0] != anchor || got[1] != first || got[2] != second {
		t.Fatalf("the block begins %v, want %d, %d, %d", got, anchor, first, second)
	}
	before, now := rowNames(t, bnd4, layout), rowNames(t, grown, layout)
	for id, name := range before {
		if now[id] != name {
			t.Fatalf("row %d is named %q after the insertion, was %q", id, now[id], name)
		}
	}

	missing := int32(1)
	for _, refused := range []struct {
		insertions []RowInsertion
		want       string
	}{
		{[]RowInsertion{{RowID: ids[1], CopyFrom: ids[0]}}, "already exists"},
		{[]RowInsertion{{RowID: ids[0] - 1, CopyFrom: ids[0]}}, "may only append"},
		{[]RowInsertion{{RowID: first, CopyFrom: 1}}, "copy source row 1 does not exist"},
		{[]RowInsertion{{RowID: first, CopyFrom: ids[0], InsertAfter: &missing}}, "anchor row 1 occurs 0 times"},
		{[]RowInsertion{{RowID: first, CopyFrom: ids[0]}, {RowID: first, CopyFrom: ids[0]}}, "inserted twice"},
	} {
		if _, err := InsertRows(bnd4, layout, refused.insertions); err == nil || !strings.Contains(err.Error(), refused.want) {
			t.Errorf("insertion %+v: err = %v, want %q", refused.insertions, err, refused.want)
		}
	}
	for _, removals := range [][]int32{{987654321}, {ids[0], ids[0]}, ids} {
		if _, err := RemoveRows(bnd4, layout, removals); err == nil {
			t.Errorf("removing %d rows starting %v was accepted", len(removals), removals[0])
		}
	}
}

// rowNames reads each row's name through its own offset, the pointer an
// insertion or removal has to relocate.
func rowNames(t *testing.T, bnd4 []byte, layout TableLayout) map[int32]string {
	t.Helper()
	_, data, header, rows, err := LoadParamRows(bnd4, layout.Entry)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[int32]string, len(rows))
	for index, row := range rows {
		base := header.RowTableOffset + index*24
		offset := int(binary.LittleEndian.Uint64(data[base+16 : base+24]))
		if offset == 0 {
			continue
		}
		var units []uint16
		for position := offset; position+2 <= len(data); position += 2 {
			unit := binary.LittleEndian.Uint16(data[position:])
			if unit == 0 {
				break
			}
			units = append(units, unit)
		}
		names[row.ID] = string(utf16.Decode(units))
	}
	if len(names) == 0 {
		t.Fatal("no row carries a name; nothing witnesses the relocation")
	}
	return names
}

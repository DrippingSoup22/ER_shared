package regulation

// Structural edits: adding and removing PARAM rows.
//
// A patch changes bytes inside existing rows, so the row table and every
// offset stay put. Inserting or removing a row changes the row count, the row
// headers, every body offset after it, the size of the BND4 entry and the
// offset of every entry after that. A byte-window comparison cannot express
// that, so each operation carries its own proof, compared by row ID rather
// than by offset: every row that was there and was not removed survives
// byte-identically, and the only rows that appear or vanish are the declared
// ones.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	rowHeaderSize    = 24
	maxParamRowCount = 0xFFFF
	// paramRowTableOffset is where the row table starts in the shipped PARAM
	// shape. It equals bnd4EntryTableOffset by coincidence.
	paramRowTableOffset = 0x40
)

// Table is one PARAM whose identity and stride match a TableLayout.
type Table struct {
	Entry  BND4Entry
	Data   []byte
	Rows   []ParamRow
	ByID   map[int32]ParamRow
	Layout TableLayout
}

// OpenTable loads a PARAM and refuses it unless its type, data version and
// row stride are the ones the layout declares and every row holds a full
// stride.
func OpenTable(bnd4 []byte, layout TableLayout) (*Table, error) {
	entry, err := FindBND4Entry(bnd4, layout.Entry)
	if err != nil {
		return nil, err
	}
	data := bnd4[entry.Offset : entry.Offset+entry.Size]
	header, err := parseParamHeader(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", layout.Entry, err)
	}
	if header.ParamType != layout.ParamType || header.DataVersion != layout.DataVersion {
		return nil, fmt.Errorf("%s is %q/%d, expected %q/%d: %w", layout.Entry,
			header.ParamType, header.DataVersion, layout.ParamType, layout.DataVersion, ErrUnsupportedRegulation)
	}
	rows, err := parseParamRows(data, header, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", layout.Entry, err)
	}
	observed, err := UniformRowSize(data, rows)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", layout.Entry, err)
	}
	if observed != layout.RowSize {
		return nil, fmt.Errorf("%s stride is %d bytes, expected %d; the regulation version is unsupported: %w",
			layout.Entry, observed, layout.RowSize, ErrUnsupportedRegulation)
	}
	byID := make(map[int32]ParamRow, len(rows))
	for _, row := range rows {
		if err := RequireRowSize(data, row, layout.RowSize, layout.Entry); err != nil {
			return nil, err
		}
		byID[row.ID] = row
	}
	return &Table{Entry: entry, Data: data, Rows: rows, ByID: byID, Layout: layout}, nil
}

// RowInsertion is one row to add, byte-copied from an existing row. Callers
// then edit the copy like any other row. An inserted row carries no name:
// names are debug strings the game never reads.
type RowInsertion struct {
	RowID    int32
	CopyFrom int32
	// InsertAfter names the row the new one must physically follow. Nil
	// appends, which is allowed only when RowID is above every existing ID.
	// Placement matters: BuddyParam's consumer walks a contiguous block.
	InsertAfter *int32
}

// InsertRows returns a new BND4 with the rows added to one table. The input is
// never modified.
func InsertRows(bnd4 []byte, layout TableLayout, insertions []RowInsertion) ([]byte, error) {
	if len(insertions) == 0 {
		return nil, fmt.Errorf("%s: no rows to insert", layout.Entry)
	}
	table, err := OpenTable(bnd4, layout)
	if err != nil {
		return nil, err
	}
	shipped := rowDigests(table)
	rebuilt, err := rebuildTableWithRows(table, insertions)
	if err != nil {
		return nil, err
	}
	grown, err := ReplaceBND4Entry(bnd4, table.Entry, rebuilt)
	if err != nil {
		return nil, err
	}
	if err := verifyRowInsertion(grown, layout, shipped, insertions); err != nil {
		return nil, err
	}
	return grown, nil
}

// RemoveRows returns a new BND4 with the rows taken out of one table. The
// input is never modified. Deciding which rows a caller may remove is the
// caller's job.
func RemoveRows(bnd4 []byte, layout TableLayout, removals []int32) ([]byte, error) {
	if len(removals) == 0 {
		return nil, fmt.Errorf("%s: no rows to remove", layout.Entry)
	}
	table, err := OpenTable(bnd4, layout)
	if err != nil {
		return nil, err
	}
	shipped := rowDigests(table)
	rebuilt, err := rebuildTableWithoutRows(table, removals)
	if err != nil {
		return nil, err
	}
	shrunk, err := ReplaceBND4Entry(bnd4, table.Entry, rebuilt)
	if err != nil {
		return nil, err
	}
	if err := verifyRowRemoval(shrunk, layout, shipped, removals); err != nil {
		return nil, err
	}
	return shrunk, nil
}

func rowDigests(table *Table) map[int32][32]byte {
	digests := make(map[int32][32]byte, len(table.Rows))
	for _, row := range table.Rows {
		digests[row.ID] = sha256.Sum256(table.Data[row.DataOffset : row.DataOffset+table.Layout.RowSize])
	}
	return digests
}

// paramGeometry is where a shipped PARAM keeps its regions.
type paramGeometry struct {
	tableEnd      int
	dataStart     int
	stringsOffset int
	typeOffset    int
}

// readParamGeometry validates the shipped PARAM shape: header, row table, row
// bodies in header order, then a string region starting with the type name.
// Anything else is a different format, so it is refused rather than guessed.
func readParamGeometry(table *Table) (*ParamHeader, paramGeometry, error) {
	data, layout, rows := table.Data, table.Layout, table.Rows
	header, err := parseParamHeader(data)
	if err != nil {
		return nil, paramGeometry{}, fmt.Errorf("%s: %w", layout.Entry, err)
	}
	if !header.LongDataOffset || data[0x2D]&0x80 == 0 || header.RowTableOffset != paramRowTableOffset {
		return nil, paramGeometry{}, fmt.Errorf("%s: rebuilding supports only the shipped PARAM shape - 64-bit row offsets, type string by offset, row table at 0x40: %w",
			layout.Entry, ErrUnsupportedRegulation)
	}
	if len(rows) == 0 || header.RowCount != len(rows) {
		return nil, paramGeometry{}, fmt.Errorf("%s: header declares %d rows but %d parsed", layout.Entry, header.RowCount, len(rows))
	}
	geometry := paramGeometry{tableEnd: header.RowTableOffset + len(rows)*rowHeaderSize}
	if geometry.tableEnd > len(data) {
		return nil, paramGeometry{}, fmt.Errorf("%s: row table overruns the entry", layout.Entry)
	}
	geometry.stringsOffset = int(binary.LittleEndian.Uint32(data[0:4]))
	typeOffset64 := binary.LittleEndian.Uint64(data[0x10:0x18])
	dataStart64 := binary.LittleEndian.Uint64(data[0x30:0x38])
	if typeOffset64 > uint64(len(data)) || dataStart64 > uint64(len(data)) {
		return nil, paramGeometry{}, fmt.Errorf("%s: PARAM header pointer is out of bounds", layout.Entry)
	}
	geometry.typeOffset, geometry.dataStart = int(typeOffset64), int(dataStart64)
	if geometry.stringsOffset != geometry.typeOffset || geometry.dataStart < geometry.tableEnd ||
		geometry.stringsOffset < geometry.dataStart || geometry.stringsOffset > len(data) {
		return nil, paramGeometry{}, fmt.Errorf("%s: unsupported PARAM layout (table ends %#x, bodies %#x, strings %#x, type %#x): %w",
			layout.Entry, geometry.tableEnd, geometry.dataStart, geometry.stringsOffset, geometry.typeOffset, ErrUnsupportedRegulation)
	}
	if geometry.stringsOffset-geometry.dataStart != len(rows)*layout.RowSize {
		return nil, paramGeometry{}, fmt.Errorf("%s: body region is %d bytes, want %d rows of %d: %w",
			layout.Entry, geometry.stringsOffset-geometry.dataStart, len(rows), layout.RowSize, ErrUnsupportedRegulation)
	}
	// A rebuild keeps bodies in header order: a mid-table header whose body
	// was merely appended is not something the game is obliged to accept.
	for index, row := range rows {
		if want := geometry.dataStart + index*layout.RowSize; row.DataOffset != want {
			return nil, paramGeometry{}, fmt.Errorf("%s: row %d body is at %#x, not the header-order position %#x: %w",
				layout.Entry, row.ID, row.DataOffset, want, ErrUnsupportedRegulation)
		}
	}
	return header, geometry, nil
}

// plannedRow is one row header in the order the rebuilt table will carry.
type plannedRow struct {
	id         int32
	bodyOffset int
	// originalIndex is the row's position in the table being rebuilt, or -1
	// for an inserted row.
	originalIndex int
}

// serialiseTable writes one PARAM holding exactly the planned rows, in order.
// Insertion and removal share it: the row count changes, the row table and
// body regions change by whole rows, the string region moves by their sum, and
// every body and name pointer follows.
func serialiseTable(table *Table, header *ParamHeader, geometry paramGeometry, planned []plannedRow) ([]byte, error) {
	data, layout := table.Data, table.Layout
	if len(planned) == 0 {
		return nil, fmt.Errorf("%s: a rebuilt table may not be empty", layout.Entry)
	}
	if len(planned) > maxParamRowCount {
		return nil, fmt.Errorf("%s: %d rows overflows the 16-bit row count", layout.Entry, len(planned))
	}
	rowSize := layout.RowSize
	tableDelta := (len(planned) - len(table.Rows)) * rowHeaderSize
	bodyDelta := (len(planned) - len(table.Rows)) * rowSize
	newTableEnd := geometry.tableEnd + tableDelta
	newDataStart := geometry.dataStart + tableDelta
	newStringsOffset := geometry.stringsOffset + tableDelta + bodyDelta

	result := make([]byte, len(data)+tableDelta+bodyDelta)
	copy(result[:header.RowTableOffset], data[:header.RowTableOffset])
	// Whatever sits between the row table and the first body (padding, on
	// every table measured) is carried across rather than assumed empty.
	copy(result[newTableEnd:newDataStart], data[geometry.tableEnd:geometry.dataStart])
	copy(result[newStringsOffset:], data[geometry.stringsOffset:])

	binary.LittleEndian.PutUint16(result[10:12], uint16(len(planned)))
	binary.LittleEndian.PutUint32(result[0:4], uint32(newStringsOffset))
	binary.LittleEndian.PutUint64(result[0x10:0x18], uint64(geometry.typeOffset+tableDelta+bodyDelta))
	binary.LittleEndian.PutUint64(result[0x30:0x38], uint64(newDataStart))

	for index, row := range planned {
		base := header.RowTableOffset + index*rowHeaderSize
		body := newDataStart + index*rowSize
		if row.originalIndex >= 0 {
			// Copy the whole original header so unmodelled fields survive,
			// then correct the two pointers that moved.
			oldBase := header.RowTableOffset + row.originalIndex*rowHeaderSize
			copy(result[base:base+rowHeaderSize], data[oldBase:oldBase+rowHeaderSize])
			if nameOffset := binary.LittleEndian.Uint64(data[oldBase+16 : oldBase+24]); nameOffset != 0 {
				if nameOffset < uint64(geometry.stringsOffset) {
					return nil, fmt.Errorf("%s: row %d name precedes the string region: %w",
						layout.Entry, row.id, ErrUnsupportedRegulation)
				}
				binary.LittleEndian.PutUint64(result[base+16:base+24], uint64(int(nameOffset)+tableDelta+bodyDelta))
			}
		} else {
			binary.LittleEndian.PutUint32(result[base:base+4], uint32(row.id))
		}
		binary.LittleEndian.PutUint64(result[base+8:base+16], uint64(body))
		copy(result[body:body+rowSize], data[row.bodyOffset:row.bodyOffset+rowSize])
	}
	return result, nil
}

func rebuildTableWithRows(table *Table, insertions []RowInsertion) ([]byte, error) {
	layout, rows := table.Layout, table.Rows
	header, geometry, err := readParamGeometry(table)
	if err != nil {
		return nil, err
	}
	if len(rows)+len(insertions) > maxParamRowCount {
		return nil, fmt.Errorf("%s: %d rows plus %d insertions overflows the 16-bit row count",
			layout.Entry, len(rows), len(insertions))
	}

	maxID := rows[0].ID
	for _, row := range rows {
		if row.ID > maxID {
			maxID = row.ID
		}
	}
	allocated := make(map[int32]bool, len(insertions))
	for _, insertion := range insertions {
		if _, exists := table.ByID[insertion.RowID]; exists {
			return nil, fmt.Errorf("%s: row %d already exists; insertion adds a row, it never repurposes one",
				layout.Entry, insertion.RowID)
		}
		if allocated[insertion.RowID] {
			return nil, fmt.Errorf("%s: row %d is inserted twice", layout.Entry, insertion.RowID)
		}
		if _, exists := table.ByID[insertion.CopyFrom]; !exists {
			return nil, fmt.Errorf("%s: copy source row %d does not exist", layout.Entry, insertion.CopyFrom)
		}
		if insertion.InsertAfter == nil && insertion.RowID <= maxID {
			return nil, fmt.Errorf("%s: row %d is not above the existing maximum %d and names no anchor; an unanchored insertion may only append",
				layout.Entry, insertion.RowID, maxID)
		}
		allocated[insertion.RowID] = true
		if insertion.RowID > maxID {
			maxID = insertion.RowID
		}
	}

	planned := make([]plannedRow, 0, len(rows)+len(insertions))
	for index, row := range rows {
		planned = append(planned, plannedRow{id: row.ID, bodyOffset: row.DataOffset, originalIndex: index})
	}
	for _, insertion := range insertions {
		added := plannedRow{id: insertion.RowID, bodyOffset: table.ByID[insertion.CopyFrom].DataOffset, originalIndex: -1}
		if insertion.InsertAfter == nil {
			planned = append(planned, added)
			continue
		}
		anchor, anchors := -1, 0
		for index, candidate := range planned {
			if candidate.id == *insertion.InsertAfter {
				anchor, anchors = index, anchors+1
			}
		}
		if anchors != 1 {
			return nil, fmt.Errorf("%s: anchor row %d occurs %d times; exactly one is required",
				layout.Entry, *insertion.InsertAfter, anchors)
		}
		planned = append(planned, plannedRow{})
		copy(planned[anchor+2:], planned[anchor+1:])
		planned[anchor+1] = added
	}
	return serialiseTable(table, header, geometry, planned)
}

func rebuildTableWithoutRows(table *Table, removals []int32) ([]byte, error) {
	layout := table.Layout
	header, geometry, err := readParamGeometry(table)
	if err != nil {
		return nil, err
	}
	doomed := make(map[int32]bool, len(removals))
	for _, rowID := range removals {
		if _, exists := table.ByID[rowID]; !exists {
			return nil, fmt.Errorf("%s: row %d does not exist, so removing it would be removing something else",
				layout.Entry, rowID)
		}
		if doomed[rowID] {
			return nil, fmt.Errorf("%s: row %d is removed twice", layout.Entry, rowID)
		}
		doomed[rowID] = true
	}
	planned := make([]plannedRow, 0, len(table.Rows)-len(doomed))
	for index, row := range table.Rows {
		if !doomed[row.ID] {
			planned = append(planned, plannedRow{id: row.ID, bodyOffset: row.DataOffset, originalIndex: index})
		}
	}
	return serialiseTable(table, header, geometry, planned)
}

// reopenInHeaderOrder reopens a rebuilt table and checks its bodies are still
// in header order. It returns each row's position.
func reopenInHeaderOrder(bnd4 []byte, layout TableLayout, operation string) (*Table, map[int32]int, error) {
	table, err := OpenTable(bnd4, layout)
	if err != nil {
		return nil, nil, fmt.Errorf("reopening %s after %s: %w", layout.Entry, operation, err)
	}
	dataStart := int(binary.LittleEndian.Uint64(table.Data[0x30:0x38]))
	positions := make(map[int32]int, len(table.Rows))
	for position, row := range table.Rows {
		if want := dataStart + position*layout.RowSize; row.DataOffset != want {
			return nil, nil, fmt.Errorf("%s row %d body is at %#x, not the header-order position %#x",
				layout.Entry, row.ID, row.DataOffset, want)
		}
		positions[row.ID] = position
	}
	return table, positions, nil
}

// verifyRowInsertion: no original row changed or vanished, nothing undeclared
// appeared, and each new row is a faithful copy placed where it was asked for.
func verifyRowInsertion(bnd4 []byte, layout TableLayout, shipped map[int32][32]byte, insertions []RowInsertion) error {
	table, positions, err := reopenInHeaderOrder(bnd4, layout, "insertion")
	if err != nil {
		return err
	}
	if len(table.Rows) != len(shipped)+len(insertions) {
		return fmt.Errorf("%s holds %d rows after inserting %d into %d",
			layout.Entry, len(table.Rows), len(insertions), len(shipped))
	}
	digests := rowDigests(table)
	for id, digest := range shipped {
		if _, present := table.ByID[id]; !present {
			return fmt.Errorf("%s row %d disappeared during insertion", layout.Entry, id)
		}
		if digests[id] != digest {
			return fmt.Errorf("%s row %d changed during insertion", layout.Entry, id)
		}
	}
	declared := make(map[int32]bool, len(insertions))
	for _, insertion := range insertions {
		declared[insertion.RowID] = true
	}
	for id := range table.ByID {
		if _, existed := shipped[id]; !existed && !declared[id] {
			return fmt.Errorf("%s row %d appeared but was never declared", layout.Entry, id)
		}
	}
	for _, insertion := range insertions {
		if _, present := table.ByID[insertion.RowID]; !present {
			return fmt.Errorf("%s inserted row %d is absent after reopen", layout.Entry, insertion.RowID)
		}
		if digests[insertion.RowID] != shipped[insertion.CopyFrom] {
			return fmt.Errorf("%s inserted row %d is not a copy of row %d", layout.Entry, insertion.RowID, insertion.CopyFrom)
		}
		if insertion.InsertAfter == nil {
			continue
		}
		position := positions[insertion.RowID]
		if position == 0 || table.Rows[position-1].ID != *insertion.InsertAfter {
			return fmt.Errorf("%s inserted row %d is not physically after row %d",
				layout.Entry, insertion.RowID, *insertion.InsertAfter)
		}
	}
	return nil
}

// verifyRowRemoval: every row not named survived byte-identically, every row
// named is gone, and nothing appeared.
func verifyRowRemoval(bnd4 []byte, layout TableLayout, shipped map[int32][32]byte, removals []int32) error {
	table, _, err := reopenInHeaderOrder(bnd4, layout, "removal")
	if err != nil {
		return err
	}
	if len(table.Rows) != len(shipped)-len(removals) {
		return fmt.Errorf("%s holds %d rows after removing %d from %d",
			layout.Entry, len(table.Rows), len(removals), len(shipped))
	}
	removed := make(map[int32]bool, len(removals))
	for _, rowID := range removals {
		if _, present := table.ByID[rowID]; present {
			return fmt.Errorf("%s row %d was declared for removal but is still there", layout.Entry, rowID)
		}
		removed[rowID] = true
	}
	digests := rowDigests(table)
	for id, digest := range shipped {
		if removed[id] {
			continue
		}
		if _, present := table.ByID[id]; !present {
			return fmt.Errorf("%s row %d disappeared during removal but was never declared", layout.Entry, id)
		}
		if digests[id] != digest {
			return fmt.Errorf("%s row %d changed during removal", layout.Entry, id)
		}
	}
	for id := range table.ByID {
		if _, existed := shipped[id]; !existed {
			return fmt.Errorf("%s row %d appeared during a removal", layout.Entry, id)
		}
	}
	return nil
}

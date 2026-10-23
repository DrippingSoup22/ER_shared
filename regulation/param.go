package regulation

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
)

// ParamHeader holds the PARAM properties needed to find and check rows.
type ParamHeader struct {
	RowCount       int
	DataVersion    int16
	LongDataOffset bool
	RowTableOffset int
	ParamType      string
}

// ParamRow is one row: its ID and where its data starts within the PARAM.
type ParamRow struct {
	ID         int32
	DataOffset int
}

// LoadParamRows parses the row table of one named PARAM in a BND4.
func LoadParamRows(bnd4 []byte, entryName string) (BND4Entry, []byte, *ParamHeader, []ParamRow, error) {
	return loadParamRows(bnd4, entryName, false)
}

// LoadRowsByID loads one PARAM and indexes its rows by ID. A non-empty
// paramType is asserted together with dataVersion: decoding against the wrong
// definition is silent, so the check belongs here rather than at each caller.
func LoadRowsByID(bnd4 []byte, entryName, paramType string, dataVersion int16) ([]byte, map[int32]ParamRow, error) {
	_, data, header, rows, err := LoadParamRows(bnd4, entryName)
	if err != nil {
		return nil, nil, err
	}
	if paramType != "" && (header.ParamType != paramType || header.DataVersion != dataVersion) {
		return nil, nil, fmt.Errorf("unsupported %s schema %q/%d, expected %q/%d: %w",
			entryName, header.ParamType, header.DataVersion, paramType, dataVersion, ErrUnsupportedRegulation)
	}
	byID := make(map[int32]ParamRow, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	return data, byID, nil
}

func loadParamRows(bnd4 []byte, entryName string, allowDuplicateIDs bool) (BND4Entry, []byte, *ParamHeader, []ParamRow, error) {
	entry, err := FindBND4Entry(bnd4, entryName)
	if err != nil {
		return BND4Entry{}, nil, nil, nil, err
	}
	data := bnd4[entry.Offset : entry.Offset+entry.Size]
	header, err := parseParamHeader(data)
	if err != nil {
		return BND4Entry{}, nil, nil, nil, fmt.Errorf("%s: %w", entryName, err)
	}
	rows, err := parseParamRows(data, header, allowDuplicateIDs)
	if err != nil {
		return BND4Entry{}, nil, nil, nil, fmt.Errorf("%s: %w", entryName, err)
	}
	return entry, data, header, rows, nil
}

func parseParamHeader(blob []byte) (*ParamHeader, error) {
	if len(blob) < 0x40 {
		return nil, fmt.Errorf("PARAM is too small (%d bytes)", len(blob))
	}
	format := blob[0x2D]
	longOffset := format&0x04 != 0
	expandedOffset := format&0x01 != 0 && format&0x02 != 0
	rowCount := int(binary.LittleEndian.Uint16(blob[10:12]))
	position := 12
	var paramType string
	if format&0x80 != 0 {
		if position+12 > len(blob) {
			return nil, fmt.Errorf("truncated PARAM type offset")
		}
		position += 4
		typeOffset := binary.LittleEndian.Uint64(blob[position : position+8])
		position += 8 + 0x14
		if typeOffset > uint64(len(blob)) {
			return nil, fmt.Errorf("PARAM type offset is out of bounds")
		}
		if typeOffset != 0 {
			paramType = readASCIICString(blob, int(typeOffset))
		}
	} else {
		if position+0x20 > len(blob) {
			return nil, fmt.Errorf("truncated PARAM type")
		}
		raw := blob[position : position+0x20]
		if zero := bytes.IndexByte(raw, 0); zero >= 0 {
			raw = raw[:zero]
		}
		paramType = string(raw)
		position += 0x20
	}
	position += 4
	if expandedOffset || longOffset {
		position += 16
	}
	if position < 0 || position > len(blob) {
		return nil, fmt.Errorf("PARAM row table offset is out of bounds")
	}
	return &ParamHeader{
		RowCount: rowCount, DataVersion: int16(binary.LittleEndian.Uint16(blob[8:10])),
		LongDataOffset: longOffset, RowTableOffset: position, ParamType: paramType,
	}, nil
}

func parseParamRows(blob []byte, header *ParamHeader, allowDuplicateIDs bool) ([]ParamRow, error) {
	entrySize := 12
	if header.LongDataOffset {
		entrySize = 24
	}
	if header.RowCount < 0 || header.RowTableOffset > len(blob)-header.RowCount*entrySize {
		return nil, fmt.Errorf("PARAM row table is out of bounds")
	}
	rows := make([]ParamRow, 0, header.RowCount)
	seen := make(map[int32]bool, header.RowCount)
	for index := 0; index < header.RowCount; index++ {
		base := header.RowTableOffset + index*entrySize
		id := int32(binary.LittleEndian.Uint32(blob[base : base+4]))
		if seen[id] && !allowDuplicateIDs {
			return nil, fmt.Errorf("duplicate PARAM row ID %d", id)
		}
		seen[id] = true
		var dataOffset uint64
		if header.LongDataOffset {
			dataOffset = binary.LittleEndian.Uint64(blob[base+8 : base+16])
		} else {
			dataOffset = uint64(binary.LittleEndian.Uint32(blob[base+4 : base+8]))
		}
		if dataOffset > uint64(len(blob)) {
			return nil, fmt.Errorf("row %d data offset is out of bounds", id)
		}
		rows = append(rows, ParamRow{ID: id, DataOffset: int(dataOffset)})
	}
	return rows, nil
}

func readASCIICString(blob []byte, offset int) string {
	end := offset
	for end < len(blob) && blob[end] != 0 {
		end++
	}
	return string(blob[offset:end])
}

// UniformRowSize derives the row stride from consecutive row offsets and
// rejects a table whose rows are not evenly spaced.
func UniformRowSize(data []byte, rows []ParamRow) (int, error) {
	if len(rows) < 2 {
		return 0, fmt.Errorf("%d rows; a stride needs at least two", len(rows))
	}
	ordered := append([]ParamRow(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].DataOffset < ordered[j].DataOffset })
	size := ordered[1].DataOffset - ordered[0].DataOffset
	if size <= 0 {
		return 0, fmt.Errorf("non-positive row stride %d", size)
	}
	for index := 1; index+1 < len(ordered); index++ {
		if ordered[index+1].DataOffset-ordered[index].DataOffset != size {
			return 0, fmt.Errorf("row stride is not uniform at row %d", ordered[index].ID)
		}
	}
	if last := ordered[len(ordered)-1].DataOffset; last+size > len(data) {
		return 0, fmt.Errorf("final row overruns the entry")
	}
	return size, nil
}

// RequireRowSize checks that a row holds at least size bytes.
func RequireRowSize(data []byte, row ParamRow, size int, label string) error {
	if row.DataOffset < 0 || row.DataOffset > len(data)-size {
		return fmt.Errorf("%s row %d is shorter than the validated %d-byte layout", label, row.ID, size)
	}
	return nil
}

func ReadS32(data []byte, offset int) int32 {
	return int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
}

func WriteS32(data []byte, offset int, value int32) {
	binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(value))
}

func ReadF32(data []byte, offset int) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data[offset : offset+4]))
}

func ReadS32Range(data []byte, offset, count int) []int32 {
	result := make([]int32, count)
	for index := range result {
		result[index] = ReadS32(data, offset+index*4)
	}
	return result
}

func Sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func FileSha256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Sha256Hex(data), nil
}

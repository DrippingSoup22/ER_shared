package regulation

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Paramdex schema machinery: it walks a pinned PARAMDEF, lays out field
// offsets, binds a schema to an embedded PARAM, and decodes rows by name.
//
// Paramdex remains external: this project parses the pinned schema but does not
// redistribute its data.

type paramdexXML struct {
	ParamType   string             `xml:"ParamType"`
	DataVersion int16              `xml:"DataVersion"`
	Fields      []paramdexFieldXML `xml:"Fields>Field"`
}

type paramdexFieldXML struct {
	Def            string `xml:"Def,attr"`
	FirstVersion   uint32 `xml:"FirstVersion,attr"`
	RemovedVersion uint32 `xml:"RemovedVersion,attr"`
}

type ParamField struct {
	Name         string
	Type         string
	Offset       int
	Size         int
	ArrayLength  int
	BitOffset    int
	BitSize      int
	DefaultValue string
}

type ParamSchema struct {
	ParamType   string
	DataVersion int16
	RowSize     int
	Fields      []ParamField
}

type ParamTable struct {
	Entry     BND4Entry
	Data      []byte
	Header    *ParamHeader
	Rows      []ParamRow
	Schema    *ParamSchema
	Names     map[int32]string
	TableName string
}

type DecodedField struct {
	Field  string `json:"field"`
	Offset int    `json:"offset"`
	Type   string `json:"type"`
	Value  any    `json:"value"`
}

type DecodedRow struct {
	Param  string         `json:"param"`
	RowID  int32          `json:"row_id"`
	Name   string         `json:"name,omitempty"`
	Fields []DecodedField `json:"fields"`
}

// LoadParamdexSchema loads a schema from the externally pinned checkout;
// Paramdex data is never copied into this repository.
func LoadParamdexSchema(root, game, tableName string, version uint32) (*ParamSchema, error) {
	if err := VerifyParamdexRevision(root); err != nil {
		return nil, err
	}
	if !SafeParamName.MatchString(tableName) || (game != "ER" && game != "NR") {
		return nil, fmt.Errorf("invalid Paramdex schema %q/%q", game, tableName)
	}
	path := filepath.Join(root, game, "Defs", tableName+".xml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s Paramdex schema %s: %w", game, tableName, err)
	}
	var definition paramdexXML
	if err := xml.Unmarshal(data, &definition); err != nil {
		return nil, fmt.Errorf("parse %s Paramdex schema %s: %w", game, tableName, err)
	}
	fields, rowSize, err := layoutParamFields(definition.Fields, version)
	if err != nil {
		return nil, fmt.Errorf("layout %s Paramdex schema %s: %w", game, tableName, err)
	}
	return &ParamSchema{ParamType: definition.ParamType, DataVersion: definition.DataVersion, RowSize: rowSize, Fields: fields}, nil
}

func layoutParamFields(definitions []paramdexFieldXML, version uint32) ([]ParamField, int, error) {
	fields := make([]ParamField, 0, len(definitions))
	offset := 0
	bitType := ""
	bitOffset := 0
	bitUnitSize := 0
	flushBits := func() {
		if bitType != "" {
			offset += bitUnitSize
			bitType = ""
			bitOffset = 0
			bitUnitSize = 0
		}
	}
	for _, definition := range definitions {
		if definition.FirstVersion != 0 && version < definition.FirstVersion {
			continue
		}
		if definition.RemovedVersion != 0 && version >= definition.RemovedVersion {
			continue
		}
		field, err := parseParamFieldDef(definition.Def)
		if err != nil {
			return nil, 0, err
		}
		unitSize, err := paramTypeSize(field.Type, field.ArrayLength)
		if err != nil {
			return nil, 0, err
		}
		field.Size = unitSize
		if field.BitSize > 0 {
			baseSize, err := paramTypeSize(field.Type, 1)
			if err != nil {
				return nil, 0, err
			}
			capacity := baseSize * 8
			if field.BitSize > capacity {
				return nil, 0, fmt.Errorf("field %s uses %d bits in %s", field.Name, field.BitSize, field.Type)
			}
			storageType := strconv.Itoa(baseSize)
			if bitType != storageType || bitOffset+field.BitSize > capacity {
				flushBits()
				bitType = storageType
				bitUnitSize = baseSize
			}
			field.Offset = offset
			field.BitOffset = bitOffset
			bitOffset += field.BitSize
			fields = append(fields, field)
			if bitOffset == capacity {
				flushBits()
			}
			continue
		}
		flushBits()
		field.Offset = offset
		fields = append(fields, field)
		offset += unitSize
	}
	flushBits()
	return fields, offset, nil
}

func parseParamFieldDef(definition string) (ParamField, error) {
	parts := strings.SplitN(definition, "=", 2)
	left := strings.TrimSpace(parts[0])
	defaultValue := "0"
	if len(parts) == 2 {
		defaultValue = strings.TrimSpace(parts[1])
	}
	tokens := strings.Fields(left)
	if len(tokens) != 2 {
		return ParamField{}, fmt.Errorf("unsupported field definition %q", definition)
	}
	field := ParamField{Type: tokens[0], ArrayLength: 1, DefaultValue: defaultValue}
	name := tokens[1]
	if open := strings.IndexByte(name, '['); open >= 0 {
		if !strings.HasSuffix(name, "]") {
			return ParamField{}, fmt.Errorf("malformed array field %q", definition)
		}
		count, err := strconv.Atoi(name[open+1 : len(name)-1])
		if err != nil || count <= 0 {
			return ParamField{}, fmt.Errorf("invalid array length in %q", definition)
		}
		field.ArrayLength = count
		name = name[:open]
	}
	if colon := strings.IndexByte(name, ':'); colon >= 0 {
		bits, err := strconv.Atoi(name[colon+1:])
		if err != nil || bits <= 0 {
			return ParamField{}, fmt.Errorf("invalid bit width in %q", definition)
		}
		field.BitSize = bits
		name = name[:colon]
	}
	field.Name = name
	return field, nil
}

func paramTypeSize(kind string, count int) (int, error) {
	if count <= 0 {
		return 0, fmt.Errorf("invalid field array length %d", count)
	}
	switch kind {
	case "s8", "u8", "dummy8", "fixstr":
		return count, nil
	case "s16", "u16", "fixstrW":
		return 2 * count, nil
	case "s32", "u32", "f32":
		return 4 * count, nil
	default:
		return 0, fmt.Errorf("unsupported Paramdex field type %q", kind)
	}
}

// LoadParamdexTable decodes an existing regulation table with an external
// schema. entryTableName may differ from schemaTableName for map-specific
// tables such as MapMimicryEstablishmentParam_m61.
func LoadParamdexTable(regulation *Regulation, root, game, entryTableName, schemaTableName string, allowDuplicateIDs bool) (*ParamTable, error) {
	entryName := entryTableName
	if !strings.HasSuffix(strings.ToLower(entryName), ".param") {
		entryName += ".param"
	}
	_, data, header, rows, err := loadParamRows(regulation.BND4, entryName, allowDuplicateIDs)
	if err != nil {
		return nil, err
	}
	baseName := strings.TrimSuffix(filepath.Base(strings.ReplaceAll(entryName, "\\", "/")), ".param")
	schema, err := LoadParamdexSchema(root, game, schemaTableName, regulation.Version)
	if err != nil {
		return nil, err
	}
	if header.ParamType != schema.ParamType || header.DataVersion != schema.DataVersion {
		return nil, fmt.Errorf("%s type/version is %q/%d, Paramdex declares %q/%d", entryName, header.ParamType, header.DataVersion, schema.ParamType, schema.DataVersion)
	}
	for index, row := range rows {
		if row.DataOffset < 0 || row.DataOffset > len(data)-schema.RowSize {
			return nil, fmt.Errorf("%s row %d cannot hold the %d-byte Paramdex schema", entryName, row.ID, schema.RowSize)
		}
		if index+1 < len(rows) && rows[index+1].DataOffset-row.DataOffset != schema.RowSize {
			return nil, fmt.Errorf("%s row %d span is %d bytes, Paramdex schema is %d", entryName, row.ID, rows[index+1].DataOffset-row.DataOffset, schema.RowSize)
		}
	}
	names, err := LoadParamdexNamesOptional(root, game, baseName)
	if err != nil && !os.IsNotExist(rootCause(err)) {
		return nil, err
	}
	entry, err := FindBND4Entry(regulation.BND4, entryName)
	if err != nil {
		return nil, err
	}
	return &ParamTable{Entry: entry, Data: data, Header: header, Rows: rows, Schema: schema, Names: names, TableName: baseName}, nil
}

func rootCause(err error) error {
	for {
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok || unwrapped.Unwrap() == nil {
			return err
		}
		err = unwrapped.Unwrap()
	}
}

func LoadParamdexNamesOptional(root, game, tableName string) (map[int32]string, error) {
	path := filepath.Join(root, game, "Names", tableName+".txt")
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s Paramdex names %s: %w", game, tableName, err)
	}
	defer file.Close()
	names := make(map[int32]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		id, err := strconv.ParseInt(parts[0], 10, 32)
		if err != nil {
			// A few name files contain wrapped prose continuation lines.
			// Names are optional labels, so ignore those lines.
			continue
		}
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			names[int32(id)] = strings.TrimSpace(parts[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s Paramdex names %s: %w", game, tableName, err)
	}
	return names, nil
}

func (table *ParamTable) Row(id int32, fieldPattern *regexp.Regexp, nonDefaultOnly bool) (DecodedRow, error) {
	index := -1
	for candidateIndex, candidate := range table.Rows {
		if candidate.ID != id {
			continue
		}
		if index >= 0 {
			return DecodedRow{}, fmt.Errorf("row ID %d is duplicated in %s; select it by table position before interpreting it", id, table.TableName)
		}
		index = candidateIndex
	}
	if index < 0 {
		return DecodedRow{}, fmt.Errorf("row %d is absent from %s", id, table.TableName)
	}
	return table.DecodeRow(table.Rows[index], fieldPattern, nonDefaultOnly)
}

func (table *ParamTable) DecodeRow(row ParamRow, fieldPattern *regexp.Regexp, nonDefaultOnly bool) (DecodedRow, error) {
	blob := table.Data[row.DataOffset : row.DataOffset+table.Schema.RowSize]
	result := DecodedRow{Param: table.TableName, RowID: row.ID, Name: table.Names[row.ID]}
	for _, field := range table.Schema.Fields {
		if fieldPattern != nil && !fieldPattern.MatchString(field.Name) {
			continue
		}
		if field.Type == "dummy8" {
			continue
		}
		value, err := DecodeParamField(blob, field)
		if err != nil {
			return DecodedRow{}, fmt.Errorf("%s row %d field %s: %w", table.TableName, row.ID, field.Name, err)
		}
		if nonDefaultOnly && paramValueIsDefault(value, field) {
			continue
		}
		result.Fields = append(result.Fields, DecodedField{Field: field.Name, Offset: field.Offset, Type: field.Type, Value: value})
	}
	return result, nil
}

func DecodeParamField(blob []byte, field ParamField) (any, error) {
	if field.Offset < 0 || field.Size < 0 || field.Offset > len(blob)-field.Size {
		return nil, fmt.Errorf("field range is out of bounds")
	}
	if field.BitSize > 0 {
		var raw uint64
		switch field.Size {
		case 1:
			raw = uint64(blob[field.Offset])
		case 2:
			raw = uint64(binary.LittleEndian.Uint16(blob[field.Offset:]))
		case 4:
			raw = uint64(binary.LittleEndian.Uint32(blob[field.Offset:]))
		default:
			return nil, fmt.Errorf("unsupported bitfield unit size %d", field.Size)
		}
		mask := uint64(1<<field.BitSize) - 1
		return (raw >> field.BitOffset) & mask, nil
	}
	if field.ArrayLength > 1 || field.Type == "fixstr" || field.Type == "fixstrW" {
		raw := blob[field.Offset : field.Offset+field.Size]
		if field.Type == "fixstr" {
			return strings.TrimRight(string(raw), "\x00"), nil
		}
		if field.Type == "fixstrW" {
			units := make([]uint16, 0, field.ArrayLength)
			for offset := 0; offset < len(raw); offset += 2 {
				unit := binary.LittleEndian.Uint16(raw[offset:])
				if unit == 0 {
					break
				}
				units = append(units, unit)
			}
			return string(utf16.Decode(units)), nil
		}
		return hex.EncodeToString(raw), nil
	}
	switch field.Type {
	case "s8":
		return int8(blob[field.Offset]), nil
	case "u8":
		return blob[field.Offset], nil
	case "s16":
		return int16(binary.LittleEndian.Uint16(blob[field.Offset:])), nil
	case "u16":
		return binary.LittleEndian.Uint16(blob[field.Offset:]), nil
	case "s32":
		return int32(binary.LittleEndian.Uint32(blob[field.Offset:])), nil
	case "u32":
		return binary.LittleEndian.Uint32(blob[field.Offset:]), nil
	case "f32":
		return math.Float32frombits(binary.LittleEndian.Uint32(blob[field.Offset:])), nil
	default:
		return nil, fmt.Errorf("unsupported field type %q", field.Type)
	}
}

// EncodeParamField writes value into a scalar or bit field of a row in place:
// the counterpart of DecodeParamField. It refuses a value the field cannot
// hold exactly (an integer out of range or with a fraction, a non-finite or
// out-of-range float) and arrays and strings, so a row is never written with
// a silently truncated value.
func EncodeParamField(blob []byte, field ParamField, value float64) error {
	if field.Offset < 0 || field.Size <= 0 || field.Offset > len(blob)-field.Size {
		return fmt.Errorf("field %s range is out of bounds", field.Name)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("field %s: value must be finite", field.Name)
	}
	whole := value == math.Trunc(value)
	if field.BitSize > 0 {
		limit := float64(uint64(1)<<field.BitSize - 1)
		if !whole || value < 0 || value > limit {
			return fmt.Errorf("field %s: %g is not an integer between 0 and %g", field.Name, value, limit)
		}
		var raw uint64
		switch field.Size {
		case 1:
			raw = uint64(blob[field.Offset])
		case 2:
			raw = uint64(binary.LittleEndian.Uint16(blob[field.Offset:]))
		case 4:
			raw = uint64(binary.LittleEndian.Uint32(blob[field.Offset:]))
		default:
			return fmt.Errorf("field %s: unsupported bitfield unit size %d", field.Name, field.Size)
		}
		mask := (uint64(1)<<field.BitSize - 1) << field.BitOffset
		raw = raw&^mask | uint64(value)<<field.BitOffset
		switch field.Size {
		case 1:
			blob[field.Offset] = byte(raw)
		case 2:
			binary.LittleEndian.PutUint16(blob[field.Offset:], uint16(raw))
		case 4:
			binary.LittleEndian.PutUint32(blob[field.Offset:], uint32(raw))
		}
		return nil
	}
	if field.ArrayLength > 1 {
		return fmt.Errorf("field %s: arrays are not written by value", field.Name)
	}
	ranges := map[string][2]float64{
		"s8": {math.MinInt8, math.MaxInt8}, "u8": {0, math.MaxUint8},
		"s16": {math.MinInt16, math.MaxInt16}, "u16": {0, math.MaxUint16},
		"s32": {math.MinInt32, math.MaxInt32}, "u32": {0, math.MaxUint32},
	}
	if field.Type == "f32" {
		if math.Abs(value) > math.MaxFloat32 {
			return fmt.Errorf("field %s: %g is outside float32 range", field.Name, value)
		}
		binary.LittleEndian.PutUint32(blob[field.Offset:], math.Float32bits(float32(value)))
		return nil
	}
	bounds, ok := ranges[field.Type]
	if !ok {
		return fmt.Errorf("field %s: unsupported field type %q", field.Name, field.Type)
	}
	if !whole || value < bounds[0] || value > bounds[1] {
		return fmt.Errorf("field %s: %g is not a %s", field.Name, value, field.Type)
	}
	switch field.Size {
	case 1:
		blob[field.Offset] = byte(int64(value))
	case 2:
		binary.LittleEndian.PutUint16(blob[field.Offset:], uint16(int64(value)))
	case 4:
		binary.LittleEndian.PutUint32(blob[field.Offset:], uint32(int64(value)))
	}
	return nil
}

func paramValueIsDefault(value any, field ParamField) bool {
	if field.ArrayLength > 1 || field.Type == "fixstr" || field.Type == "fixstrW" {
		return value == "" || value == strings.Repeat("00", field.Size)
	}
	if field.Type == "f32" {
		want, err := strconv.ParseFloat(field.DefaultValue, 32)
		got, ok := value.(float32)
		return err == nil && ok && got == float32(want)
	}
	want, err := strconv.ParseInt(field.DefaultValue, 0, 64)
	if err != nil {
		return false
	}
	got, ok := ParamInteger(value)
	return ok && got == want
}

func ParamInteger(value any) (int64, bool) {
	switch value := value.(type) {
	case int8:
		return int64(value), true
	case uint8:
		return int64(value), true
	case int16:
		return int64(value), true
	case uint16:
		return int64(value), true
	case int32:
		return int64(value), true
	case uint32:
		return int64(value), true
	case uint64:
		if value <= math.MaxInt64 {
			return int64(value), true
		}
	}
	return 0, false
}

func CompileOptionalPattern(expression string) (*regexp.Regexp, error) {
	if strings.TrimSpace(expression) == "" {
		return nil, nil
	}
	pattern, err := regexp.Compile(expression)
	if err != nil {
		return nil, fmt.Errorf("invalid field regular expression: %w", err)
	}
	return pattern, nil
}

// SafeParamName matches a plain table basename, safe to join into a path.
var SafeParamName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// VerifyParamdexRevision checks that the Paramdex checkout at root is the
// pinned revision.
func VerifyParamdexRevision(root string) error {
	head, err := os.ReadFile(filepath.Join(root, ".git", "HEAD"))
	if err != nil {
		return fmt.Errorf("read Paramdex revision: %w", err)
	}
	revision := strings.TrimSpace(string(head))
	if strings.HasPrefix(revision, "ref: ") {
		ref := strings.TrimPrefix(revision, "ref: ")
		data, readErr := os.ReadFile(filepath.Join(root, ".git", filepath.FromSlash(ref)))
		if readErr == nil {
			revision = strings.TrimSpace(string(data))
		} else {
			packed, packedErr := os.ReadFile(filepath.Join(root, ".git", "packed-refs"))
			if packedErr != nil {
				return fmt.Errorf("resolve Paramdex revision %s", ref)
			}
			for _, line := range strings.Split(string(packed), "\n") {
				parts := strings.Fields(line)
				if len(parts) == 2 && parts[1] == ref {
					revision = parts[0]
					break
				}
			}
		}
	}
	if revision != PinnedParamdexRevision {
		return fmt.Errorf("Paramdex revision is %s, want pinned %s", revision, PinnedParamdexRevision)
	}
	return nil
}

const PinnedParamdexRevision = "ff7245e524329bc3eab00036723d2bd53384cedf"

package regulation

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

type ParamMetadata struct {
	Entry       string `json:"entry"`
	ParamType   string `json:"param_type"`
	DataVersion int16  `json:"data_version"`
	RowCount    int    `json:"row_count"`
	MinimumID   int32  `json:"minimum_id"`
	MaximumID   int32  `json:"maximum_id"`
}

// ParamRowList is a compact row-ID listing for any embedded PARAM. It answers
// "which rows exist in this ID range", which the schema-specific inspectors
// cannot: they all require a validated per-table layout first.
type ParamRowList struct {
	Entry       string   `json:"entry"`
	ParamType   string   `json:"param_type"`
	DataVersion int16    `json:"data_version"`
	RowCount    int      `json:"row_count"`
	Matched     int      `json:"matched"`
	RowStride   int      `json:"row_stride,omitempty"`
	RowIDs      []int32  `json:"row_ids"`
	Names       []string `json:"names,omitempty"`
	RowBytes    []string `json:"row_bytes,omitempty"`
}

// ListParamRows reports row IDs within an inclusive range without decoding any
// field, so it works on tables this project has no schema fixture for.
func ListParamRows(savePath, entry string, minID, maxID int32, limit int, names map[int32]string) (*ParamRowList, error) {
	return listParamRows(savePath, entry, minID, maxID, limit, names, false)
}

// ListParamRowBytes additionally returns each matched row as hex. Raw bytes are
// the only ground truth for a table whose pinned Paramdex definition is shorter
// than the stride the shipped regulation actually uses.
func ListParamRowBytes(savePath, entry string, minID, maxID int32, limit int, names map[int32]string) (*ParamRowList, error) {
	return listParamRows(savePath, entry, minID, maxID, limit, names, true)
}

func listParamRows(savePath, entry string, minID, maxID int32, limit int, names map[int32]string, withBytes bool) (*ParamRowList, error) {
	if minID > maxID {
		return nil, fmt.Errorf("min %d exceeds max %d", minID, maxID)
	}
	if limit < 0 {
		return nil, fmt.Errorf("limit must not be negative")
	}
	entryName, err := normalizeParamEntry(entry)
	if err != nil {
		return nil, err
	}
	regulation, err := Load(savePath)
	if err != nil {
		return nil, err
	}
	_, data, header, rows, err := LoadParamRows(regulation.BND4, entryName)
	if err != nil {
		return nil, err
	}
	result := &ParamRowList{
		Entry: entryName, ParamType: header.ParamType, DataVersion: header.DataVersion,
		RowCount: len(rows), RowIDs: []int32{},
	}
	var stride int
	if withBytes {
		stride, err = UniformRowSize(data, rows)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entryName, err)
		}
		result.RowStride = stride
	}
	for _, row := range rows {
		if row.ID < minID || row.ID > maxID {
			continue
		}
		result.Matched++
		if limit != 0 && len(result.RowIDs) >= limit {
			continue
		}
		result.RowIDs = append(result.RowIDs, row.ID)
		if names != nil {
			result.Names = append(result.Names, names[row.ID])
		}
		if withBytes {
			result.RowBytes = append(result.RowBytes, hex.EncodeToString(data[row.DataOffset:row.DataOffset+stride]))
		}
	}
	return result, nil
}

// normalizeParamEntry accepts a table name with or without the .param suffix
// and refuses anything that is not a plain basename.
func normalizeParamEntry(raw string) (string, error) {
	entry := strings.TrimSpace(raw)
	if entry == "" || filepath.Base(entry) != entry {
		return "", fmt.Errorf("PARAM entry must be a basename: %q", raw)
	}
	if !strings.HasSuffix(strings.ToLower(entry), ".param") {
		entry += ".param"
	}
	return entry, nil
}

func InspectParamMetadata(savePath string, entries []string) ([]ParamMetadata, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("no PARAM entries supplied")
	}
	regulation, err := Load(savePath)
	if err != nil {
		return nil, err
	}
	result := make([]ParamMetadata, 0, len(entries))
	for _, raw := range entries {
		entry, err := normalizeParamEntry(raw)
		if err != nil {
			return nil, err
		}
		_, _, header, rows, err := LoadParamRows(regulation.BND4, entry)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, fmt.Errorf("%s has no rows", entry)
		}
		minimum, maximum := rows[0].ID, rows[0].ID
		for _, row := range rows[1:] {
			if row.ID < minimum {
				minimum = row.ID
			}
			if row.ID > maximum {
				maximum = row.ID
			}
		}
		result = append(result, ParamMetadata{Entry: entry, ParamType: header.ParamType, DataVersion: header.DataVersion, RowCount: len(rows), MinimumID: minimum, MaximumID: maximum})
	}
	return result, nil
}

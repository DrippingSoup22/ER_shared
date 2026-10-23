package regulation

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	bnd4EntryTableOffset = 0x40
	bnd4EntryHeaderSize  = 0x24
)

// BND4Entry is one file inside a BND4 archive.
type BND4Entry struct {
	Name   string
	Offset int
	Size   int
}

// ListBND4Entries reads and bounds-checks every entry header, in archive order.
func ListBND4Entries(blob []byte) ([]BND4Entry, error) {
	if len(blob) < 0x10 || string(blob[:4]) != "BND4" {
		return nil, fmt.Errorf("not a BND4 archive")
	}
	count := int(binary.LittleEndian.Uint32(blob[0x0C:0x10]))
	entries := make([]BND4Entry, 0, count)
	for index := 0; index < count; index++ {
		base := bnd4EntryTableOffset + index*bnd4EntryHeaderSize
		if base < 0 || base+bnd4EntryHeaderSize > len(blob) {
			return nil, fmt.Errorf("BND4 entry %d is out of bounds", index)
		}
		size64 := binary.LittleEndian.Uint64(blob[base+8 : base+16])
		offset := int(binary.LittleEndian.Uint32(blob[base+24 : base+28]))
		nameOffset := int(binary.LittleEndian.Uint32(blob[base+32 : base+36]))
		name, err := readUTF16LECString(blob, nameOffset)
		if err != nil {
			return nil, err
		}
		if size64 > uint64(len(blob)) {
			return nil, fmt.Errorf("BND4 entry %q size is out of bounds", name)
		}
		size := int(size64)
		if offset < 0 || size < 0 || offset > len(blob)-size {
			return nil, fmt.Errorf("BND4 entry %q data is out of bounds", name)
		}
		entries = append(entries, BND4Entry{Name: name, Offset: offset, Size: size})
	}
	return entries, nil
}

// FindBND4Entry finds an entry by its basename.
func FindBND4Entry(blob []byte, name string) (BND4Entry, error) {
	entries, err := ListBND4Entries(blob)
	if err != nil {
		return BND4Entry{}, err
	}
	for _, entry := range entries {
		if entry.Name == name || strings.HasSuffix(entry.Name, "\\"+name) || strings.HasSuffix(entry.Name, "/"+name) {
			return entry, nil
		}
	}
	return BND4Entry{}, fmt.Errorf("no BND4 entry named %q: %w", name, ErrUnsupportedRegulation)
}

func readUTF16LECString(blob []byte, offset int) (string, error) {
	if offset < 0 || offset >= len(blob) {
		return "", fmt.Errorf("BND4 name offset 0x%X is out of bounds", offset)
	}
	var units []uint16
	for position := offset; ; position += 2 {
		if position+2 > len(blob) {
			return "", fmt.Errorf("unterminated BND4 name at 0x%X", offset)
		}
		unit := binary.LittleEndian.Uint16(blob[position : position+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units)), nil
}

// ReplaceBND4Entry swaps one entry for a different-sized one, moving every
// entry stored after it and rewriting their offsets. It grows and shrinks.
// The reopen-and-compare at the end is what makes it safe: every other entry
// must read back byte-identical.
func ReplaceBND4Entry(blob []byte, target BND4Entry, replacement []byte) ([]byte, error) {
	if len(replacement) == 0 {
		return nil, fmt.Errorf("refusing to replace BND4 entry %q with nothing", target.Name)
	}
	if len(blob) < bnd4EntryTableOffset || blob[9] != 0 {
		return nil, fmt.Errorf("only little-endian BND4 archives are supported: %w", ErrUnsupportedRegulation)
	}
	if binary.LittleEndian.Uint64(blob[0x20:0x28]) != bnd4EntryHeaderSize {
		return nil, fmt.Errorf("unsupported BND4 entry header size: %w", ErrUnsupportedRegulation)
	}
	entries, err := ListBND4Entries(blob)
	if err != nil {
		return nil, err
	}
	targetIndex := -1
	for index, entry := range entries {
		if entry == target {
			targetIndex = index
			break
		}
	}
	if targetIndex < 0 {
		return nil, fmt.Errorf("BND4 entry %q is not present", target.Name)
	}
	base := bnd4EntryTableOffset + targetIndex*bnd4EntryHeaderSize
	if binary.LittleEndian.Uint64(blob[base+16:base+24]) != uint64(target.Size) {
		return nil, fmt.Errorf("BND4 entry %q is compressed; resizing one needs a stored entry: %w",
			target.Name, ErrUnsupportedRegulation)
	}

	// Entries are contiguous and 16-aligned on every regulation measured.
	// Growing an entry that does not own the space up to the next one would
	// truncate its neighbour, so any other layout is refused.
	nextOffset := len(blob)
	for _, entry := range entries {
		if entry.Offset > target.Offset && entry.Offset < nextOffset {
			nextOffset = entry.Offset
		}
	}
	if nextOffset != len(blob) && nextOffset != align16(target.Offset+target.Size) {
		return nil, fmt.Errorf("BND4 entry %q ends at %#x but the next entry starts at %#x: %w",
			target.Name, align16(target.Offset+target.Size), nextOffset, ErrUnsupportedRegulation)
	}
	if nextOffset == len(blob) && target.Offset+target.Size != len(blob) {
		return nil, fmt.Errorf("BND4 entry %q is last but does not reach the archive end: %w",
			target.Name, ErrUnsupportedRegulation)
	}
	newNext := target.Offset + len(replacement)
	if nextOffset != len(blob) {
		newNext = align16(newNext)
	}
	delta := newNext - nextOffset

	result := make([]byte, len(blob)+delta)
	copy(result[:target.Offset], blob[:target.Offset])
	copy(result[target.Offset:], replacement)
	copy(result[newNext:], blob[nextOffset:])
	binary.LittleEndian.PutUint64(result[base+8:base+16], uint64(len(replacement)))
	binary.LittleEndian.PutUint64(result[base+16:base+24], uint64(len(replacement)))
	for index, entry := range entries {
		if index == targetIndex || entry.Offset < nextOffset {
			continue
		}
		headerBase := bnd4EntryTableOffset + index*bnd4EntryHeaderSize
		binary.LittleEndian.PutUint32(result[headerBase+24:headerBase+28], uint32(entry.Offset+delta))
	}

	// This also catches an archive whose entry names sit after the moved data:
	// they would decode differently.
	reopened, err := ListBND4Entries(result)
	if err != nil {
		return nil, fmt.Errorf("reopening the archive after resizing %q: %w", target.Name, err)
	}
	if len(reopened) != len(entries) {
		return nil, fmt.Errorf("BND4 entry count changed from %d to %d", len(entries), len(reopened))
	}
	for index := range entries {
		before, after := entries[index], reopened[index]
		if before.Name != after.Name {
			return nil, fmt.Errorf("BND4 entry %d is now named %q, was %q", index, after.Name, before.Name)
		}
		if index == targetIndex {
			if after.Size != len(replacement) || !bytes.Equal(result[after.Offset:after.Offset+after.Size], replacement) {
				return nil, fmt.Errorf("BND4 entry %q did not read back as written", target.Name)
			}
			continue
		}
		if before.Size != after.Size || !bytes.Equal(blob[before.Offset:before.Offset+before.Size], result[after.Offset:after.Offset+after.Size]) {
			return nil, fmt.Errorf("BND4 entry %q changed while resizing %q", before.Name, target.Name)
		}
	}
	return result, nil
}

func align16(value int) int { return (value + 15) &^ 15 }

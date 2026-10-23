// Package charslot reads and edits the ten character slots of an Elden Ring
// save on either platform: which slots hold a character, who each one is, and
// the event flags that record its progress.
//
// Two byte patterns locate everything, so no structure in between has to be
// walked: the identity pattern, from EldenRing-SaveForge (GPL-3.0), and the
// TutorialData magic, found by ER Merchant Editor. ER_research walks the
// structures between them and checks the second against the walk.
package charslot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"unicode/utf16"

	"github.com/DrippingSoup22/ER_shared/regulation"
)

// Slots returns the ten slot bodies of a save, backed by data: editing one
// edits the save. On PC an edited slot needs RefreshDigest before the file is
// written.
func Slots(data []byte) ([][]byte, error) {
	platform, err := regulation.DetectPlatform(data)
	if err != nil {
		return nil, err
	}
	if end := regulation.SlotOffset(platform, regulation.NumSlots); len(data) < end {
		return nil, fmt.Errorf("%s save is %d bytes, too small for ten slots: %w", platform, len(data), regulation.ErrNotDecryptedSave)
	}
	slots := make([][]byte, regulation.NumSlots)
	for index := range slots {
		start := regulation.SlotOffset(platform, index)
		slots[index] = data[start : start+regulation.SlotSize : start+regulation.SlotSize]
	}
	return slots, nil
}

// RefreshDigest rewrites a PC slot's MD5 after an edit; the game rejects a PC
// save whose digests do not match. PS4 slots carry none: a no-op.
func RefreshDigest(data []byte, slot int) error {
	platform, err := regulation.DetectPlatform(data)
	if err != nil {
		return err
	}
	if slot < 0 || slot >= regulation.NumSlots {
		return fmt.Errorf("slot %d is outside 0..%d", slot, regulation.NumSlots-1)
	}
	start := regulation.SlotOffset(platform, slot)
	return regulation.RefreshDigest(platform, data, start, start+regulation.SlotSize)
}

// IsEmpty reports whether a slot holds no character: its leading version word
// is zero.
func IsEmpty(slot []byte) bool {
	return binary.LittleEndian.Uint32(slot) == 0
}

// identityPattern sits just after PlayerGameData; the name and level are read
// at fixed distances before it. From EldenRing-SaveForge's
// backend/core/structures.go (MagicPattern) and offset_defs.go.
var identityPattern = []byte{
	0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

const (
	nameBeforePattern  = 0x11B // 16 UTF-16LE units, zero-terminated
	levelBeforePattern = 335
)

// Identity is what a slot picker shows.
type Identity struct {
	Name  string
	Level uint32
}

// ReadIdentity reads a slot's character name and level.
func ReadIdentity(slot []byte) (Identity, error) {
	at := bytes.Index(slot, identityPattern)
	if at < max(nameBeforePattern, levelBeforePattern) {
		return Identity{}, fmt.Errorf("no identity pattern: the slot is empty or not a character")
	}
	units := make([]uint16, 16)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(slot[at-nameBeforePattern+2*index:])
	}
	if end := slices.Index(units, 0); end >= 0 {
		units = units[:end]
	}
	return Identity{
		Name:  string(utf16.Decode(units)),
		Level: binary.LittleEndian.Uint32(slot[at-levelBeforePattern:]),
	}, nil
}

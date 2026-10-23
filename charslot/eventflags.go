package charslot

import (
	"bytes"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// FlagBytes is the length of a slot's event-flag bitfield: 14667 blocks of 125
// bytes. One zero byte follows it.
const FlagBytes = 0x1BF99F

const (
	flagsPerBlock = 1000
	blockBytes    = flagsPerBlock / 8

	// The bitfield starts this far after the TutorialData magic, which occurs
	// once in every occupied slot.
	tutorialToFlags = 0x425
)

var tutorialMagic = []byte{0xAE, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00}

// EventFlags returns a slot's event-flag bitfield, backed by the slot.
func EventFlags(slot []byte) ([]byte, error) {
	at := bytes.Index(slot, tutorialMagic)
	if at < 0 {
		return nil, fmt.Errorf("no TutorialData magic: the slot is empty or not a character")
	}
	start := at + tutorialToFlags
	if start+FlagBytes >= len(slot) {
		return nil, fmt.Errorf("event flags at 0x%X would run past the slot", start)
	}
	if terminator := slot[start+FlagBytes]; terminator != 0 {
		return nil, fmt.Errorf("event flags at 0x%X end in 0x%02X, not the zero terminator", start, terminator)
	}
	return slot[start : start+FlagBytes : start+FlagBytes], nil
}

// The game stores a block of a thousand flags wherever its own table says, not
// at id/1000: the table is neither dense nor monotonic. eventflag_bst.txt is
// that table, "block,position" per line, from EldenRing-SaveForge's
// backend/db/data/eventflag_bst.txt (GPL-3.0), line endings normalised.
//
//go:embed eventflag_bst.txt
var blockTable string

var blockPositions = sync.OnceValue(func() map[uint32]uint32 {
	positions := make(map[uint32]uint32, 12000)
	for _, line := range strings.Fields(blockTable) {
		block, position, _ := strings.Cut(line, ",")
		b, errBlock := strconv.ParseUint(block, 10, 32)
		p, errPosition := strconv.ParseUint(position, 10, 32)
		if errBlock != nil || errPosition != nil {
			panic("charslot: malformed block table line " + line)
		}
		positions[uint32(b)] = uint32(p)
	}
	return positions
})

// FlagPosition is the byte and bit holding a flag. Bits count from the most
// significant, so flag N of a block is bit 7-(N%8). A flag whose block the
// table does not hold is an error, never a guess.
func FlagPosition(id uint32) (byteIndex int, bit uint, err error) {
	position, ok := blockPositions()[id/flagsPerBlock]
	if !ok {
		return 0, 0, fmt.Errorf("event flag %d: block %d is not in the game's table", id, id/flagsPerBlock)
	}
	index := id % flagsPerBlock
	byteIndex = int(position)*blockBytes + int(index/8)
	if byteIndex >= FlagBytes {
		return 0, 0, fmt.Errorf("event flag %d resolves past the bitfield", id)
	}
	return byteIndex, 7 - uint(index%8), nil
}

// GetFlag reports whether a flag is set in a bitfield from EventFlags.
func GetFlag(flags []byte, id uint32) (bool, error) {
	byteIndex, bit, err := FlagPosition(id)
	if err != nil {
		return false, err
	}
	if byteIndex >= len(flags) {
		return false, fmt.Errorf("event flag %d: byte 0x%X is outside a %d-byte bitfield", id, byteIndex, len(flags))
	}
	return flags[byteIndex]>>bit&1 == 1, nil
}

// SetFlag sets or clears a flag in place.
func SetFlag(flags []byte, id uint32, on bool) error {
	byteIndex, bit, err := FlagPosition(id)
	if err != nil {
		return err
	}
	if byteIndex >= len(flags) {
		return fmt.Errorf("event flag %d: byte 0x%X is outside a %d-byte bitfield", id, byteIndex, len(flags))
	}
	if on {
		flags[byteIndex] |= 1 << bit
	} else {
		flags[byteIndex] &^= 1 << bit
	}
	return nil
}

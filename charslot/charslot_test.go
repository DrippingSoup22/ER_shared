package charslot

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/DrippingSoup22/ER_shared/regulation"
)

// syntheticSave is a save of one platform with a character in slot 2.
func syntheticSave(platform regulation.Platform) []byte {
	data := make([]byte, regulation.UserData10Offset(platform))
	if platform == regulation.PC {
		copy(data, "BND4")
	} else {
		copy(data, []byte{0xCB, 0x01, 0x9C, 0x2C})
	}
	slot := data[regulation.SlotOffset(platform, 2):]
	binary.LittleEndian.PutUint32(slot, 0x10)
	pattern := 0x20000
	copy(slot[pattern:], identityPattern)
	for index, unit := range utf16.Encode([]rune("Tarnished")) {
		binary.LittleEndian.PutUint16(slot[pattern-nameBeforePattern+2*index:], unit)
	}
	binary.LittleEndian.PutUint32(slot[pattern-levelBeforePattern:], 42)
	copy(slot[0x30000:], tutorialMagic)
	return data
}

func TestSlotsIdentityAndFlagsOnBothPlatforms(t *testing.T) {
	for _, platform := range []regulation.Platform{regulation.PS4, regulation.PC} {
		data := syntheticSave(platform)
		slots, err := Slots(data)
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		if !IsEmpty(slots[0]) || IsEmpty(slots[2]) {
			t.Fatalf("%s: slot 0 empty %v, slot 2 empty %v", platform, IsEmpty(slots[0]), IsEmpty(slots[2]))
		}
		identity, err := ReadIdentity(slots[2])
		if err != nil || identity != (Identity{"Tarnished", 42}) {
			t.Fatalf("%s: identity %+v, %v", platform, identity, err)
		}
		flags, err := EventFlags(slots[2])
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		if err := SetFlag(flags, 71190, true); err != nil {
			t.Fatal(err)
		}
		byteIndex, bit, _ := FlagPosition(71190)
		start := regulation.SlotOffset(platform, 2)
		if data[start+0x30000+tutorialToFlags+byteIndex] != 1<<bit {
			t.Fatalf("%s: SetFlag did not write through to the save", platform)
		}
		if on, err := GetFlag(flags, 71190); !on || err != nil {
			t.Fatalf("%s: GetFlag = %v, %v", platform, on, err)
		}

		if err := RefreshDigest(data, 2); err != nil {
			t.Fatal(err)
		}
		sum := md5.Sum(slots[2])
		hasDigest := bytes.Equal(data[start-regulation.DigestSize:start], sum[:])
		if hasDigest != (platform == regulation.PC) {
			t.Fatalf("%s: digest written %v", platform, hasDigest)
		}

		slots[2][0x30000+tutorialToFlags+FlagBytes] = 1
		if _, err := EventFlags(slots[2]); err == nil {
			t.Fatalf("%s: a missing terminator was accepted", platform)
		}
	}
}

func TestBlockTableFitsTheBitfield(t *testing.T) {
	seen := map[uint32]uint32{}
	for block, position := range blockPositions() {
		if int(position+1)*blockBytes > FlagBytes {
			t.Errorf("block %d sits at position %d, past the bitfield", block, position)
		}
		if other, clash := seen[position]; clash {
			t.Errorf("blocks %d and %d share position %d", block, other, position)
		}
		seen[position] = block
	}
	if _, _, err := FlagPosition(99019775); err == nil {
		t.Error("a flag outside the table resolved")
	}
}

// The private saves live in the research project; ER_SAVE names another.
func TestEveryOccupiedSlotOfARealSaveReads(t *testing.T) {
	path := os.Getenv("ER_SAVE")
	if path == "" {
		path = filepath.Join("..", "..", "ER_research", "save_file", "memory-1.17.1.dat")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("private save %s is absent: %v", path, err)
	}
	slots, err := Slots(data)
	if err != nil {
		t.Fatal(err)
	}
	occupied := 0
	for index, slot := range slots {
		if IsEmpty(slot) {
			continue
		}
		occupied++
		if _, err := ReadIdentity(slot); err != nil {
			t.Errorf("slot %d: %v", index, err)
		}
		if _, err := EventFlags(slot); err != nil {
			t.Errorf("slot %d: %v", index, err)
		}
	}
	if occupied == 0 {
		t.Fatal("no occupied slot")
	}
}

package regulation

import (
	"bytes"
	"crypto/md5"
	"fmt"
)

// Platform is the save container a file uses. The regulation inside is the
// same on both - same key, same DCX/ZSTD, same BND4 and PARAM rows - so the
// platform decides only where each region starts, and whether a written
// region needs its MD5 refreshed.
type Platform int

const (
	PS4 Platform = iota // a decrypted PlayStation memory.dat
	PC                  // an unencrypted ER0000.sl2
)

func (platform Platform) String() string {
	if platform == PC {
		return "PC"
	}
	return "PS4"
}

// The container layout: a header, ten character slots, UserData10, then
// UserData11, which holds the encrypted regulation. PC wraps the twelve regions
// in a BND4 and puts MD5(region) before each one; PS4 packs them bare.
const (
	PS4HeaderSize  = 0x70
	PCHeaderSize   = 0x300
	DigestSize     = 0x10
	SlotSize       = 0x280000
	NumSlots       = 10
	UserData10Size = 0x60000
)

var ps4Magic = []byte{0xCB, 0x01, 0x9C, 0x2C}

// DetectPlatform names the container by its leading magic and nothing else:
// never by file extension, and never by trying a decryption, because a file
// read as the wrong platform would be written back in the wrong shape. A PC
// save that Steam encrypted on Windows has no leading BND4 and is refused.
func DetectPlatform(data []byte) (Platform, error) {
	if len(data) >= 4 {
		switch {
		case string(data[:4]) == "BND4":
			return PC, nil
		case bytes.Equal(data[:4], ps4Magic):
			return PS4, nil
		}
	}
	return 0, fmt.Errorf("unrecognised container: a PC save starts with \"BND4\", a decrypted "+
		"PlayStation save with CB 01 9C 2C; a Steam-encrypted PC save must be decrypted first: %w", ErrNotDecryptedSave)
}

// SlotOffset is where character slot i's body starts.
func SlotOffset(platform Platform, slot int) int {
	if platform == PC {
		return PCHeaderSize + slot*(DigestSize+SlotSize) + DigestSize
	}
	return PS4HeaderSize + slot*SlotSize
}

// UserData10Offset is where UserData10's body starts: the profile summaries.
func UserData10Offset(platform Platform) int {
	return SlotOffset(platform, NumSlots)
}

// UserData11Offset is where UserData11's body starts; it runs to the end of the file.
func UserData11Offset(platform Platform) int {
	if platform == PC {
		return UserData10Offset(platform) + UserData10Size + DigestSize
	}
	return UserData10Offset(platform) + UserData10Size
}

// RefreshDigest rewrites the MD5 of the region data[start:end] in the sixteen
// bytes before it. The game rejects a PC save whose digests do not match, so
// every write to a PC region ends here. PS4 regions carry no digest: a no-op.
func RefreshDigest(platform Platform, data []byte, start, end int) error {
	if platform != PC {
		return nil
	}
	if start < DigestSize || end > len(data) || start > end {
		return fmt.Errorf("region [%#x,%#x) has no digest slot inside a %d-byte file", start, end, len(data))
	}
	sum := md5.Sum(data[start:end])
	copy(data[start-DigestSize:start], sum[:])
	return nil
}

// Package regulation reads and rebuilds the regulation embedded in an Elden
// Ring save - a decrypted PS4 memory.dat or an unencrypted PC ER0000.sl2: the
// save container and its DCX/ZSTD compression, the BND4 archive inside it, and
// the PARAM tables in that archive.
//
// Only the ZSTD format the game ships is supported. The implementation descends
// from ER Merchant Editor's save code, which came from er_pvp_mod and
// SaveForge-derived work. All are GPL-3.0-or-later; see ../LICENSE.
package regulation

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// Each sentinel is wrapped in a message that keeps the detail. Use errors.Is
// for the category.
var (
	// ErrNotDecryptedSave: not a recognised container, too small, or UserData11
	// still carries console encryption.
	ErrNotDecryptedSave = errors.New("not a decrypted save")
	// ErrUnsupportedRegulation: the container was recognised, but its contents
	// are a shape this code does not read or write, such as another
	// compression format or a PARAM whose schema or stride differs.
	ErrUnsupportedRegulation = errors.New("unsupported regulation layout")
	// ErrOutputExists: writing would replace an existing file.
	ErrOutputExists = errors.New("output file already exists")
)

var regulationKey = []byte{
	0x99, 0xBF, 0xFC, 0x36, 0x6A, 0x6B, 0xC8, 0xC6,
	0xF5, 0x82, 0x7D, 0x09, 0x36, 0x02, 0xD6, 0x76,
	0xC4, 0x28, 0x92, 0xA0, 0x1C, 0x20, 0x7F, 0xB0,
	0x24, 0xD3, 0xAF, 0x4E, 0x49, 0x3F, 0xEF, 0x99,
}

const (
	userData11HeaderSize   = 0x10
	aesIVSize              = 16
	dcxHeaderSize          = 76
	soulsFormatsWindowSize = 1 << 16
	// The game's BND4 is about 52 MiB; this leaves room for added rows.
	maxBND4Size = 256 << 20
)

// Regulation is a loaded save. Callers edit BND4 and pass the result to Build.
type Regulation struct {
	FileBytes        []byte
	Platform         Platform
	UserData11Offset int
	Version          uint32
	IV               []byte
	CiphertextLen    int
	Plaintext        []byte
	CompressedSize   int
	BND4             []byte
}

// WriteSummary describes a rebuild's recompression.
type WriteSummary struct {
	OriginalStreamSize int
	NewStreamSize      int
	Capacity           int
}

// Load decrypts and decompresses the regulation of the save at path.
func Load(path string) (*Regulation, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	platform, err := DetectPlatform(fileBytes)
	if err != nil {
		return nil, err
	}
	userData11Offset := UserData11Offset(platform)
	if userData11Offset >= len(fileBytes) {
		return nil, fmt.Errorf("file too small (%d bytes) for %s UserData11 at 0x%X: %w", len(fileBytes), platform, userData11Offset, ErrNotDecryptedSave)
	}
	userData11 := fileBytes[userData11Offset:]
	if len(userData11) < userData11HeaderSize+aesIVSize+aes.BlockSize {
		return nil, fmt.Errorf("UserData11 too short: %d bytes: %w", len(userData11), ErrNotDecryptedSave)
	}
	// The magic at the computed offset is also the layout check: had the
	// platform arithmetic been wrong, this would land inside a character slot.
	if string(userData11[:4]) != " GER" {
		return nil, fmt.Errorf("%s UserData11 is not decrypted (magic % X): %w", platform, userData11[:4], ErrNotDecryptedSave)
	}

	iv := bytes.Clone(userData11[userData11HeaderSize : userData11HeaderSize+aesIVSize])
	ciphertext := userData11[userData11HeaderSize+aesIVSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("regulation ciphertext size %d is not AES-block-aligned: %w", len(ciphertext), ErrNotDecryptedSave)
	}
	block, err := aes.NewCipher(regulationKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	if len(plaintext) < dcxHeaderSize || string(plaintext[:4]) != "DCX\x00" {
		return nil, fmt.Errorf("decrypted regulation is not DCX: %w", ErrNotDecryptedSave)
	}
	if format := string(plaintext[40:44]); format != "ZSTD" {
		return nil, fmt.Errorf("unsupported DCX format %q; only verified ZSTD saves are supported: %w", format, ErrUnsupportedRegulation)
	}
	decompressedSize := int(binary.BigEndian.Uint32(plaintext[28:32]))
	compressedSize := int(binary.BigEndian.Uint32(plaintext[32:36]))
	if compressedSize <= 0 || dcxHeaderSize+compressedSize > len(plaintext) {
		return nil, fmt.Errorf("invalid DCX compressed size %d: %w", compressedSize, ErrUnsupportedRegulation)
	}
	// The header's size sets the buffer, so it is trusted only up to a bound: a
	// corrupt save fails here instead of asking for gigabytes.
	if decompressedSize <= 0 || decompressedSize > maxBND4Size {
		return nil, fmt.Errorf("invalid DCX decompressed size %d: %w", decompressedSize, ErrUnsupportedRegulation)
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	bnd4, err := decoder.DecodeAll(plaintext[dcxHeaderSize:dcxHeaderSize+compressedSize], make([]byte, 0, decompressedSize))
	if err != nil {
		return nil, fmt.Errorf("zstd decompress: %v: %w", err, ErrUnsupportedRegulation)
	}
	if len(bnd4) != decompressedSize {
		return nil, fmt.Errorf("decompressed size %d does not match DCX header %d: %w", len(bnd4), decompressedSize, ErrUnsupportedRegulation)
	}
	if len(bnd4) < 4 || string(bnd4[:4]) != "BND4" {
		return nil, fmt.Errorf("decompressed regulation is not BND4: %w", ErrUnsupportedRegulation)
	}
	return &Regulation{
		FileBytes: fileBytes, Platform: platform, UserData11Offset: userData11Offset,
		Version: binary.LittleEndian.Uint32(userData11[8:12]), IV: iv,
		CiphertextLen: len(ciphertext), Plaintext: plaintext,
		CompressedSize: compressedSize, BND4: bnd4,
	}, nil
}

// Build recompresses and encrypts regulation.BND4 and returns the complete
// save image. It checks that the new stream decompresses to the same BND4 and
// fits the fixed capacity. It writes nothing to disk.
func Build(regulation *Regulation) ([]byte, WriteSummary, error) {
	stream, err := recompress(regulation.BND4)
	if err != nil {
		return nil, WriteSummary{}, err
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, WriteSummary{}, err
	}
	roundTrip, decodeErr := decoder.DecodeAll(stream, make([]byte, 0, len(regulation.BND4)))
	decoder.Close()
	if decodeErr != nil {
		return nil, WriteSummary{}, fmt.Errorf("recompression self-check: %w", decodeErr)
	}
	if !bytes.Equal(roundTrip, regulation.BND4) {
		return nil, WriteSummary{}, fmt.Errorf("recompression self-check returned different BND4 data")
	}

	liveSize := dcxHeaderSize + len(stream)
	if liveSize > regulation.CiphertextLen {
		return nil, WriteSummary{}, fmt.Errorf("rebuilt regulation size %d exceeds capacity %d", liveSize, regulation.CiphertextLen)
	}
	plaintext := make([]byte, regulation.CiphertextLen)
	copy(plaintext, regulation.Plaintext[:dcxHeaderSize])
	// A structural edit may grow the decompressed BND4 even when the stream
	// still fits the capacity, so both sizes are rewritten.
	binary.BigEndian.PutUint32(plaintext[28:32], uint32(len(regulation.BND4)))
	binary.BigEndian.PutUint32(plaintext[32:36], uint32(len(stream)))
	copy(plaintext[dcxHeaderSize:], stream)

	block, err := aes.NewCipher(regulationKey)
	if err != nil {
		return nil, WriteSummary{}, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, regulation.IV).CryptBlocks(ciphertext, plaintext)
	result := bytes.Clone(regulation.FileBytes)
	copy(result[regulation.UserData11Offset+userData11HeaderSize:], regulation.IV)
	copy(result[regulation.UserData11Offset+userData11HeaderSize+aesIVSize:], ciphertext)
	if err := RefreshDigest(regulation.Platform, result, regulation.UserData11Offset, len(result)); err != nil {
		return nil, WriteSummary{}, err
	}
	return result, WriteSummary{
		OriginalStreamSize: regulation.CompressedSize,
		NewStreamSize:      len(stream), Capacity: regulation.CiphertextLen,
	}, nil
}

// recompress encodes in the frame shape SoulsFormats writes: a 64 KiB window,
// no checksum and no content size.
func recompress(bnd4 []byte) ([]byte, error) {
	var buffer bytes.Buffer
	encoder, err := zstd.NewWriter(&buffer,
		zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithWindowSize(soulsFormatsWindowSize),
		zstd.WithEncoderCRC(false),
	)
	if err != nil {
		return nil, fmt.Errorf("zstd encoder: %w", err)
	}
	if _, err := encoder.Write(bnd4); err != nil {
		encoder.Close()
		return nil, fmt.Errorf("zstd encode: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("zstd close: %w", err)
	}
	return buffer.Bytes(), nil
}

// WriteAtomicValidated writes data to a temporary file beside outPath, runs
// validate on it, and only then renames it to outPath. It never replaces an
// existing file.
func WriteAtomicValidated(outPath string, data []byte, validate func(string) error) error {
	return writeAtomic(outPath, data, validate, false)
}

// ReplaceAtomicValidated is WriteAtomicValidated for an output the user chose
// to replace, as a Save As dialog asks: an existing outPath is swapped out only
// once the new file has validated. It refuses to replace inputPath itself.
func ReplaceAtomicValidated(inputPath, outPath string, data []byte, validate func(string) error) error {
	if input, err := os.Stat(inputPath); err == nil {
		if output, err := os.Stat(outPath); err == nil && os.SameFile(input, output) {
			return fmt.Errorf("output %s is the input save: %w", outPath, ErrOutputExists)
		}
	}
	return writeAtomic(outPath, data, validate, true)
}

func writeAtomic(outPath string, data []byte, validate func(string) error, replace bool) error {
	if _, err := os.Stat(outPath); err == nil && !replace {
		return fmt.Errorf("output already exists: %s: %w", outPath, ErrOutputExists)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	directory := filepath.Dir(outPath)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(outPath)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := validate(temporaryPath); err != nil {
		return fmt.Errorf("output validation: %w", err)
	}
	if _, err := os.Stat(outPath); err == nil && !replace {
		return fmt.Errorf("output appeared while writing: %s: %w", outPath, ErrOutputExists)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(temporaryPath, outPath); err != nil {
		return err
	}
	published = true
	return nil
}

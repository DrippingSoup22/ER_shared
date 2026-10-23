package regulation

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// recompress is unexported, so this test lives with it rather than reaching
// across a package boundary for a format-layer internal.
func TestRecompressUsesSoulsFormatsFrameShape(t *testing.T) {
	stream, err := recompress(bytes.Repeat([]byte("Elden Ring regulation test data\n"), 4096))
	if err != nil {
		t.Fatal(err)
	}
	if len(stream) < 6 {
		t.Fatalf("zstd stream is too short: %d", len(stream))
	}
	descriptor := stream[4]
	if descriptor&(1<<5) != 0 {
		t.Error("single-segment frame implies a content size")
	}
	if descriptor&(1<<2) != 0 {
		t.Error("zstd checksum flag is set")
	}
	if contentSizeFlag := descriptor >> 6; contentSizeFlag != 0 {
		t.Errorf("content size flag = %d, want 0", contentSizeFlag)
	}
	windowDescriptor := stream[5]
	exponent := int(windowDescriptor >> 3)
	mantissa := int(windowDescriptor & 7)
	windowBase := 1 << (10 + exponent)
	windowSize := windowBase + (windowBase/8)*mantissa
	if windowSize != soulsFormatsWindowSize {
		t.Errorf("window size = %d, want %d", windowSize, soulsFormatsWindowSize)
	}
}

// One pass over every layer on the real save: insert a row, remove it again,
// rebuild the container and reopen it. Each step must hand back exactly what
// went in.
func TestInsertRemoveAndRebuildRoundTripTheRealSave(t *testing.T) {
	savePath := requireSave(t)
	loaded, err := Load(savePath)
	if err != nil {
		t.Fatal(err)
	}
	layout := MustLayout("NpcThinkParam")
	table, err := OpenTable(loaded.BND4, layout)
	if err != nil {
		t.Fatal(err)
	}
	last := table.Rows[len(table.Rows)-1].ID
	grown, err := InsertRows(loaded.BND4, layout, []RowInsertion{{RowID: last + 1, CopyFrom: table.Rows[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(grown, loaded.BND4) {
		t.Fatal("insertion changed nothing")
	}
	shrunk, err := RemoveRows(grown, layout, []int32{last + 1})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shrunk, loaded.BND4) {
		t.Fatal("removing the inserted row did not restore the original BND4")
	}

	image, _, err := Build(loaded)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rebuilt.dat")
	if err := WriteAtomicValidated(path, image, func(candidate string) error {
		reopened, err := Load(candidate)
		if err != nil {
			return err
		}
		if !bytes.Equal(reopened.BND4, loaded.BND4) {
			return fmt.Errorf("rebuilt save holds a different BND4")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomicValidated(path, image, func(string) error { return nil }); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("second write returned %v, want ErrOutputExists", err)
	}
	// A replacement never hits the input, and one that fails validation
	// leaves the old file in place.
	if err := ReplaceAtomicValidated(path, path, []byte("new"), func(string) error { return nil }); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("replacing the input returned %v", err)
	}
	if err := ReplaceAtomicValidated(savePath, path, []byte("bad"), func(string) error { return errors.New("bad") }); err == nil {
		t.Fatal("a replacement that failed validation was accepted")
	}
	if err := ReplaceAtomicValidated(savePath, path, []byte("new"), func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if replaced, _ := os.ReadFile(path); string(replaced) != "new" {
		t.Fatalf("output holds %d bytes after the replacement", len(replaced))
	}
}

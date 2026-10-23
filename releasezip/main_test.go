package main

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateArchiveIncludesBundleAndPreservesMode(t *testing.T) {
	temp := t.TempDir()
	bundle := filepath.Join(temp, "ER-Tool-linux-amd64-1.0.0")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(bundle, "ERTool")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(temp, "release", "tool.zip")
	if err := createArchive(bundle, archivePath); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	wantName := filepath.Base(bundle) + "/ERTool"
	for _, entry := range zr.File {
		if entry.Name != wantName {
			continue
		}
		if runtime.GOOS != "windows" && entry.Mode().Perm() != 0o755 {
			t.Fatalf("executable mode = %o, want 755", entry.Mode().Perm())
		}
		reader, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			_ = reader.Close()
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if string(data) != "binary" {
			t.Fatalf("archived contents = %q", data)
		}
		return
	}
	t.Fatalf("archive is missing %q", wantName)
}

func TestCreateArchiveRefusesOverwrite(t *testing.T) {
	temp := t.TempDir()
	bundle := filepath.Join(temp, "bundle")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(temp, "existing.zip")
	if err := os.WriteFile(archivePath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createArchive(bundle, archivePath); err == nil {
		t.Fatal("existing output was overwritten")
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("existing output changed to %q", data)
	}
}

func TestCreateArchiveRejectsOutputInsideBundle(t *testing.T) {
	temp := t.TempDir()
	bundle := filepath.Join(temp, "bundle")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createArchive(bundle, filepath.Join(bundle, "self.zip")); err == nil {
		t.Fatal("output inside bundle was accepted")
	}
}

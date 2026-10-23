// Command releasezip creates a release ZIP containing one bundle directory.
package main

import (
	"archive/zip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	root := flag.String("root", "", "bundle directory to archive")
	out := flag.String("out", "", "new destination .zip path")
	flag.Parse()

	if *root == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "error: -root and -out are required")
		os.Exit(2)
	}
	if err := createArchive(*root, *out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func createArchive(root, out string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve bundle: %w", err)
	}
	outAbs, err := filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}

	info, err := os.Stat(rootAbs)
	if err != nil {
		return fmt.Errorf("stat bundle: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("bundle root is not a directory: %s", root)
	}
	if pathWithin(rootAbs, outAbs) {
		return errors.New("output archive must be outside the bundle directory")
	}
	if _, err := os.Lstat(outAbs); err == nil {
		return fmt.Errorf("refusing to overwrite existing output %q", out)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output: %w", err)
	}

	outDir := filepath.Dir(outAbs)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(outDir, ".releasezip-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary archive: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	zw := zip.NewWriter(tmp)
	parent := filepath.Dir(filepath.Clean(rootAbs))
	walkErr := filepath.Walk(rootAbs, func(path string, entry os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not supported: %s", path)
		}
		if !entry.IsDir() && !entry.Mode().IsRegular() {
			return fmt.Errorf("unsupported file type: %s", path)
		}

		rel, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(entry)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if entry.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		src, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, src)
		closeErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if walkErr != nil {
		_ = zw.Close()
		_ = tmp.Close()
		return fmt.Errorf("archive bundle: %w", walkErr)
	}
	if err := zw.Close(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("finish archive: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	if err := os.Rename(tmpName, outAbs); err != nil {
		return fmt.Errorf("commit archive: %w", err)
	}
	committed = true
	return nil
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

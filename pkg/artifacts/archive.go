// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Archive Extraction Support
// =========================================================================
//
// Extracts compressed archive files before scanning. Supports:
//   - .zip
//   - .tar.gz / .tgz
//   - .tar.bz2
//
// Uses only Go standard library: archive/zip, archive/tar,
// compress/gzip, compress/bzip2. No external dependencies.
//
// Extracted files are placed in a temporary directory and the caller
// is responsible for cleanup via the returned cleanup function.
//
// =========================================================================

package artifacts

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// ArchiveType represents the type of archive file.
type ArchiveType string

const (
	ArchiveZip    ArchiveType = "zip"
	ArchiveTarGz  ArchiveType = "tar.gz"
	ArchiveTarBz2 ArchiveType = "tar.bz2"
)

// ExtractResult holds the result of archive extraction.
type ExtractResult struct {
	// Dir is the temporary directory where files were extracted.
	Dir string

	// Files is the list of extracted file paths (relative to Dir).
	Files []string

	// Cleanup removes the temporary directory.
	Cleanup func()
}

// ---------------------------------------------------------------------
// Archive detection
// ---------------------------------------------------------------------

// IsArchive checks if a file path has a supported archive extension.
func IsArchive(path string) bool {
	return DetectArchiveType(path) != ""
}

// DetectArchiveType returns the archive type for a file path, or empty
// string if the file is not a supported archive.
func DetectArchiveType(path string) ArchiveType {
	lower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(lower, ".zip"):
		return ArchiveZip
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return ArchiveTarGz
	case strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tbz2"):
		return ArchiveTarBz2
	default:
		return ""
	}
}

// ---------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------

// ExtractArchive extracts an archive file to a temporary directory.
// Returns an ExtractResult containing the temp directory path, the
// list of extracted files, and a cleanup function.
//
// The caller MUST call Cleanup() to remove the temporary directory.
//
// Supported formats: .zip, .tar.gz/.tgz, .tar.bz2/.tbz2
func ExtractArchive(path string) (*ExtractResult, error) {
	archiveType := DetectArchiveType(path)
	if archiveType == "" {
		return nil, fmt.Errorf("unsupported archive type: %s", path)
	}

	// Create temporary directory.
	tmpDir, err := os.MkdirTemp("", "aegisgate-extract-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	result := &ExtractResult{
		Dir: tmpDir,
		Cleanup: func() {
			os.RemoveAll(tmpDir)
		},
	}

	switch archiveType {
	case ArchiveZip:
		files, err := extractZip(path, tmpDir)
		if err != nil {
			result.Cleanup()
			return nil, err
		}
		result.Files = files
	case ArchiveTarGz:
		files, err := extractTarGz(path, tmpDir)
		if err != nil {
			result.Cleanup()
			return nil, err
		}
		result.Files = files
	case ArchiveTarBz2:
		files, err := extractTarBz2(path, tmpDir)
		if err != nil {
			result.Cleanup()
			return nil, err
		}
		result.Files = files
	default:
		result.Cleanup()
		return nil, fmt.Errorf("unsupported archive type: %s", archiveType)
	}

	return result, nil
}

// ---------------------------------------------------------------------
// ZIP extraction
// ---------------------------------------------------------------------

// extractZip extracts a ZIP archive to the target directory.
func extractZip(zipPath, destDir string) ([]string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	var files []string

	for _, f := range r.File {
		// Prevent Zip Slip (path traversal).
		destPath, err := sanitizeExtractPath(destDir, f.Name)
		if err != nil {
			return nil, err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return nil, fmt.Errorf("create dir %s: %w", destPath, err)
			}
			continue
		}

		// Ensure parent directory exists.
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return nil, fmt.Errorf("create parent dir: %w", err)
		}

		// Open entry.
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open zip entry %s: %w", f.Name, err)
		}

		// Write file.
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			rc.Close()
			return nil, fmt.Errorf("create file %s: %w", destPath, err)
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			rc.Close()
			outFile.Close()
			return nil, fmt.Errorf("write file %s: %w", destPath, err)
		}

		rc.Close()
		outFile.Close()

		relPath, _ := filepath.Rel(destDir, destPath)
		files = append(files, filepath.ToSlash(relPath))
	}

	return files, nil
}

// ---------------------------------------------------------------------
// TAR.GZ extraction
// ---------------------------------------------------------------------

// extractTarGz extracts a .tar.gz archive to the target directory.
func extractTarGz(tarGzPath, destDir string) ([]string, error) {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return nil, fmt.Errorf("open tar.gz: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzr.Close()

	return extractTar(gzr, destDir)
}

// ---------------------------------------------------------------------
// TAR.BZ2 extraction
// ---------------------------------------------------------------------

// extractTarBz2 extracts a .tar.bz2 archive to the target directory.
func extractTarBz2(tarBz2Path, destDir string) ([]string, error) {
	f, err := os.Open(tarBz2Path)
	if err != nil {
		return nil, fmt.Errorf("open tar.bz2: %w", err)
	}
	defer f.Close()

	bz2r := bzip2.NewReader(f)

	return extractTar(bz2r, destDir)
}

// ---------------------------------------------------------------------
// Common TAR extraction
// ---------------------------------------------------------------------

// extractTar reads a tar stream and extracts files to destDir.
func extractTar(r io.Reader, destDir string) ([]string, error) {
	tr := tar.NewReader(r)

	var files []string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar header: %w", err)
		}

		// Prevent path traversal (Tar Slip).
		destPath, err := sanitizeExtractPath(destDir, header.Name)
		if err != nil {
			return nil, err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return nil, fmt.Errorf("create dir %s: %w", destPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return nil, fmt.Errorf("create parent dir: %w", err)
			}

			outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return nil, fmt.Errorf("create file %s: %w", destPath, err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return nil, fmt.Errorf("write file %s: %w", destPath, err)
			}
			outFile.Close()

			relPath, _ := filepath.Rel(destDir, destPath)
			files = append(files, filepath.ToSlash(relPath))

		case tar.TypeSymlink:
			// Skip symlinks for security.
			continue
		}
	}

	return files, nil
}

// ---------------------------------------------------------------------
// Security helpers
// ---------------------------------------------------------------------

// sanitizeExtractPath prevents path traversal attacks by ensuring the
// extracted path stays within the destination directory.
func sanitizeExtractPath(destDir, entryName string) (string, error) {
	// Reject entries that contain path traversal sequences.
	cleaned := filepath.Clean(entryName)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, string(os.PathSeparator)+"..") {
		return "", fmt.Errorf("path traversal detected: %s contains '..'", entryName)
	}

	// Clean the entry name and join with destDir.
	destPath := filepath.Join(destDir, filepath.Clean("/"+entryName))

	// Verify the resulting path is within destDir.
	if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) && destPath != filepath.Clean(destDir) {
		return "", fmt.Errorf("path traversal detected: %s escapes %s", entryName, destDir)
	}

	return destPath, nil
}

// ---------------------------------------------------------------------
// WalkFiles extracts and returns artifacts from a list of file paths,
// extracting any archive files found. Non-archive files are passed through.
// This is used by the walker when --extract-archives is enabled.
// ---------------------------------------------------------------------

// ExtractArchivesInPlace walks a list of file paths, extracts any
// archives found, and returns a combined list of paths to scan
// (including extracted files and non-archive files).
//
// The returned cleanup function removes all temporary extraction directories.
func ExtractArchivesInPlace(paths []string) (extractedPaths []string, cleanup func(), err error) {
	var cleanups []func()
	var allPaths []string

	for _, p := range paths {
		if IsArchive(p) {
			result, err := ExtractArchive(p)
			if err != nil {
				// Run any existing cleanups before returning error.
				for _, c := range cleanups {
					c()
				}
				return nil, nil, fmt.Errorf("extract %s: %w", p, err)
			}
			cleanups = append(cleanups, result.Cleanup)

			// Add extracted file paths (full paths).
			for _, f := range result.Files {
				allPaths = append(allPaths, filepath.Join(result.Dir, f))
			}
		} else {
			allPaths = append(allPaths, p)
		}
	}

	cleanup = func() {
		for _, c := range cleanups {
			c()
		}
	}

	return allPaths, cleanup, nil
}

// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"strings"
	"testing"
)

func TestReadArtifactFromContent_Text(t *testing.T) {
	content := []byte("Hello, world!\nThis is line 2.\nLine 3.")
	art := ReadArtifactFromContent("stdin.txt", content)

	if art.Path != "stdin.txt" {
		t.Errorf("Path = %q, want stdin.txt", art.Path)
	}
	if art.AbsPath != "stdin.txt" {
		t.Errorf("AbsPath = %q, want stdin.txt", art.AbsPath)
	}
	if art.Class != ClassRAGDocument {
		t.Errorf("Class = %q, want %q", art.Class, ClassRAGDocument)
	}
	if art.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", art.Size, len(content))
	}
	if art.Binary {
		t.Error("Binary = true, want false")
	}
	if art.Skipped != "" {
		t.Errorf("Skipped = %q, want empty", art.Skipped)
	}
	if art.Content != string(content) {
		t.Errorf("Content mismatch")
	}
	// 3 lines: "Hello, world!\nThis is line 2.\nLine 3." → 3 lines (no trailing newline)
	if art.Lines != 3 {
		t.Errorf("Lines = %d, want 3", art.Lines)
	}
}

func TestReadArtifactFromContent_BOMStripped(t *testing.T) {
	// UTF-8 BOM + text
	content := []byte("\xEF\xBB\xBFHello, world!")
	art := ReadArtifactFromContent("stdin.txt", content)

	if strings.HasPrefix(art.Content, "\xEF\xBB\xBF") {
		t.Error("BOM not stripped from content")
	}
	if art.Content != "Hello, world!" {
		t.Errorf("Content = %q, want 'Hello, world!'", art.Content)
	}
}

func TestReadArtifactFromContent_PyExtension(t *testing.T) {
	content := []byte("import os\nos.system('rm -rf /')")
	art := ReadArtifactFromContent("stdin.py", content)

	if art.Class != ClassAgentSkill {
		t.Errorf("Class = %q, want %q", art.Class, ClassAgentSkill)
	}
}

func TestReadArtifactFromContent_JsonExtension(t *testing.T) {
	content := []byte(`{"key": "value"}`)
	art := ReadArtifactFromContent("stdin.json", content)

	// .json can be multiple classes; default (no path context) is first in list
	if art.Class == ClassGeneric {
		t.Errorf("Class = ClassGeneric, want a specific class")
	}
}

func TestReadArtifactFromContent_BinaryNullBytes(t *testing.T) {
	// Content with null bytes → binary
	content := []byte{0x48, 0x49, 0x00, 0x49, 0x4A}
	art := ReadArtifactFromContent("stdin.txt", content)

	if !art.Binary {
		t.Error("Binary = false, want true for null-byte content")
	}
	if art.Skipped == "" {
		t.Error("Skipped should be set for binary content")
	}
	if art.Content != "" {
		t.Errorf("Content should be empty for binary, got %q", art.Content)
	}
}

func TestReadArtifactFromContent_BinaryHighNonText(t *testing.T) {
	// Content with >30% non-text bytes
	content := make([]byte, 200)
	for i := range content {
		if i%2 == 0 {
			content[i] = 0x01 // non-text byte
		} else {
			content[i] = 'A'
		}
	}
	art := ReadArtifactFromContent("stdin.txt", content)

	if !art.Binary {
		t.Error("Binary = false, want true for high non-text content")
	}
}

func TestReadArtifactFromContent_EmptyContent(t *testing.T) {
	art := ReadArtifactFromContent("stdin.txt", []byte{})

	if art.Binary {
		t.Error("Binary = true for empty content")
	}
	if art.Lines != 0 {
		t.Errorf("Lines = %d, want 0", art.Lines)
	}
	if art.Size != 0 {
		t.Errorf("Size = %d, want 0", art.Size)
	}
}

func TestReadArtifactFromContent_TrailingNewline(t *testing.T) {
	content := []byte("line1\nline2\n")
	art := ReadArtifactFromContent("stdin.txt", content)

	// "line1\nline2\n" → 2 lines (trailing newline doesn't add extra line)
	if art.Lines != 2 {
		t.Errorf("Lines = %d, want 2", art.Lines)
	}
}

func TestReadArtifactFromContent_NoTrailingNewline(t *testing.T) {
	content := []byte("line1\nline2\nline3")
	art := ReadArtifactFromContent("stdin.txt", content)

	// "line1\nline2\nline3" → 3 lines
	if art.Lines != 3 {
		t.Errorf("Lines = %d, want 3", art.Lines)
	}
}

func TestReadArtifactFromContent_LargeContent(t *testing.T) {
	// 1MB content
	content := strings.Repeat("A", 1024*1024)
	art := ReadArtifactFromContent("stdin.txt", []byte(content))

	if art.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", art.Size, len(content))
	}
	if art.Binary {
		t.Error("Large text content should not be binary")
	}
}

func TestIsBinaryContent_Empty(t *testing.T) {
	if isBinaryContent(nil) {
		t.Error("empty content should not be binary")
	}
	if isBinaryContent([]byte{}) {
		t.Error("empty content should not be binary")
	}
}

func TestIsBinaryContent_PureText(t *testing.T) {
	text := []byte("Hello, world! This is a normal text file with printable characters.")
	if isBinaryContent(text) {
		t.Error("pure text content should not be binary")
	}
}

func TestIsBinaryContent_NullByte(t *testing.T) {
	content := []byte("Hello\x00World")
	if !isBinaryContent(content) {
		t.Error("content with null byte should be binary")
	}
}

func TestIsBinaryContent_HighNonTextRatio(t *testing.T) {
	// 50% non-text bytes in first 512 bytes
	content := make([]byte, 512)
	for i := range content {
		if i%2 == 0 {
			content[i] = 0x01
		} else {
			content[i] = 'A'
		}
	}
	if !isBinaryContent(content) {
		t.Error("50% non-text content should be binary")
	}
}

func TestIsBinaryContent_LowNonTextRatio(t *testing.T) {
	// <30% non-text bytes
	content := make([]byte, 100)
	for i := 0; i < 90; i++ {
		content[i] = 'A'
	}
	for i := 90; i < 100; i++ {
		content[i] = 0x01
	}
	if isBinaryContent(content) {
		t.Error("10% non-text content should not be binary")
	}
}

func TestIsBinaryContent_UTF8Valid(t *testing.T) {
	// Valid UTF-8 with multi-byte chars
	content := []byte("Hello 世界 🌍 café")
	if isBinaryContent(content) {
		t.Error("valid UTF-8 content should not be binary")
	}
}

func TestIsBinaryContent_LargerThanSample(t *testing.T) {
	// Content larger than binaryCheckBytes (512)
	// First 512 bytes are text, then a null byte
	content := make([]byte, 1000)
	for i := range content {
		content[i] = 'A'
	}
	// Null byte at position 600 (beyond sample range)
	content[600] = 0
	// Should NOT be binary since the null is beyond the 512-byte sample
	if isBinaryContent(content) {
		t.Error("null byte beyond sample range should not trigger binary")
	}
}

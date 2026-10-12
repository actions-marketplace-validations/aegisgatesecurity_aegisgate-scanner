// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — SBOM Output Tests
// =========================================================================
//
// Tests for FormatSBOM() verifying SPDX JSON structure, package
// entries, relationships, and edge cases.
//
// =========================================================================

package output

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// SPDX document parsing helpers
// ---------------------------------------------------------------------

func parseSBOM(t *testing.T, data []byte) spdxDocument {
	t.Helper()
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Failed to parse SBOM JSON: %v", err)
	}
	return doc
}

// ---------------------------------------------------------------------
// FormatSBOM tests
// ---------------------------------------------------------------------

func TestFormatSBOM_Basic(t *testing.T) {
	result := makeScanResult()
	data, err := FormatSBOM(result, "/test/root", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatSBOM error: %v", err)
	}

	doc := parseSBOM(t, data)

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %s, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("DataLicense = %s, want CC0-1.0", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %s, want SPDXRef-DOCUMENT", doc.SPDXID)
	}
}

func TestFormatSBOM_ScannerPackage(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/root", "v1.0.0")
	doc := parseSBOM(t, data)

	found := false
	for _, pkg := range doc.Packages {
		if pkg.Name == "aegisgate-scanner" {
			found = true
			if pkg.VersionInfo != "v1.0.0" {
				t.Errorf("scanner version = %s, want v1.0.0", pkg.VersionInfo)
			}
			if pkg.LicenseConcluded != "Apache-2.0" {
				t.Errorf("scanner license = %s, want Apache-2.0", pkg.LicenseConcluded)
			}
		}
	}
	if !found {
		t.Error("SBOM should contain aegisgate-scanner package")
	}
}

func TestFormatSBOM_GoRuntime(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/root", "v1.0.0")
	doc := parseSBOM(t, data)

	found := false
	for _, pkg := range doc.Packages {
		if pkg.Name == "go-runtime" {
			found = true
			if pkg.LicenseConcluded != "BSD-3-Clause" {
				t.Errorf("go-runtime license = %s, want BSD-3-Clause", pkg.LicenseConcluded)
			}
		}
	}
	if !found {
		t.Error("SBOM should contain go-runtime package")
	}
}

func TestFormatSBOM_Relationships(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/root", "v1.0.0")
	doc := parseSBOM(t, data)

	if len(doc.Relationships) == 0 {
		t.Error("SBOM should contain at least one relationship")
	}

	// Should have DEPENDS_ON relationship to go-runtime.
	foundDep := false
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == "DEPENDS_ON" {
			foundDep = true
		}
	}
	if !foundDep {
		t.Error("SBOM should contain DEPENDS_ON relationship")
	}
}

func TestFormatSBOM_Creators(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/root", "v1.0.0")
	doc := parseSBOM(t, data)

	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("SBOM should have at least one creator")
	}

	foundTool := false
	for _, c := range doc.CreationInfo.Creators {
		if strings.Contains(c, "aegisgate-scanner") {
			foundTool = true
		}
	}
	if !foundTool {
		t.Error("SBOM creators should include aegisgate-scanner tool")
	}
}

func TestFormatSBOM_EmptyResults(t *testing.T) {
	result := makeEmptyScanResult()
	data, err := FormatSBOM(result, "/empty", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatSBOM error on empty: %v", err)
	}

	doc := parseSBOM(t, data)
	// Should still have scanner and go-runtime packages.
	if len(doc.Packages) < 2 {
		t.Error("SBOM for empty results should still have scanner and go-runtime packages")
	}
}

func TestFormatSBOM_NilResult(t *testing.T) {
	data, err := FormatSBOM(nil, "/root", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatSBOM should handle nil result: %v", err)
	}
	doc := parseSBOM(t, data)
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Error("SBOM should be valid SPDX even with nil result")
	}
}

func TestFormatSBOM_ExternalRefs(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/root", "v1.0.0")
	doc := parseSBOM(t, data)

	// Scanner package should have purl external ref.
	foundPurl := false
	for _, pkg := range doc.Packages {
		if pkg.Name == "aegisgate-scanner" {
			for _, ref := range pkg.ExternalRefs {
				if ref.ReferenceType == "purl" {
					foundPurl = true
				}
			}
		}
	}
	if !foundPurl {
		t.Error("Scanner package should have purl external reference")
	}
}

func TestFormatSBOM_DocumentNamespace(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/root", "v1.0.0")
	doc := parseSBOM(t, data)

	if !strings.Contains(doc.DocumentNamespace, "aegisgatesecurity.io") {
		t.Error("Document namespace should contain aegisgatesecurity.io")
	}
}

func TestFormatSBOM_CreationTimestamp(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/root", "v1.0.0")
	doc := parseSBOM(t, data)

	if doc.CreationInfo.Created == "" {
		t.Error("SBOM should have creation timestamp")
	}
}

func TestFormatSBOM_ValidJSON(t *testing.T) {
	result := makeScanResult()
	data, err := FormatSBOM(result, "/root", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatSBOM error: %v", err)
	}

	// Verify the output is valid JSON by re-parsing into a generic map.
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("SBOM output is not valid JSON: %v", err)
	}
}

func TestMakeSPDXID(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"github.com/aegisgatesecurity/aegisgate-scanner", "SPDXRef-Package-github-com-aegisgatesecurity-aegisgate-scanner"},
		{"simple", "SPDXRef-Package-simple"},
		{"a/b.c_d", "SPDXRef-Package-a-b-c-d"},
	}

	for _, tt := range tests {
		got := makeSPDXID(tt.input)
		if got != tt.expect {
			t.Errorf("makeSPDXID(%s) = %s, want %s", tt.input, got, tt.expect)
		}
	}
}

func TestFormatSBOM_ScannedArtifactsPackage(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatSBOM(result, "/my/project", "v1.0.0")
	doc := parseSBOM(t, data)

	// Should contain scanned-artifacts package since result has files.
	found := false
	for _, pkg := range doc.Packages {
		if pkg.Name == "scanned-artifacts" {
			found = true
			if !strings.Contains(pkg.Description, "/my/project") {
				t.Error("scanned-artifacts package should mention scan root")
			}
		}
	}
	if !found {
		t.Error("SBOM should contain scanned-artifacts package when files were scanned")
	}
}

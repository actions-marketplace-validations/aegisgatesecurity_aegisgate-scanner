// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — SBOM (Software Bill of Materials) Output
// =========================================================================
//
// Generates SBOM output in SPDX JSON format. The SBOM includes:
//   - Go module info (module name, Go version)
//   - Scanner version and tool metadata
//   - Vendored dependencies (from internal/ packages)
//   - SPDX 2.3 JSON schema compliance
//
// SPDX spec: https://spdx.github.io/spdx-spec/
//
// =========================================================================

package output

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// SPDX JSON schema types (SPDX 2.3)
// ---------------------------------------------------------------------

// spdxDocument is the top-level SPDX document.
type spdxDocument struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      spdxCreation   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Relationships     []spdxRelation `json:"relationships"`
}

// spdxCreation holds document creation metadata.
type spdxCreation struct {
	Created        string   `json:"created"`
	Creators       []string `json:"creators"`
	LicenseListVer string   `json:"licenseListVersion,omitempty"`
}

// spdxPackage describes a package in the SBOM.
type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	PackageFileName  string            `json:"packageFileName,omitempty"`
	Supplier         string            `json:"supplier,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string            `json:"licenseDeclared,omitempty"`
	CopyrightText    string            `json:"copyrightText,omitempty"`
	Description      string            `json:"description,omitempty"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

// spdxChecksum holds a package checksum.
type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// spdxExternalRef holds an external reference for a package.
type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// spdxRelation describes a relationship between SPDX elements.
type spdxRelation struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// ---------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------

// FormatSBOM produces an SPDX 2.3 JSON SBOM document from scan results.
// The SBOM includes the scanner itself as a package, Go module info,
// and any vendored dependencies detected from the build info.
func FormatSBOM(result *scanner.ScanResult, root, toolVersion string) ([]byte, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "aegisgate-scanner-sbom",
		DocumentNamespace: fmt.Sprintf("https://aegisgatesecurity.io/spdx/aegisgate-scanner-%s-%d", toolVersion, time.Now().Unix()),
		CreationInfo: spdxCreation{
			Created: now,
			Creators: []string{
				"Tool: aegisgate-scanner-" + toolVersion,
				"Organization: AegisGate Security",
			},
			LicenseListVer: "3.21",
		},
		Packages:      []spdxPackage{},
		Relationships: []spdxRelation{},
	}

	// Add scanner package.
	scannerPkg := spdxPackage{
		Name:             "aegisgate-scanner",
		SPDXID:           "SPDXRef-Package-aegisgate-scanner",
		VersionInfo:      toolVersion,
		Supplier:         "Organization: AegisGate Security",
		DownloadLocation: "https://github.com/aegisgatesecurity/aegisgate-scanner",
		FilesAnalyzed:    false,
		LicenseConcluded: "Apache-2.0",
		LicenseDeclared:  "Apache-2.0",
		CopyrightText:    "Copyright (c) AegisGate Security",
		Description:      "Antivirus for AI Artifacts — scans AI artifacts for security threats",
		ExternalRefs: []spdxExternalRef{
			{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  "pkg:github/aegisgatesecurity/aegisgate-scanner@" + toolVersion,
			},
		},
	}
	doc.Packages = append(doc.Packages, scannerPkg)

	// Add Go runtime info.
	goPkg := spdxPackage{
		Name:             "go-runtime",
		SPDXID:           "SPDXRef-Package-go-runtime",
		VersionInfo:      runtime.Version(),
		Supplier:         "Organization: Google LLC",
		DownloadLocation: "https://go.dev/dl/" + runtime.Version(),
		FilesAnalyzed:    false,
		LicenseConcluded: "BSD-3-Clause",
		LicenseDeclared:  "BSD-3-Clause",
		Description:      "Go programming language runtime",
	}
	doc.Packages = append(doc.Packages, goPkg)
	doc.Relationships = append(doc.Relationships, spdxRelation{
		SPDXElementID:      "SPDXRef-Package-aegisgate-scanner",
		RelationshipType:   "DEPENDS_ON",
		RelatedSPDXElement: "SPDXRef-Package-go-runtime",
	})

	// Add Go module dependencies from build info (if available).
	addModuleDependencies(&doc)

	// Add scanned artifacts as packages if we have findings context.
	if result != nil && result.Stats.FilesScanned > 0 {
		artifactsPkg := spdxPackage{
			Name:             "scanned-artifacts",
			SPDXID:           "SPDXRef-Package-scanned-artifacts",
			Supplier:         "Organization: AegisGate Security",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			Description:      fmt.Sprintf("Scanned artifacts at %s (%d files)", root, result.Stats.FilesScanned),
		}
		doc.Packages = append(doc.Packages, artifactsPkg)
		doc.Relationships = append(doc.Relationships, spdxRelation{
			SPDXElementID:      "SPDXRef-Package-aegisgate-scanner",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: "SPDXRef-Package-scanned-artifacts",
		})
	}

	return json.MarshalIndent(doc, "", "  ")
}

// addModuleDependencies reads Go build info and adds module dependencies
// as SPDX packages. In air-gapped environments with zero dependencies
// modules, this will typically only find the main module.
func addModuleDependencies(doc *spdxDocument) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	// Add main module.
	if info.Main.Path != "" {
		mainPkg := spdxPackage{
			Name:             info.Main.Path,
			SPDXID:           makeSPDXID(info.Main.Path),
			VersionInfo:      info.Main.Version,
			Supplier:         "Organization: AegisGate Security",
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "Apache-2.0",
			LicenseDeclared:  "Apache-2.0",
			Description:      "Main Go module for aegisgate-scanner",
		}
		if info.Main.Version == "" {
			mainPkg.VersionInfo = "(devel)"
		}
		doc.Packages = append(doc.Packages, mainPkg)
		doc.Relationships = append(doc.Relationships, spdxRelation{
			SPDXElementID:      "SPDXRef-Package-aegisgate-scanner",
			RelationshipType:   "CONTAINS",
			RelatedSPDXElement: mainPkg.SPDXID,
		})
	}

	// Add dependencies.
	for _, dep := range info.Deps {
		if dep.Path == "" {
			continue
		}
		depPkg := spdxPackage{
			Name:             dep.Path,
			SPDXID:           makeSPDXID(dep.Path),
			VersionInfo:      dep.Version,
			DownloadLocation: dep.Sum,
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			Description:      "Go module dependency",
		}
		if dep.Version == "" {
			depPkg.VersionInfo = "(devel)"
		}
		if dep.Replace != nil {
			depPkg.Name = dep.Replace.Path
			depPkg.SPDXID = makeSPDXID(dep.Replace.Path)
			depPkg.VersionInfo = dep.Replace.Version
		}
		doc.Packages = append(doc.Packages, depPkg)
		doc.Relationships = append(doc.Relationships, spdxRelation{
			SPDXElementID:      "SPDXRef-Package-aegisgate-scanner",
			RelationshipType:   "DEPENDS_ON",
			RelatedSPDXElement: depPkg.SPDXID,
		})
	}
}

// makeSPDXID creates a valid SPDX identifier from a module path.
func makeSPDXID(path string) string {
	// Replace non-alphanumeric characters with hyphens.
	id := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, path)
	return "SPDXRef-Package-" + id
}

// ---------------------------------------------------------------------
// Helper: detect go.mod presence
// ---------------------------------------------------------------------

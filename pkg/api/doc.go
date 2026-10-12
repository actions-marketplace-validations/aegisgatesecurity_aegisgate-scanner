// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Programmatic API / SDK
// =========================================================================
//
// Package api provides a clean, stable Go API for embedding the
// AegisGate Scanner into other applications and CI/CD pipelines.
//
// The API wraps the internal scanner package with a simplified
// interface suitable for programmatic use:
//
//   - NewScanner() — create a scanner with defaults
//   - NewScannerWithOptions() — create with custom configuration
//   - ScanPath() — scan a directory
//   - ScanContent() — scan raw content bytes
//   - ScanReader() — scan from an io.Reader
//   - ScanFiles() — scan specific file paths
//
// Example usage:
//
//	sc, err := api.NewScanner()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sc.Close()
//
//	result, err := sc.ScanPath("./rag-docs")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, finding := range result.Findings {
//	    fmt.Printf("%s:%d %s %s\n",
//	        finding.Artifact, finding.Line,
//	        finding.Severity, finding.Message)
//	}
//
// The API is designed to be stable across minor versions. Breaking
// changes will only occur in major version bumps.
//
// =========================================================================

package api

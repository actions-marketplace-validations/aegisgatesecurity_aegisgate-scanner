// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner - Pattern Pull from Platform
// =========================================================================
//
// Package patternpull implements opt-in pattern synchronization from the
// AegisGate Platform to the Scanner. It is fully air-gap compatible:
//
//   - If platform_url is empty, no pull occurs. The Scanner uses only its
//     bundled patterns and has full functionality without any network
//     connectivity.
//   - If platform_url is set, the Puller fetches canonical patterns from
//     the Platform's GET /api/v1/patterns/latest endpoint, converts them
//     to detectors.PatternDef, and registers them as custom patterns via
//     detectors.RegisterCustomPatterns.
//
// Bandwidth efficiency:
//   - Uses the If-Modified-Since header on subsequent requests. If the
//     Platform responds with 304 Not Modified, no patterns are
//     transferred and the existing patterns remain in use.
//
// Authentication:
//   - API key authentication is supported via the Authorization: Bearer
//     header. If no API key is configured, requests are sent without
//     authentication (for air-gapped / trusted-network deployments).
//
// =========================================================================
package patternpull

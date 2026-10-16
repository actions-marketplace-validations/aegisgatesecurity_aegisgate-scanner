// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Platform Forwarder
// =========================================================================
//
// Forwards scan detection metadata to AegisGate Platform for SIEM
// integration, attestation, and audit trail. Only metadata is sent —
// never matched text, PII values, or credentials.
//
// Privacy (non-negotiable):
//   - No matched text is sent — only detection metadata
//   - No PII values sent — only categories and rule names
//   - No credentials sent
//   - Platform forwarding is opt-in (requires AEGISGATE_PLATFORM_URL)
//   - Air-gap compatible — if URL is empty, forwarding is disabled
//
// Usage:
//
//	fwd := platformforward.New("https://platform.example.com/api/v1/telemetry", "api-key")
//	if fwd.Enabled() {
//	    fwd.ForwardFindings("path/to/file.go", findings)
//	}
//
// The forwarder converts scanner.Finding values into contracts.Event
// payloads (metadata-only) and sends them as an EventBatch to the
// Platform's /api/v1/telemetry endpoint.
//
// =========================================================================

package platformforward

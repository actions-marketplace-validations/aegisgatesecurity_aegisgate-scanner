module github.com/aegisgatesecurity/aegisgate-scanner

go 1.27.2

// External dependencies:
//   pkg/contracts — canonical event/pattern schema (type definitions only,
//   no runtime behavior). Used by pkg/platformforward to emit canonical events.
//
// All other third-party code is vendored into internal/ — see NOTICE for details.
// Runs air-gapped without network connectivity.
// CGO_ENABLED=1: full neural detection (ONNX Runtime vendored in lib/).
// CGO_ENABLED=0: heuristic-only fallback (no ONNX, pure Go).

replace github.com/aegisgatesecurity/aegisgate-platform => ../consolidated/aegisgate-platform

require github.com/aegisgatesecurity/aegisgate-platform v1.3.8 // indirect

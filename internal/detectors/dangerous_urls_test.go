package detectors

import "testing"

func TestDetectDangerousURLs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantRule string
	}{
		{"raw IP URL", "fetch('http://192.168.1.1:8080/api')", "dangerous_ip_address_url"},
		{"localhost URL", "requests.get('http://localhost:3000')", "dangerous_localhost_url"},
		{"non-standard port", "connect('https://api.example.com:8443')", "dangerous_internal_service_url"},
		{"websocket URL", "ws://evil.com/ws", "dangerous_websocket_url"},
		{"AWS endpoint", "https://mybucket.s3.amazonaws.com/data", "dangerous_aws_endpoint"},
		{"GCP endpoint", "https://myfunc.googleapis.com/v1", "dangerous_gcp_endpoint"},
		{"py b64decode", "base64.b64decode(payload)", "dangerous_py_b64decode"},
		{"js atob", "const decoded = atob(encoded)", "dangerous_js_atob"},
		{"b64 env var", "os.environ['TOKEN'] = 'SGVsbG8gV29ybGQgVGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgc3RyaW5nIGZvciB0ZXN0aW5n'", "dangerous_b64_env_var"},
		{"b64 eval chain", "eval(base64.b64decode('SGVsbG8gV29ybGQgVGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgc3RyaW5n'))", "dangerous_b64_eval_chain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectDangerousFunctions(tt.input)
			found := false
			for _, m := range matches {
				if m.Category == tt.wantRule {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected to find rule %s in input %q, got %d matches", tt.wantRule, tt.input, len(matches))
				for _, m := range matches {
					t.Logf("  found: %s", m.Category)
				}
			}
		})
	}
}

func TestDetectDangerousURLs_SafeCode(t *testing.T) {
	safe := []string{
		"const url = 'https://api.github.com/repos'", // standard https URL — will match dangerous_hardcoded_url_http but NOT the new patterns
		"print('hello world')",
		"const x = 1 + 2",
	}

	for _, code := range safe {
		matches := DetectDangerousFunctions(code)
		for _, m := range matches {
			// These safe inputs should NOT trigger the new URL/base64 patterns
			switch m.Category {
			case "dangerous_ip_address_url", "dangerous_localhost_url", "dangerous_websocket_url",
				"dangerous_aws_endpoint", "dangerous_gcp_endpoint",
				"dangerous_py_b64decode", "dangerous_js_atob", "dangerous_b64_eval_chain":
				t.Errorf("safe code triggered %s: %q", m.Category, code)
			}
		}
	}
}

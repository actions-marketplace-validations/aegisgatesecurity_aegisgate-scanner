// SPDX-License-Identifier: Apache-2.0
// AegisGate Scanner — Path Traversal Detector Tests
// ============================================================================
// Tests for path traversal and sensitive file access detection patterns.
// Contributed by: community discussion feedback (redbotster / 1claw)
// ============================================================================

package detectors

import (
	"testing"
)

func TestPathTraversal_DotDotSlash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"deep traversal", "../../../etc/shadow", true},
		{"two levels", "../../config/db.yml", true},
		{"single level", "../app/config.yml", true}, // single ../ is still traversal (medium)
		{"normal path", "/app/config/settings.json", false},
		{"tool call arg", "read_file('../../../../etc/passwd')", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestPathTraversal_EncodedVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"url-encoded", "%2e%2e/etc/shadow", true},
		{"url-encoded upper", "%2E%2E/etc/shadow", true},
		{"double-encoded", "%252e%252e/etc/shadow", true},
		{"encoded slash", "..%2fetc%2fshadow", true},
		{"normal url", "https://example.com/path", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestPathTraversal_BackslashVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"windows deep", "..\\..\\..\\windows\\system32", true},
		{"mixed sep", "../..\\etc\\shadow", true},
		{"normal windows", "C:\\Users\\app\\config.yml", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestPathTraversal_NullByte(t *testing.T) {
	matches := DetectPathTraversal("../../../etc/passwd%00.txt")
	if len(matches) == 0 {
		t.Error("Expected null byte traversal detection")
	}
}

func TestPathTraversal_FileURL(t *testing.T) {
	matches := DetectPathTraversal("file://../../../etc/shadow")
	if len(matches) == 0 {
		t.Error("Expected file:// traversal detection")
	}
}

func TestSensitiveFile_Shadow(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"absolute", "cat /etc/shadow", true},
		{"in command", "read('/etc/shadow')", true},
		{"traversal to", "../../../etc/shadow", true},
		{"not shadow", "/etc/shadow-utils/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestSensitiveFile_Proc(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"proc self", "cat /proc/self/environ", true},
		{"proc pid", "/proc/1234/cmdline", true},
		{"not proc", "/procurement/order.txt", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestSensitiveFile_SSHKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"id_rsa", "~/.ssh/id_rsa", true},
		{"ed25519", "/root/.ssh/id_ed25519", true},
		{"authorized_keys", "~/.ssh/authorized_keys", true},
		{"not ssh", "~/.sshrc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestSensitiveFile_CloudCreds(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"aws creds", "~/.aws/credentials", true},
		{"aws config", "/root/.aws/config", true},
		{"kube config", "~/.kube/config", true},
		{"gcp creds", "~/.config/gcloud/application_default_credentials.json", true},
		{"docker socket", "/var/run/docker.sock", true},
		{"not creds", "~/.aws-sdk/config", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestSensitiveFile_EnvFile(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"env file", "cat .env", true},
		{"env local", "read('.env.local')", true},
		{"env production", "/app/.env.production", true},
		{"not env file", "environment.yml", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectPathTraversal(tt.input)
			got := len(matches) > 0
			if got != tt.expected {
				t.Errorf("DetectPathTraversal(%q) = %v matches, expected %v", tt.input, len(matches), tt.expected)
			}
		})
	}
}

func TestPathTraversal_NoFalsePositives(t *testing.T) {
	benign := []string{
		"The application stores data in /app/data/",
		"Navigate to the parent directory using cd ..",
		"The documentation is in the docs directory",
		"Configuration files are stored in the config folder",
		"Normal sentence about environments",
		"Discuss the procurement process",
		"Use the AWS SDK to connect to S3",
		"The Kubernetes pod is running in the default namespace",
	}
	for _, input := range benign {
		matches := DetectPathTraversal(input)
		if len(matches) > 0 {
			t.Errorf("False positive on benign input %q: got %d matches", input, len(matches))
		}
	}
}

func TestPathTraversal_PatternCount(t *testing.T) {
	if len(PathTraversalPatterns) != 19 {
		t.Errorf("PathTraversalPatterns has %d patterns, expected 19", len(PathTraversalPatterns))
	}
}

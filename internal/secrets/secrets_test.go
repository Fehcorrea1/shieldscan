package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretsDetector(t *testing.T) {
	detector := NewDetector()
	
	tempDir := t.TempDir()

	t.Run("Detect high entropy API key", func(t *testing.T) {
		content := `
function connect() {
	const apiKey = "AKIAIOSFODNN7EXAMPLE"; // very secret
}
`
		filePath := filepath.Join(tempDir, "high_entropy.js")
		os.WriteFile(filePath, []byte(content), 0644)

		findings := detector.Scan(filePath)
		if len(findings) == 0 {
			t.Errorf("Expected to detect high entropy secret")
		}
	})

	t.Run("Ignore low entropy string", func(t *testing.T) {
		content := `
function connect() {
	const apiKey = "111111111111111111111111"; // low entropy
}
`
		filePath := filepath.Join(tempDir, "low_entropy.js")
		os.WriteFile(filePath, []byte(content), 0644)

		findings := detector.Scan(filePath)
		if len(findings) > 0 {
			t.Errorf("Expected to ignore low entropy string")
		}
	})

	t.Run("Ignore comments", func(t *testing.T) {
		content := `
// const aws_access_key = "AKIAIOSFODNN7EXAMPLE"
# token = "eW91ciBhdXRoZW50aWNhdGlvbiB0b2tlbiBoZXJl"
/* secret_key = "AKIAIOSFODNN7EXAMPLE" */
`
		filePath := filepath.Join(tempDir, "comments.js")
		os.WriteFile(filePath, []byte(content), 0644)

		findings := detector.Scan(filePath)
		if len(findings) > 0 {
			t.Errorf("Expected to ignore secrets in comments")
		}
	})
}

package secrets

import (
	"math"
	"os"
	"regexp"
	"strings"

	"shieldscan/internal/report"
)

type Detector struct {
	patterns []*regexp.Regexp
	minEntropy float64
	minLength int
}

func NewDetector() *Detector {
	return &Detector{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)`),
			regexp.MustCompile(`(?i)(secret[_-]?key|secretkey|private[_-]?key)`),
			regexp.MustCompile(`(?i)(password|passwd|pwd)`),
			regexp.MustCompile(`(?i)(token|auth[_-]?token|access[_-]?token)`),
			regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key|aws[_-]?secret)`),
			regexp.MustCompile(`(?i)(bearer\s+[a-zA-Z0-9\-_\.]+)`),
			regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
		},
		minEntropy: 4.5,
		minLength:  20,
	}
}

func (d *Detector) Scan(filePath string) []report.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var findings []report.Finding
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/*") {
			continue
		}

		if d.matchesPattern(line) && len(line) >= d.minLength {
			entropy := calculateEntropy(line)
			if entropy > d.minEntropy {
				findings = append(findings, report.Finding{
					ID:          "SS-SEC-001",
					Name:        "Potential Hardcoded Secret",
					Severity:    "HIGH",
					Confidence:  0.8,
					File:        filePath,
					Line:        i + 1,
					Message:     "Potential hardcoded secret detected with high entropy",
					CodeSnippet: line[:min(80, len(line))] + "...",
					Remediation: "Remove hardcoded secrets. Use environment variables or a secrets manager.",
					CWEID:       "CWE-798",
				})
			}
		}
	}

	return findings
}

func (d *Detector) matchesPattern(line string) bool {
	for _, pattern := range d.patterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}



func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range freq {
		prob := count / length
		entropy -= prob * math.Log2(prob)
	}

	return entropy
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
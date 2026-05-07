package pkgvalidator

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"shieldscan/internal/report"
)

type Validator struct {
	cache       map[string]CacheEntry
	cacheMutex  sync.RWMutex
	cacheTTL    time.Duration
	httpClient  *http.Client
	maxWorkers  int
}

type CacheEntry struct {
	Exists  bool
	Checked time.Time
}

type PackageInfo struct {
	Name     string
	Language string
	Line     int
	File     string
}

func New() *Validator {
	return &Validator{
		cache:      make(map[string]CacheEntry),
		cacheTTL:   24 * time.Hour,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		maxWorkers: 10,
	}
}

func (v *Validator) ValidatePackages(packages []PackageInfo) []report.Finding {
	var findings []report.Finding

	jobs := make(chan PackageInfo, len(packages))
	results := make(chan report.Finding, len(packages))

	var wg sync.WaitGroup

	for i := 0; i < v.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				if finding := v.validateOne(pkg); finding != nil {
					results <- *finding
				}
			}
		}()
	}

	for _, pkg := range packages {
		jobs <- pkg
	}
	close(jobs)

	wg.Wait()
	close(results)

	for finding := range results {
		findings = append(findings, finding)
	}

	return findings
}

func (v *Validator) validateOne(pkg PackageInfo) *report.Finding {
	cacheKey := fmt.Sprintf("%s:%s", pkg.Language, pkg.Name)

	v.cacheMutex.RLock()
	if entry, exists := v.cache[cacheKey]; exists {
		if time.Since(entry.Checked) < v.cacheTTL {
			v.cacheMutex.RUnlock()
			if !entry.Exists {
				return v.createFinding(pkg, "cached")
			}
			return nil
		}
	}
	v.cacheMutex.RUnlock()

	var exists bool
	var err error

	switch pkg.Language {
	case "javascript":
		exists, err = v.validateNPM(pkg.Name)
	case "python":
		exists, err = v.validatePyPI(pkg.Name)
	case "go":
		exists, err = v.validateGo(pkg.Name)
	}

	if err != nil {
		return nil
	}

	v.cacheMutex.Lock()
	v.cache[cacheKey] = CacheEntry{
		Exists:  exists,
		Checked: time.Now(),
	}
	v.cacheMutex.Unlock()

	if !exists {
		return v.createFinding(pkg, "verified")
	}

	return nil
}

func (v *Validator) validateNPM(packageName string) (bool, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
	resp, err := v.httpClient.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

func (v *Validator) validatePyPI(packageName string) (bool, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", packageName)
	resp, err := v.httpClient.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

func (v *Validator) validateGo(modulePath string) (bool, error) {
	if !strings.Contains(modulePath, "/") {
		modulePath = "github.com/" + modulePath
	}

	url := fmt.Sprintf("https://proxy.golang.org/%s/@v/list", modulePath)
	resp, err := v.httpClient.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

func (v *Validator) createFinding(pkg PackageInfo, source string) *report.Finding {
	return &report.Finding{
		ID:         "SS-PKG-001",
		Name:       "Package Hallucination Detected",
		Severity:   "HIGH",
		Confidence: 1.0,
		File:       pkg.File,
		Line:       pkg.Line,
		Message:    fmt.Sprintf("Package '%s' not found in %s registry. This may indicate an LLM hallucination or typosquatting attack.",
			pkg.Name, getLanguageName(pkg.Language)),
		Remediation: "Verify the package name is correct. If legitimate, add to whitelist or check the source.",
		CWEID:       "CWE-155",
	}
}

func getLanguageName(lang string) string {
	switch lang {
	case "javascript":
		return "NPM"
	case "python":
		return "PyPI"
	case "go":
		return "Go"
	default:
		return lang
	}
}
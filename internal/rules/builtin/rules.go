package builtin

import (
	"shieldscan/internal/ast"
	"shieldscan/internal/report"
	"shieldscan/internal/rules/engine"
)

type DangerousFunctionRule struct{}

func (r *DangerousFunctionRule) ID() string              { return "SS-001" }
func (r *DangerousFunctionRule) Name() string            { return "Dangerous Function Usage" }
func (r *DangerousFunctionRule) Description() string     { return "Detects usage of eval() or exec() which allow arbitrary code execution" }
func (r *DangerousFunctionRule) Severity() string        { return "HIGH" }
func (r *DangerousFunctionRule) Confidence() float64     { return 0.9 }
func (r *DangerousFunctionRule) Check(node ast.Node, ctx *engine.Context) []report.Finding {
	if node.GetType() == "call_expression" {
		if contains(node.GetText(), "eval") || contains(node.GetText(), "exec") {
			return []report.Finding{
				{
					ID:            r.ID(),
					Name:          r.Name(),
					Severity:      r.Severity(),
					Confidence:    r.Confidence(),
					File:          ctx.FilePath,
					Line:          node.GetLine(),
					Message:       "Usage of dangerous function detected: " + node.GetText(),
					CodeSnippet:   node.GetText(),
					Remediation:   "Avoid using eval() or exec() with untrusted input",
					CWEID:         "CWE-95",
					OWASPCategory: "A03:2021-Injection",
				},
			}
		}
	}
	return nil
}

type DangerouslySetInnerHTMLRule struct{}

func (r *DangerouslySetInnerHTMLRule) ID() string          { return "SS-002" }
func (r *DangerouslySetInnerHTMLRule) Name() string        { return "Dangerously Set Inner HTML" }
func (r *DangerouslySetInnerHTMLRule) Description() string { return "Detects usage of dangerouslySetInnerHTML which can lead to XSS" }
func (r *DangerouslySetInnerHTMLRule) Severity() string    { return "HIGH" }
func (r *DangerouslySetInnerHTMLRule) Confidence() float64 { return 0.95 }
func (r *DangerouslySetInnerHTMLRule) Check(node ast.Node, ctx *engine.Context) []report.Finding {
	if node.GetType() == "dangerously_set_inner_html" {
		return []report.Finding{
			{
				ID:            r.ID(),
				Name:          r.Name(),
				Severity:      r.Severity(),
				Confidence:    r.Confidence(),
				File:          ctx.FilePath,
				Line:          node.GetLine(),
				Message:       "DangerouslySetInnerHTML detected - potential XSS vulnerability",
				CodeSnippet:   node.GetText(),
				Remediation:   "Sanitize input before using dangerouslySetInnerHTML",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
			},
		}
	}
	return nil
}

type InnerHTMLAssignmentRule struct{}

func (r *InnerHTMLAssignmentRule) ID() string          { return "SS-003" }
func (r *InnerHTMLAssignmentRule) Name() string        { return "Inner HTML Assignment" }
func (r *InnerHTMLAssignmentRule) Description() string { return "Detects direct innerHTML assignments which can lead to XSS" }
func (r *InnerHTMLAssignmentRule) Severity() string    { return "MEDIUM" }
func (r *InnerHTMLAssignmentRule) Confidence() float64 { return 0.85 }
func (r *InnerHTMLAssignmentRule) Check(node ast.Node, ctx *engine.Context) []report.Finding {
	if node.GetType() == "inner_html_assignment" {
		return []report.Finding{
			{
				ID:            r.ID(),
				Name:          r.Name(),
				Severity:      r.Severity(),
				Confidence:    r.Confidence(),
				File:          ctx.FilePath,
				Line:          node.GetLine(),
				Message:       "Direct innerHTML assignment detected - potential XSS",
				CodeSnippet:   node.GetText(),
				Remediation:   "Use textContent instead or sanitize input",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
			},
		}
	}
	return nil
}

type InsecureCORSRule struct{}

func (r *InsecureCORSRule) ID() string          { return "SS-004" }
func (r *InsecureCORSRule) Name() string        { return "Insecure CORS Configuration" }
func (r *InsecureCORSRule) Description() string { return "Detects overly permissive CORS settings" }
func (r *InsecureCORSRule) Severity() string    { return "MEDIUM" }
func (r *InsecureCORSRule) Confidence() float64 { return 0.9 }
func (r *InsecureCORSRule) Check(node ast.Node, ctx *engine.Context) []report.Finding {
	if node.GetType() == "insecure_cors" {
		return []report.Finding{
			{
				ID:            r.ID(),
				Name:          r.Name(),
				Severity:      r.Severity(),
				Confidence:    r.Confidence(),
				File:          ctx.FilePath,
				Line:          node.GetLine(),
				Message:       "Insecure CORS: Allow-All (* wildcard) detected",
				CodeSnippet:   node.GetText(),
				Remediation:   "Restrict CORS to specific trusted origins",
				CWEID:         "CWE-346",
				OWASPCategory: "A01:2021-Broken Access Control",
			},
		}
	}
	return nil
}

type UnsafeGoRule struct{}

func (r *UnsafeGoRule) ID() string          { return "SS-005" }
func (r *UnsafeGoRule) Name() string        { return "Unsafe Go Usage" }
func (r *UnsafeGoRule) Description() string { return "Detects usage of unsafe package in Go" }
func (r *UnsafeGoRule) Severity() string    { return "MEDIUM" }
func (r *UnsafeGoRule) Confidence() float64 { return 0.95 }
func (r *UnsafeGoRule) Check(node ast.Node, ctx *engine.Context) []report.Finding {
	if node.GetType() == "unsafe_usage" {
		return []report.Finding{
			{
				ID:            r.ID(),
				Name:          r.Name(),
				Severity:      r.Severity(),
				Confidence:    r.Confidence(),
				File:          ctx.FilePath,
				Line:          node.GetLine(),
				Message:       "Usage of unsafe package detected",
				CodeSnippet:   node.GetText(),
				Remediation:   "Avoid unsafe package unless absolutely necessary",
				CWEID:         "CWE-111",
				OWASPCategory: "A04:2021-Insecure Design",
			},
		}
	}
	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
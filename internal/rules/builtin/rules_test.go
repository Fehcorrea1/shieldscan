package builtin

import (
	"testing"

	"shieldscan/internal/ast"
	"shieldscan/internal/rules/engine"
)

func TestDangerousFunctionRule(t *testing.T) {
	rule := &DangerousFunctionRule{}
	ctx := &engine.Context{FilePath: "test.js"}

	t.Run("Detect eval", func(t *testing.T) {
		node := &ast.BasicNode{
			Type: "call_expression",
			Text: "eval('alert(1)')",
			Line: 1,
		}
		findings := rule.Check(node, ctx)
		if len(findings) == 0 {
			t.Errorf("Expected to find eval usage")
		}
	})

	t.Run("Safe call", func(t *testing.T) {
		node := &ast.BasicNode{
			Type: "call_expression",
			Text: "console.log('hello')",
			Line: 1,
		}
		findings := rule.Check(node, ctx)
		if len(findings) > 0 {
			t.Errorf("Expected no findings for safe call")
		}
	})
}

func TestDangerouslySetInnerHTMLRule(t *testing.T) {
	rule := &DangerouslySetInnerHTMLRule{}
	ctx := &engine.Context{FilePath: "test.jsx"}

	t.Run("Detect dangerouslySetInnerHTML", func(t *testing.T) {
		node := &ast.BasicNode{
			Type: "dangerously_set_inner_html",
			Text: "<div dangerouslySetInnerHTML={{ __html: data }} />",
			Line: 1,
		}
		findings := rule.Check(node, ctx)
		if len(findings) == 0 {
			t.Errorf("Expected to find dangerouslySetInnerHTML")
		}
	})
}

func TestUnsafeGoRule(t *testing.T) {
	rule := &UnsafeGoRule{}
	ctx := &engine.Context{FilePath: "test.go"}

	t.Run("Detect unsafe usage", func(t *testing.T) {
		node := &ast.BasicNode{
			Type: "unsafe_usage",
			Text: "unsafe.Pointer(&v)",
			Line: 1,
		}
		findings := rule.Check(node, ctx)
		if len(findings) == 0 {
			t.Errorf("Expected to find unsafe usage")
		}
	})
}

package engine

import (
	"shieldscan/internal/ast"
	"shieldscan/internal/report"
)

type Context struct {
	FilePath string
}

type Rule interface {
	ID() string
	Name() string
	Description() string
	Severity() string
	Confidence() float64
	Check(node ast.Node, ctx *Context) []report.Finding
}

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine {
	return &Engine{
		rules: []Rule{},
	}
}

func (e *Engine) Check(nodes []ast.Node, filePath string) []report.Finding {
	var findings []report.Finding
	ctx := &Context{FilePath: filePath}

	for _, root := range nodes {
		ast.Walk(root, func(node ast.Node) {
			for _, rule := range e.rules {
				result := rule.Check(node, ctx)
				findings = append(findings, result...)
			}
		})
	}

	return findings
}

func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}
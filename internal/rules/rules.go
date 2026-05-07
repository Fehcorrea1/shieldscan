package rules

import (
	"shieldscan/internal/rules/builtin"
	"shieldscan/internal/rules/engine"
)

// Engine é o tipo público para o rule engine
type Engine = engine.Engine

// NewEngine cria uma nova instância do rule engine
func NewEngine() *Engine {
	return engine.NewEngine()
}

// DangerousFunctionRule é uma regra para detectar funções perigosas
type DangerousFunctionRule = builtin.DangerousFunctionRule

// DangerouslySetInnerHTMLRule é uma regra para detectar dangerouslySetInnerHTML
type DangerouslySetInnerHTMLRule = builtin.DangerouslySetInnerHTMLRule

// InnerHTMLAssignmentRule é uma regra para detectar innerHTML assignment
type InnerHTMLAssignmentRule = builtin.InnerHTMLAssignmentRule

// InsecureCORSRule é uma regra para detectar CORS inseguro
type InsecureCORSRule = builtin.InsecureCORSRule

// UnsafeGoRule é uma regra para detectar uso unsafe em Go
type UnsafeGoRule = builtin.UnsafeGoRule
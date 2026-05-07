package orchestrator

import (
	"path/filepath"
	"strings"

	"shieldscan/internal/ast"
	"shieldscan/internal/parser"
	"shieldscan/internal/pkgvalidator"
	"shieldscan/internal/report"
	"shieldscan/internal/rules/builtin"
	"shieldscan/internal/rules/engine"
	"shieldscan/internal/secrets"
)

type ScanResult struct {
	FilesScanned int
	Findings     []report.Finding
	Duration     string
	Success      bool
}

type Orchestrator struct {
	Parser    *parser.Parser
	Engine    *engine.Engine
	Secrets   *secrets.Detector
	Reporter  *report.Reporter
	Validator *pkgvalidator.Validator
}

func New() *Orchestrator {
	eng := engine.NewEngine()
	eng.AddRule(&builtin.DangerousFunctionRule{})
	eng.AddRule(&builtin.DangerouslySetInnerHTMLRule{})
	eng.AddRule(&builtin.InnerHTMLAssignmentRule{})
	eng.AddRule(&builtin.InsecureCORSRule{})
	eng.AddRule(&builtin.UnsafeGoRule{})

	return &Orchestrator{
		Parser:    parser.New(),
		Engine:    eng,
		Secrets:   secrets.NewDetector(),
		Reporter:  report.New(),
		Validator: pkgvalidator.New(),
	}
}

func (o *Orchestrator) Run(path string) (*ScanResult, error) {
	result := &ScanResult{
		FilesScanned: 0,
		Findings:     []report.Finding{},
		Success:      true,
	}

	files, err := o.Parser.DiscoverFiles(path)
	if err != nil {
		return nil, err
	}

	result.FilesScanned = len(files)

	var allPackages []pkgvalidator.PackageInfo

	for _, file := range files {
		nodes, err := o.Parser.Parse(file)
		if err != nil {
			continue
		}

		findings := o.Engine.Check(nodes, file)
		result.Findings = append(result.Findings, findings...)

		for _, root := range nodes {
			ast.Walk(root, func(node ast.Node) {
				if node.GetType() == "import_statement" {
					lang := getLangFromExt(file)
					allPackages = append(allPackages, pkgvalidator.PackageInfo{
						Name:     node.GetText(),
						Language: lang,
						Line:     node.GetLine(),
						File:     file,
					})
				}
			})
		}

		secretFindings := o.Secrets.Scan(file)
		result.Findings = append(result.Findings, secretFindings...)
	}

	pkgFindings := o.Validator.ValidatePackages(allPackages)
	result.Findings = append(result.Findings, pkgFindings...)

	return result, nil
}

func getLangFromExt(file string) string {
	ext := strings.ToLower(filepath.Ext(file))
	switch ext {
	case ".js", ".jsx", ".ts", ".tsx":
		return "javascript"
	case ".py":
		return "python"
	case ".go":
		return "go"
	}
	return "unknown"
}
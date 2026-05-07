package parser

import (
	"os"
	"path/filepath"
	"strings"

	"shieldscan/internal/ast"
)

type Parser struct {
	supportedExtensions map[string]bool
	excludeDirs         map[string]bool
}

type ParseResult struct {
	FilePath string
	Nodes    []ast.Node
	Language string
}

func New() *Parser {
	return &Parser{
		supportedExtensions: map[string]bool{
			".js":  true,
			".ts":  true,
			".jsx": true,
			".tsx": true,
			".py":  true,
			".go":  true,
		},
		excludeDirs: map[string]bool{
			"node_modules": true,
			".git":         true,
			"vendor":       true,
			".venv":        true,
			"__pycache__":  true,
			".next":        true,
			"dist":         true,
			"build":        true,
		},
	}
}

func (p *Parser) DiscoverFiles(path string) ([]string, error) {
	var files []string

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if p.excludeDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(filePath))
		if p.supportedExtensions[ext] {
			files = append(files, filePath)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

func (p *Parser) Parse(filePath string) ([]ast.Node, error) {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".js", ".ts", ".jsx", ".tsx":
		return p.parseJS(filePath)
	case ".py":
		return p.parsePython(filePath)
	case ".go":
		return p.parseGo(filePath)
	}

	return nil, nil
}

func (p *Parser) parseJS(filePath string) ([]ast.Node, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var nodes []ast.Node

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "eval(") || strings.HasPrefix(line, "require(") {
			nodes = append(nodes, &ast.BasicNode{
				Type:   "call_expression",
				Text:   line,
				Line:   i + 1,
				Column: 0,
			})
		}
		if strings.Contains(line, "dangerouslySetInnerHTML") {
			nodes = append(nodes, &ast.BasicNode{
				Type:   "dangerously_set_inner_html",
				Text:   line,
				Line:   i + 1,
				Column: 0,
			})
		}
		if strings.Contains(line, ".innerHTML") {
			nodes = append(nodes, &ast.BasicNode{
				Type:   "inner_html_assignment",
				Text:   line,
				Line:   i + 1,
				Column: 0,
			})
		}
		if strings.Contains(line, "Access-Control-Allow-Origin") && strings.Contains(line, "*") {
			nodes = append(nodes, &ast.BasicNode{
				Type:   "insecure_cors",
				Text:   line,
				Line:   i + 1,
				Column: 0,
			})
		}
		if strings.HasPrefix(line, "import ") {
			parts := strings.Split(line, " from ")
			if len(parts) == 2 {
				pkg := strings.Trim(parts[1], "';\"")
				nodes = append(nodes, &ast.BasicNode{
					Type:   "import_statement",
					Text:   pkg,
					Line:   i + 1,
					Column: 0,
				})
			}
		} else if strings.Contains(line, "require(") {
			start := strings.Index(line, "require(") + 8
			end := strings.Index(line[start:], ")")
			if end != -1 {
				pkg := strings.Trim(line[start:start+end], "';\"")
				nodes = append(nodes, &ast.BasicNode{
					Type:   "import_statement",
					Text:   pkg,
					Line:   i + 1,
					Column: 0,
				})
			}
		}
	}

	return nodes, nil
}

func (p *Parser) parsePython(filePath string) ([]ast.Node, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var nodes []ast.Node

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "eval(") || strings.HasPrefix(line, "exec(") {
			nodes = append(nodes, &ast.BasicNode{
				Type:   "dangerous_function",
				Text:   line,
				Line:   i + 1,
				Column: 0,
			})
		}
		if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				var packageName string
				if parts[0] == "import" {
					packageName = parts[1]
				} else if len(parts) >= 3 && parts[1] != "import" {
					packageName = parts[1]
				}
				if packageName != "" {
					nodes = append(nodes, &ast.BasicNode{
						Type:   "import_statement",
						Text:   packageName,
						Line:   i + 1,
						Column: 0,
					})
				}
			}
		}
	}

	return nodes, nil
}

func (p *Parser) parseGo(filePath string) ([]ast.Node, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var nodes []ast.Node

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "unsafe.") {
			nodes = append(nodes, &ast.BasicNode{
				Type:   "unsafe_usage",
				Text:   line,
				Line:   i + 1,
				Column: 0,
			})
		}
		if strings.HasPrefix(line, "import ") && !strings.Contains(line, "import (") {
			pkg := strings.TrimSpace(strings.TrimPrefix(line, "import "))
			pkg = strings.Trim(pkg, "\";`")
			nodes = append(nodes, &ast.BasicNode{
				Type:   "import_statement",
				Text:   pkg,
				Line:   i + 1,
				Column: 0,
			})
		}
	}

	return nodes, nil
}
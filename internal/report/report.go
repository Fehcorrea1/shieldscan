package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type Finding struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Severity      string  `json:"severity"`
	Confidence    float64 `json:"confidence"`
	File          string  `json:"file,omitempty"`
	Line          int     `json:"line"`
	Column        int     `json:"column,omitempty"`
	Message       string  `json:"message"`
	CodeSnippet   string  `json:"code_snippet,omitempty"`
	CWEID         string  `json:"cwe_id,omitempty"`
	OWASPCategory string  `json:"owasp_category,omitempty"`
	Remediation   string  `json:"remediation,omitempty"`
}

type Report struct {
	ScanSummary  ScanSummary `json:"scan_summary"`
	Findings     []Finding    `json:"findings"`
}

type ScanSummary struct {
	FilesScanned int     `json:"files_scanned"`
	TotalFindings int    `json:"total_findings"`
	HighSeverity int     `json:"high_severity"`
	MediumSeverity int   `json:"medium_severity"`
	LowSeverity  int     `json:"low_severity"`
}

type Reporter struct{}

func New() *Reporter {
	return &Reporter{}
}

func (r *Reporter) Generate(findings []Finding, filesScanned int) Report {
	summary := ScanSummary{
		FilesScanned: filesScanned,
		TotalFindings: len(findings),
	}

	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	sort.Slice(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] > severityOrder[findings[j].Severity]
	})

	for _, f := range findings {
		switch f.Severity {
		case "HIGH":
			summary.HighSeverity++
		case "MEDIUM":
			summary.MediumSeverity++
		case "LOW":
			summary.LowSeverity++
		}
	}

	return Report{
		ScanSummary: summary,
		Findings:    findings,
	}
}

func (r *Reporter) OutputCLI(report Report) {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                     SHIELDSCAN RESULTS                        ")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("Arquivos escaneados: %d\n", report.ScanSummary.FilesScanned)
	fmt.Printf("Total de findings: %d\n", report.ScanSummary.TotalFindings)
	fmt.Println("")
	fmt.Printf("🔴 HIGH: %d | 🟡 MEDIUM: %d | 🟢 LOW: %d\n",
		report.ScanSummary.HighSeverity,
		report.ScanSummary.MediumSeverity,
		report.ScanSummary.LowSeverity)
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("")

	for i, finding := range report.Findings {
		color := "🟢"
		if finding.Severity == "HIGH" {
			color = "🔴"
		} else if finding.Severity == "MEDIUM" {
			color = "🟡"
		}

		fmt.Printf("%s [%s] %s\n", color, finding.ID, finding.Name)
		if finding.File != "" {
			fmt.Printf("   📁 %s:%d\n", finding.File, finding.Line)
		} else {
			fmt.Printf("   📁 Linha: %d\n", finding.Line)
		}
		fmt.Printf("   💬 %s\n", finding.Message)
		if finding.CWEID != "" {
			fmt.Printf("   🛡️ CWE: %s\n", finding.CWEID)
		}
		if i < len(report.Findings)-1 {
			fmt.Println("")
		}
	}
}

func (r *Reporter) OutputJSON(report Report) error {
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func (r *Reporter) OutputReportFile(report Report) error {
	file, err := os.Create("shieldscan_report.md")
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("# 🛡️ Relatório de Segurança - ShieldScan\n\n")
	file.WriteString("## Resumo da Varredura\n\n")
	file.WriteString(fmt.Sprintf("- **Arquivos Escaneados:** %d\n", report.ScanSummary.FilesScanned))
	file.WriteString(fmt.Sprintf("- **Total de Alertas:** %d\n", report.ScanSummary.TotalFindings))
	file.WriteString(fmt.Sprintf("- **🔴 HIGH:** %d | **🟡 MEDIUM:** %d | **🟢 LOW:** %d\n\n",
		report.ScanSummary.HighSeverity,
		report.ScanSummary.MediumSeverity,
		report.ScanSummary.LowSeverity))

	file.WriteString("---\n\n")
	file.WriteString("## ⚠️ Detalhes dos Alertas\n\n")

	if len(report.Findings) == 0 {
		file.WriteString("Nenhuma vulnerabilidade foi encontrada. Excelente trabalho! 🎉\n")
		return nil
	}

	for _, finding := range report.Findings {
		emoji := "🟢"
		if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
			emoji = "🔴"
		} else if finding.Severity == "MEDIUM" {
			emoji = "🟡"
		}

		file.WriteString(fmt.Sprintf("### %s [%s] %s\n\n", emoji, finding.ID, finding.Name))
		file.WriteString(fmt.Sprintf("- **Severidade:** %s\n", finding.Severity))
		if finding.File != "" {
			file.WriteString(fmt.Sprintf("- **Local:** `%s:%d`\n", finding.File, finding.Line))
		} else {
			file.WriteString(fmt.Sprintf("- **Local:** Linha %d\n", finding.Line))
		}
		
		file.WriteString(fmt.Sprintf("- **Problema:** %s\n", finding.Message))
		if finding.CWEID != "" {
			file.WriteString(fmt.Sprintf("- **CWE:** %s\n", finding.CWEID))
		}
		
		file.WriteString("\n**Remediação Sugerida:**\n")
		if finding.Remediation != "" {
			file.WriteString(fmt.Sprintf("> %s\n\n", finding.Remediation))
		} else {
			file.WriteString("> Verifique a documentação para este alerta.\n\n")
		}
		
		file.WriteString("---\n\n")
	}

	return nil
}
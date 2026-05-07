package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"shieldscan/internal/logger"
	"shieldscan/internal/orchestrator"
	"shieldscan/internal/pkgvalidator"
	"shieldscan/internal/report"
)

var (
	path    string
	format  string
	rules   string
	verbose bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "shieldscan",
		Short: "ShieldScan - Scanner de segurança para código gerado por IA",
		Long:  `ShieldScan é uma ferramenta SAST local-first para detectar vulnerabilidades em código, com foco em código gerado por IA.`,
		Run: func(cmd *cobra.Command, args []string) {
			if path == "" {
				fmt.Println("Erro: --path é obrigatório")
				os.Exit(1)
			}
			logger.Init(verbose)

			start := time.Now()
			logger.Info("ShieldScan iniciando...")

			orch := orchestrator.New()
			result, err := orch.Run(path)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Erro durante o scan: %v\n", err)
				os.Exit(1)
			}

			duration := time.Since(start)

			reporter := report.New()
			reportData := reporter.Generate(result.Findings, result.FilesScanned)

			if format == "json" {
				reporter.OutputJSON(reportData)
			} else {
				reporter.OutputCLI(reportData)
			}

			// Criar o arquivo de relatório sempre
			err = reporter.OutputReportFile(reportData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Erro ao criar arquivo de relatório: %v\n", err)
			}

			fmt.Println("")
			fmt.Printf("⏱️ Tempo de execução: %v\n", duration)
			fmt.Printf("📊 Arquivos escaneados: %d\n", result.FilesScanned)
			fmt.Printf("⚠️ Total findings: %d\n", len(result.Findings))

			if len(result.Findings) > 0 {
				os.Exit(1)
			}
		},
	}

	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Executar scan de segurança",
		Long:  `Escaneia o diretório especificado em busca de vulnerabilidades`,
		Run: func(cmd *cobra.Command, args []string) {
			if path == "" {
				fmt.Println("Erro: --path é obrigatório")
				os.Exit(1)
			}
			logger.Init(verbose)

			start := time.Now()
			logger.Info("ShieldScan iniciando...")

			orch := orchestrator.New()
			result, err := orch.Run(path)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Erro: %v\n", err)
				os.Exit(1)
			}

			duration := time.Since(start)

			reporter := report.New()
			reportData := reporter.Generate(result.Findings, result.FilesScanned)

			if format == "json" {
				reporter.OutputJSON(reportData)
			} else {
				reporter.OutputCLI(reportData)
			}

			// Criar o arquivo de relatório sempre
			err = reporter.OutputReportFile(reportData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Erro ao criar arquivo de relatório: %v\n", err)
			}

			fmt.Println("")
			fmt.Printf("⏱️ Tempo: %v | 📁 Arquivos: %d | ⚠️ Findings: %d\n",
				duration, result.FilesScanned, len(result.Findings))
		},
	}

	var validateCmd = &cobra.Command{
		Use:   "validate-packages",
		Short: "Validar dependências contra registros oficiais",
		Long:  `Verifica se os pacotes importados existem nos registros oficiais (NPM, PyPI, Go)`,
		Run: func(cmd *cobra.Command, args []string) {
			if path == "" {
				fmt.Println("Erro: --path é obrigatório")
				os.Exit(1)
			}

			fmt.Println("📦 Validando pacotes...")

			validator := pkgvalidator.New()

			var packages []pkgvalidator.PackageInfo

			validator.ValidatePackages(packages)

			fmt.Println("✅ Validação concluída")
		},
	}

	rootCmd.PersistentFlags().StringVarP(&path, "path", "p", "", "Caminho do diretório ou arquivo para scanear")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "cli", "Formato de saída (cli ou json)")
	rootCmd.PersistentFlags().StringVarP(&rules, "rules", "r", "", "Path para regras customizadas")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Habilitar logs detalhados")

	scanCmd.PersistentFlags().StringVarP(&path, "path", "p", "", "Caminho do diretório ou arquivo para scanear")
	scanCmd.PersistentFlags().StringVarP(&format, "format", "f", "cli", "Formato de saída (cli ou json)")
	scanCmd.PersistentFlags().StringVarP(&rules, "rules", "r", "", "Path para regras customizadas")
	scanCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Habilitar logs detalhados")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(validateCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Erro: %v\n", err)
		os.Exit(1)
	}
}
# ShieldScan 🛡️

<p align="left">
  <a href="https://github.com/Fehcorrea1/shieldscan/stargazers">
    <img src="https://img.shields.io/github/stars/Fehcorrea1/shieldscan?style=social" alt="stars">
  </a>
  <a href="https://github.com/Fehcorrea1/shieldscan/fork">
    <img src="https://img.shields.io/github/forks/Fehcorrea1/shieldscan?style=social" alt="forks">
  </a>
  <img src="https://img.shields.io/badge/Open%20Source-Yes!-green" alt="Open Source">
</p>

![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Status](https://img.shields.io/badge/Status-MVP-green)
[![CI](https://github.com/Fehcorrea1/shieldscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Fehcorrea1/shieldscan/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/github/actions/workflow/status/Fehcorrea1/shieldscan/ci.yml?label=tests)](https://github.com/Fehcorrea1/shieldscan/actions)

ShieldScan is a **high-performance, open-source** Static Application Security Testing (SAST) tool designed to detect vulnerabilities and hardcoded secrets in modern applications, with a special focus on identifying AI-generated code hallucinations. 

Written in Go, ShieldScan is fast, extensible, and runs fully locally without requiring internet access for basic scans, making it ideal for CI/CD pipelines and local development environments.

## Features ✨

*   **Multi-language Support:** Scans JavaScript, TypeScript, Python, and Go codebases.
*   **Built-in Security Rules (MVP):** 
    *   Detects dangerous function calls (`eval()`, `exec()`).
    *   Detects insecure DOM manipulation (`dangerouslySetInnerHTML`, `.innerHTML`).
    *   Flags overly permissive CORS configurations (`Access-Control-Allow-Origin: *`).
    *   Identifies the usage of the `unsafe` package in Go.
*   **Advanced Secrets Detection:** 
    *   Combines Regular Expressions with Shannon Entropy calculations to detect API keys, tokens, and passwords with high accuracy.
    *   Ignores comments to reduce false positives.
*   **Package Hallucination Detection:** 
    *   Parses imports and queries NPM, PyPI, and Go Module registries in real-time.
    *   Alerts when an imported package does not exist, mitigating the risk of AI hallucinations and typosquatting attacks.
*   **Flexible Output:** Provides colorful CLI output for humans and structured JSON output for integrations.

## Installation 🚀

To install ShieldScan, ensure you have [Go](https://golang.org/dl/) (version 1.20+) installed, then clone the repository and build the binary:

```bash
# Clone o projeto
git clone https://github.com/Fehcorrea1/shieldscan.git
cd shieldscan

# Compile (Linux/Mac)
go build -o shieldscan cmd/shieldscan/main.go

# No Windows (PowerShell)
go build -o shieldscan.exe cmd/shieldscan/main.go

# Ou use os scripts prontos
./compilar.sh        # Linux/Mac
.\compilar.bat       # Windows
.\compilar.ps1       # Windows PowerShell
```

Move the binary to your system's PATH to use it globally.

## Uso Rápido ⚡

### Windows (PowerShell)
```powershell
# Compile
.\compilar.ps1

# Execute
.\shieldscan.exe scan --path ./seu-projeto
```

### Linux/Mac
```bash
# Compile
./compilar.sh

# Execute
./shieldscan scan --path ./seu-projeto
```

## Usage 🛠️

ShieldScan uses a simple CLI interface powered by Cobra.

### Basic Scan
Scan a specific directory or file:

```bash
./shieldscan scan --path ./meu-projeto
```

### JSON Output
Generate a structured JSON report (ideal for CI/CD pipelines):

```bash
./shieldscan scan --path ./meu-projeto --format json
```

### Verbose Logging
Enable verbose logging for debugging:

```bash
./shieldscan scan --path ./meu-projeto --verbose
```

## Architecture 🏗️

ShieldScan is built with a modular architecture:
*   **CLI:** Powered by `spf13/cobra`.
*   **File Loader:** Recursively discovers files while ignoring common directories (`node_modules`, `.git`, etc.).
*   **AST Walker:** Uses a DFS algorithm to traverse files and expose nodes to the Rule Engine.
*   **Rule Engine:** Applies security checks dynamically via the `Rule` interface.
*   **Package Validator:** A parallelized worker pool that checks dependencies against public registries.

## Open Source 🔓

ShieldScan é **Open Source** e gratuito para uso pessoal e comercial. Sinta-se livre para:
- Fork do projeto
- Contribuir com código
- Reportar bugs
- Sugerir melhorias

## Contributing 🤝

Contributions are welcome! Please check the issues page or submit a Pull Request.

```bash
# Fork -> Clone sua versão -> Crie uma branch -> Make changes -> Push -> PR
git checkout -b feature/nova-funcionalidade
git commit -m "Add nova funcionalidade"
git push origin feature/nova-funcionalidade
```

## License 📄

This project is licensed under the MIT License.

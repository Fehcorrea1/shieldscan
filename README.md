# ShieldScan 🛡️

![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Status](https://img.shields.io/badge/Status-MVP-green)

ShieldScan is a high-performance, local-first Static Application Security Testing (SAST) tool designed to detect vulnerabilities and hardcoded secrets in modern applications, with a special focus on identifying AI-generated code hallucinations. 

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
git clone https://github.com/your-org/shieldscan.git
cd shieldscan
go build -o shieldscan cmd/shieldscan/main.go
```

Move the binary to your system's PATH to use it globally.

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

## Contributing 🤝

Contributions are welcome! Please check the issues page or submit a Pull Request.

## License 📄

This project is licensed under the MIT License.

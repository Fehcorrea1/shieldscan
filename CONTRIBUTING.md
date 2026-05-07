# Contributing to ShieldScan

Thank you for your interest in contributing to ShieldScan!

## How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/shieldscan.git
cd shieldscan

# Build the project
go build -o shieldscan ./cmd/shieldscan/main.go

# Run tests
go test ./...
```

## Code Style

- Follow standard Go conventions
- Run `go fmt` before committing
- Add tests for new features

## Reporting Issues

Use GitHub Issues to report bugs or request features.
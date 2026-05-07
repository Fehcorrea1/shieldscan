# Script PowerShell para compilar ShieldScan
Write-Host "===== COMPILANDO SHIELDSCAN =====" -ForegroundColor Green

# Verifica se o Go está no PATH
$goVersion = go version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Go nao encontrado no PATH. Tentando caminho padrao..." -ForegroundColor Yellow
    
    # Caminho padrao de instalacao do Go
    $goPath = "C:\Program Files\Go\bin\go.exe"
    
    if (Test-Path $goPath) {
        Write-Host "Go encontrado em: $goPath"
        $env:PATH = "C:\Program Files\Go\bin;" + $env:PATH
        $goVersion = go version
        Write-Host "Go version: $goVersion" -ForegroundColor Green
    } else {
        Write-Host "ERRO: Go nao encontrado! Instale o Go em: https://go.dev/dl/" -ForegroundColor Red
        Read-Host "Pressione Enter para sair"
        exit 1
    }
} else {
    Write-Host "Go encontrado: $goVersion" -ForegroundColor Green
}

Write-Host "Compilando ShieldScan..." -ForegroundColor Blue

try {
    go build -o shieldscan.exe .\cmd\shieldscan
    if ($LASTEXITCODE -eq 0) {
        Write-Host "" -ForegroundColor White
        Write-Host "===========================================" -ForegroundColor Green
        Write-Host "✅ SHIELDSCAN COMPILADO COM SUCESSO!" -ForegroundColor Green
        Write-Host "===========================================" -ForegroundColor Green
        Write-Host "" -ForegroundColor White
        Write-Host "Para rodar: shieldscan.exe scan --path ." -ForegroundColor Cyan
        Write-Host "Para ver ajuda: shieldscan.exe --help" -ForegroundColor Cyan
    } else {
        Write-Host "ERRO na compilacao!" -ForegroundColor Red
    }
} catch {
    Write-Host "ERRO na compilacao: $_" -ForegroundColor Red
}

Write-Host ""
Read-Host "Pressione Enter para sair"
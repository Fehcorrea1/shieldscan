@echo off
echo ===== COMPILANDO SHIELDSCAN =====
cd /d "%~dp0"

echo Verificando Go...
go version
if %errorlevel% neq 0 (
    echo ERRO: Go nao encontrado! Instale o Go em: https://go.dev/dl/
    pause
    exit /b 1
)

echo Compilando...
go build -o shieldscan.exe .\cmd\shieldscan

if %errorlevel% neq 0 (
    echo ERRO na compilacao!
    pause
    exit /b 1
)

echo.
echo ===========================================
echo ✅ SHIELDSCAN COMPILADO COM SUCESSO!
echo ===========================================
echo.
echo Para rodar: shieldscan.exe scan --path .
echo.
echo Para ver ajuda: shieldscan.exe --help
echo.

pause
@echo off
echo ===== COMPILANDO SHIELDSCAN COM CAMINHO COMPLETO =====
cd /d "%~dp0"

echo Caminho do Go: "C:\Program Files\go\bin\go.exe"
echo.

echo Baixando dependencias...
"C:\Program Files\Go\bin\go.exe" mod tidy

if %errorlevel% neq 0 (
    echo ERRO: Falha ao baixar dependencias!
    pause
    exit /b 1
)

echo Compilando...
"C:\Program Files\Go\bin\go.exe" build -o shieldscan.exe .\cmd\shieldscan

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
@echo off
setlocal enabledelayedexpansion
:: Use UTF-8 code page so Turkish output renders correctly
chcp 65001 >nul

echo ========================================
echo   GiH Sorgu - Derleme Betiği
echo ========================================
echo.

set BINARY_NAME=gih-sorgu

:: Get version info
for /f "tokens=*" %%i in ('git describe --tags --abbrev^=0 2^>nul') do set RAW_VERSION=%%i
if not defined RAW_VERSION (
    set VERSION=dev
) else (
    set VERSION=!RAW_VERSION:v=!
)

for /f "tokens=*" %%i in ('git rev-parse --short HEAD 2^>nul') do set COMMIT=%%i
if not defined COMMIT set COMMIT=local

for /f "tokens=*" %%i in ('powershell -command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ' -AsUTC"') do set BUILD_TIME=%%i
if not defined BUILD_TIME set BUILD_TIME=unknown

echo Sürüm: %VERSION%
echo Commit: %COMMIT%
echo Derleme Zamanı: %BUILD_TIME%
echo.

set LDFLAGS=-s -w -X main.Version=%VERSION% -X main.BuildCommit=%COMMIT% -X main.BuildTime=%BUILD_TIME%

if "%~1"=="" goto build-all
goto %~1

:build
    go build -ldflags "%LDFLAGS%" -o %BINARY_NAME%.exe .
    goto end

:build-all
    if not exist dist mkdir dist
    echo Tüm platformlar için derleniyor...
    echo.

    echo [1/6] Windows AMD64...
    set GOOS=windows& set GOARCH=amd64& go build -ldflags "%LDFLAGS%" -o dist\%BINARY_NAME%-windows-amd64.exe .

    echo [2/6] Windows ARM64...
    set GOOS=windows& set GOARCH=arm64& go build -ldflags "%LDFLAGS%" -o dist\%BINARY_NAME%-windows-arm64.exe .

    echo [3/6] Linux AMD64...
    set GOOS=linux& set GOARCH=amd64& go build -ldflags "%LDFLAGS%" -o dist\%BINARY_NAME%-linux-amd64 .

    echo [4/6] Linux ARM64...
    set GOOS=linux& set GOARCH=arm64& go build -ldflags "%LDFLAGS%" -o dist\%BINARY_NAME%-linux-arm64 .

    echo [5/6] macOS AMD64 (Intel)...
    set GOOS=darwin& set GOARCH=amd64& go build -ldflags "%LDFLAGS%" -o dist\%BINARY_NAME%-darwin-amd64 .

    echo [6/6] macOS ARM64 (Apple Silicon)...
    set GOOS=darwin& set GOARCH=arm64& go build -ldflags "%LDFLAGS%" -o dist\%BINARY_NAME%-darwin-arm64 .

    echo.
    echo ========================================
    echo   Derleme tamamlandı!
    echo ========================================
    echo.
    echo Çıktı dosyaları:
    dir /b dist\
    goto end

:clean
    if exist %BINARY_NAME%.exe del %BINARY_NAME%.exe
    if exist dist rmdir /s /q dist
    go clean
    goto end

:test
    go test ./...
    goto end

:test-race
    go test -race ./...
    goto end

:test-cover
    go test -cover ./...
    goto end

:test-verbose
    go test -v ./...
    goto end

:bench
    go test -bench=. -benchmem ./...
    goto end

:fmt
    go fmt ./...
    goto end

:vet
    go vet ./...
    goto end

:lint
    call :fmt
    call :vet
    goto end

:run
    call :build
    %BINARY_NAME%.exe
    goto end

:help
    echo Kullanılabilir komutlar:
    echo   build       - Geçerli platform için ikili dosya derle
    echo   build-all   - Tüm platformlar için çapraz derle (dist\)
    echo   clean       - Derleme çıktılarını temizle
    echo   test        - Tüm testleri çalıştır
    echo   test-race   - Testleri race dedektörü ile çalıştır
    echo   test-cover  - Testleri kapsam ölçümüyle çalıştır
    echo   test-verbose - Testleri ayrıntılı çalıştır
    echo   bench       - Benchmark'ları çalıştır
    echo   fmt         - Kodu biçimlendir
    echo   vet         - go vet çalıştır
    echo   lint        - fmt ve vet çalıştır
    echo   run         - Derle ve çalıştır
    goto end

:end
    endlocal

@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   GiH Sorgu - Build Script
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

echo Version: %VERSION%
echo Commit: %COMMIT%
echo Build Time: %BUILD_TIME%
echo.

set LDFLAGS=-s -w -X main.Version=%VERSION% -X main.BuildCommit=%COMMIT% -X main.BuildTime=%BUILD_TIME%

if "%~1"=="" goto build-all
goto %~1

:build
    go build -ldflags "%LDFLAGS%" -o %BINARY_NAME%.exe .
    goto end

:build-all
    if not exist dist mkdir dist
    echo Building for all platforms...
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
    echo   Build completed!
    echo ========================================
    echo.
    echo Output files:
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
    echo Available commands:
    echo   build       - Build binary for current platform
    echo   build-all   - Cross-compile for all platforms (dist\)
    echo   clean       - Remove build artifacts
    echo   test        - Run all tests
    echo   test-race   - Run tests with race detector
    echo   test-cover  - Run tests with coverage
    echo   test-verbose - Run tests verbosely
    echo   bench       - Run benchmarks
    echo   fmt         - Format code
    echo   vet         - Run go vet
    echo   lint        - Run fmt and vet
    echo   run         - Build and run
    goto end

:end
    endlocal

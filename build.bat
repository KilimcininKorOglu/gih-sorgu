@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   GIH Sorgu - Build Script (Windows)
echo ========================================
echo.

:: Get version from git tag
for /f "tokens=*" %%a in ('git describe --tags --abbrev^=0 2^>nul') do set VERSION=%%a
if "%VERSION%"=="" set VERSION=dev
set VERSION=%VERSION:v=%

:: Get commit hash
for /f "tokens=*" %%a in ('git rev-parse --short HEAD 2^>nul') do set COMMIT=%%a
if "%COMMIT%"=="" set COMMIT=local

:: Get build time
for /f "tokens=*" %%a in ('powershell -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'"') do set BUILD_TIME=%%a

echo Version: %VERSION%
echo Commit: %COMMIT%
echo Build Time: %BUILD_TIME%
echo.

set LDFLAGS=-s -w -X main.Version=%VERSION% -X main.BuildCommit=%COMMIT% -X main.BuildTime=%BUILD_TIME%

:: Create dist directory
if not exist dist mkdir dist

echo Building for all platforms...
echo.

:: Windows AMD64
echo [1/6] Windows AMD64...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o dist\gih-sorgu-windows-amd64.exe .
if %errorlevel% neq 0 goto :error

:: Windows ARM64
echo [2/6] Windows ARM64...
set GOOS=windows
set GOARCH=arm64
go build -ldflags="%LDFLAGS%" -o dist\gih-sorgu-windows-arm64.exe .
if %errorlevel% neq 0 goto :error

:: Linux AMD64
echo [3/6] Linux AMD64...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o dist\gih-sorgu-linux-amd64 .
if %errorlevel% neq 0 goto :error

:: Linux ARM64
echo [4/6] Linux ARM64...
set GOOS=linux
set GOARCH=arm64
go build -ldflags="%LDFLAGS%" -o dist\gih-sorgu-linux-arm64 .
if %errorlevel% neq 0 goto :error

:: macOS AMD64
echo [5/6] macOS AMD64 (Intel)...
set GOOS=darwin
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o dist\gih-sorgu-darwin-amd64 .
if %errorlevel% neq 0 goto :error

:: macOS ARM64
echo [6/6] macOS ARM64 (Apple Silicon)...
set GOOS=darwin
set GOARCH=arm64
go build -ldflags="%LDFLAGS%" -o dist\gih-sorgu-darwin-arm64 .
if %errorlevel% neq 0 goto :error

echo.
echo ========================================
echo   Build completed successfully!
echo ========================================
echo.
echo Output files:
dir /b dist
echo.
goto :end

:error
echo.
echo Build failed with error %errorlevel%
exit /b %errorlevel%

:end
endlocal

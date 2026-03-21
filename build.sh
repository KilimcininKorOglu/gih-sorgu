#!/bin/bash

echo "========================================"
echo "  GİH Sorgu - Build Script"
echo "========================================"
echo

# Get version from git tag or use dev
VERSION=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "local")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Version: $VERSION"
echo "Commit: $COMMIT"
echo "Build Time: $BUILD_TIME"
echo

LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildCommit=$COMMIT -X main.BuildTime=$BUILD_TIME"

# Create dist directory
mkdir -p dist

echo "Building for all platforms..."
echo

# Windows AMD64
echo "[1/6] Windows AMD64..."
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o dist/gih-sorgu-windows-amd64.exe . || exit 1

# Windows ARM64
echo "[2/6] Windows ARM64..."
GOOS=windows GOARCH=arm64 go build -ldflags="$LDFLAGS" -o dist/gih-sorgu-windows-arm64.exe . || exit 1

# Linux AMD64
echo "[3/6] Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o dist/gih-sorgu-linux-amd64 . || exit 1

# Linux ARM64
echo "[4/6] Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o dist/gih-sorgu-linux-arm64 . || exit 1

# macOS AMD64
echo "[5/6] macOS AMD64 (Intel)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -o dist/gih-sorgu-darwin-amd64 . || exit 1

# macOS ARM64
echo "[6/6] macOS ARM64 (Apple Silicon)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o dist/gih-sorgu-darwin-arm64 . || exit 1

# Create checksums
echo
echo "Creating checksums..."
cd dist
sha256sum * > checksums.txt 2>/dev/null || shasum -a 256 * > checksums.txt
cat checksums.txt
cd ..

echo
echo "========================================"
echo "  Build completed successfully!"
echo "========================================"
echo
echo "Output files:"
ls -lh dist/

# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-03-21

### Added
- Interactive TUI mode with Bubbletea (domain input, query history, scroll)
- CLI mode with single/multi domain query support
- JSON output format (`--json` flag)
- Domain list file support (`--liste` flag)
- Gemini API powered automatic CAPTCHA solving
- Query history persistence in `history.json` (max 100 items)
- CI workflow and cross-platform build scripts
- Custom `.env` file parser for configuration

### Fixed
- Replace number key history selection with tab cycling to allow digit input in domains
- Detect unparseable HTML responses as unknown status instead of false-accessible
- Show error when `--liste` is used without a filename
- Return appropriate exit codes for network (4) and API (5) errors
- Log saveHistory errors to stderr instead of silently discarding
- Drain response body in getSessionCookies for HTTP connection reuse
- SSL bypass scoped only to guvenlinet.org.tr
- Handle non-JSON Gemini API error responses
- Improve domain validation with IDN support
- Add bounds validation for GEMINI_MAX_TOKENS
- Use in-memory buffer for CAPTCHA instead of file
- Make rate limit delay configurable
- Implement semantic exit codes
- Add error handlers on response streams
- Align TUI elements and deduplicate history

### Changed
- Update build files (Makefile, build.bat, .goreleaser.yml) for gih-sorgu project
- Remove deprecated rand.Seed call (Go 1.24 auto-seeds)
- Remove unused style variables (bgColor, helpStyle, historyStyle)

# Changelog

All notable changes to this project will be documented in this file.

## [1.1.2] - 2026-07-27

### Changed
- Raise the Go build floor to 1.25.12 to clear called standard-library CVEs and track it from go.mod in the release workflow
- Annotate accepted gosec findings and Gemini error strings in place instead of altering behavior, and handle remaining unchecked error returns

## [1.1.1] - 2026-07-26

### Added
- Cancel an in-progress query with Esc to return to input (TUI)
- Show query duration in the history list (TUI)
- `--resume` batch mode with a checkpoint file to continue interrupted runs
- Case-insensitive domain deduplication before querying
- `[N/total]` progress indicator in batch mode
- Machine-readable error codes (`errorCode`) in JSON error output
- Log the resolved configuration and loaded `.env` path at batch startup
- Extract the matching CHANGELOG entry for the GitHub release body (CI)

### Fixed
- Return specific domain validation errors instead of a generic message
- Send a Turkish `Accept-Language` header and a shared header baseline for GIH requests
- Handle JSON marshal errors in the JSON output functions
- Preserve the original error when opening the domain list file
- Drain the response body on non-200 paths for HTTP connection reuse
- Add granular dial, TLS, and response-header timeouts
- Warn on malformed `.env` lines instead of silently skipping them
- Validate the `Content-Type` header in the query response
- Extend `GeminiError` to capture code, status, and details, and handle unmarshal failures
- Add a circuit breaker to stop the batch after consecutive Gemini failures
- Respect the `Retry-After` header on Gemini 429 responses
- Use exponential backoff with jitter and skip retries for non-retriable 401/403 errors
- Reject non-ASCII Unicode domain labels; preserve original CAPTCHA case
- Display the relative timestamp and `Mesaj` field in the TUI
- Count unparseable batch results as unknown in the summary
- Include retries in the measured query duration
- Maintain a backup of `history.json` and write it atomically with 0600 permissions
- Add TTL and proactive refresh to the session cookie cache
- Preserve cookie attributes and respect server-initiated deletions
- Strip the `export` prefix from `.env` keys
- Wrap response body reads with `io.LimitReader` to prevent OOM
- Handle SIGINT/SIGTERM for graceful batch shutdown with a partial summary
- Strip `x-goog-api-key` on cross-domain redirects and validate redirect target host
- Route diagnostic output to stderr in JSON mode
- Use case-insensitive comparison for `Content-Encoding`
- Limit the CAPTCHA `Accept` header to `image/jpeg` to match validation
- Remove the arbitrary length heuristic from `isCaptchaError`
- Translate network and user-facing errors to Turkish
- Fall back to the default `RATE_LIMIT_DELAY` when the env value is invalid
- Bump `golang.org/x/sys` to v0.44.0 (CVE-2026-39824) and pin GitHub Actions to full SHAs
- Release only on manual tag creation and gate build/release behind lint and test

### Changed
- Enforce English comments and Turkish user-facing output across Go and build scripts
- Adopt Go 1.25 idioms flagged by modernize (e.g. `max` builtin)
- Add `test-race`, `test-cover`, `test-verbose`, and `bench` targets to `build.bat`
- Align `.env.example` User-Agent with the Firefox default and document `USER_AGENT` in help
- Remove the unused `width` field from `TUIModel` and separate log routing from JSON mode
- Extract duplicated API key help into a shared function
- Remove the orphaned GoReleaser config
- Add unit tests for pure functions

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

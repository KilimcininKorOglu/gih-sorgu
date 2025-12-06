/**
 * Güvenli İnternet Hizmeti (GİH) Sorgu Tool v1.0.0
 * ==================================================
 * Queries domain blocking status on Turkey's Safe Internet Service.
 * Uses Gemini API for automatic CAPTCHA solving.
 *
 * Source: https://www.guvenlinet.org.tr/sorgula
 *
 * Usage:
 *   gih-sorgu <domain>                  Single domain query
 *   gih-sorgu --liste sites.txt         Query from file
 *   gih-sorgu --json <domain>           JSON output
 */

package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ============================================================================
// CONSTANTS
// ============================================================================

// Build info (set via ldflags at build time)
var (
	Version     = "dev"
	BuildCommit = "local"
	BuildTime   = "unknown"
)

// Exit codes
const (
	ExitSuccess      = 0
	ExitGeneralError = 1
	ExitInvalidArgs  = 2
	ExitConfigError  = 3
	ExitNetworkError = 4
	ExitAPIError     = 5
)

// Default values
const (
	DefaultGeminiModel    = "gemini-2.5-flash"
	DefaultMaxTokens      = 256
	DefaultUserAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
	DefaultRateLimitDelay = 500
	DefaultTimeout        = 30 * time.Second

	MaxRetries   = 3
	RetryDelay   = 1 * time.Second
	MaxTokensCap = 8192
	MaxRateLimit = 10000

	BaseURL     = "https://www.guvenlinet.org.tr"
	SorguPath   = "/ajax/sorgu/sorgula.php"
	CaptchaPath = "/captcha/get_captcha.php"
	RefererPath = "/sorgula"

	GeminiPrompt = `Read the CAPTCHA text. Reply with ONLY the characters (letters and numbers), nothing else. The CAPTCHA is usually 6 characters.`
)

// ============================================================================
// TYPES
// ============================================================================

// Config holds all configuration values
type Config struct {
	GeminiAPIKey    string
	GeminiModel     string
	GeminiMaxTokens int
	UserAgent       string
	RateLimitDelay  int
}

// QueryResult holds the result of a domain query
type QueryResult struct {
	Domain       string  `json:"domain"`
	AileProfili  string  `json:"aileProfili"`
	CocukProfili string  `json:"cocukProfili"`
	EngelliMi    bool    `json:"engelliMi"`
	Mesaj        *string `json:"mesaj,omitempty"`
	EngelTarihi  *string `json:"engelTarihi,omitempty"`
}

// CaptchaResult holds CAPTCHA download result
type CaptchaResult struct {
	Cookies     map[string]string
	ImageBuffer []byte
}

// CLIArgs holds parsed command line arguments
type CLIArgs struct {
	Domains     []string
	ListFile    string
	JSONOutput  bool
	ShowHelp    bool
	ShowVersion bool
}

// Gemini API types
type GeminiRequest struct {
	Contents         []GeminiContent        `json:"contents"`
	GenerationConfig GeminiGenerationConfig `json:"generationConfig"`
}

type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text       string            `json:"text,omitempty"`
	InlineData *GeminiInlineData `json:"inline_data,omitempty"`
}

type GeminiInlineData struct {
	MimeType string `json:"mime_type"`
	Data     string `json:"data"`
}

type GeminiGenerationConfig struct {
	Temperature     float64 `json:"temperature"`
	MaxOutputTokens int     `json:"maxOutputTokens"`
}

type GeminiResponse struct {
	Candidates     []GeminiCandidate     `json:"candidates"`
	PromptFeedback *GeminiPromptFeedback `json:"promptFeedback,omitempty"`
}

type GeminiCandidate struct {
	Content      GeminiContent `json:"content"`
	FinishReason string        `json:"finishReason"`
}

type GeminiPromptFeedback struct {
	BlockReason string `json:"blockReason,omitempty"`
}

type GeminiError struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// JSON output types
type JSONOutput struct {
	Timestamp              string  `json:"timestamp"`
	Status                 bool    `json:"status"`
	QueryDuration          *int64  `json:"queryDuration,omitempty"`
	QueryDurationFormatted *string `json:"queryDurationFormatted,omitempty"`
	Domain                 string  `json:"domain"`
	AileProfili            string  `json:"aileProfili"`
	CocukProfili           string  `json:"cocukProfili"`
	EngelliMi              bool    `json:"engelliMi"`
	Mesaj                  *string `json:"mesaj,omitempty"`
	EngelTarihi            *string `json:"engelTarihi,omitempty"`
}

type JSONErrorOutput struct {
	Timestamp string  `json:"timestamp"`
	Status    bool    `json:"status"`
	Domain    *string `json:"domain,omitempty"`
	Error     string  `json:"error"`
}

// ============================================================================
// GLOBAL STATE
// ============================================================================

var (
	jsonOutputMode bool

	// HTTP clients
	secureClient   *http.Client
	insecureClient *http.Client

	// Regex patterns for HTML parsing
	engelTarihiRegex  = regexp.MustCompile(`görüntülenememektedir\.\s*\((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\)`)
	errorMesajRegex   = regexp.MustCompile(`<div class="error">([^<]+)</div>`)
	successMesajRegex = regexp.MustCompile(`<div class="success">([^<]+)</div>`)
	profileImgRegex   = regexp.MustCompile(`(?s)<td[^>]*id="profile"[^>]*>.*?<img src="([^"]+)"[^>]*>.*?</td>`)
)

// ============================================================================
// TUI STYLES
// ============================================================================

var (
	// Colors
	primaryColor   = lipgloss.Color("#FF6B6B")
	secondaryColor = lipgloss.Color("#4ECDC4")
	successColor   = lipgloss.Color("#2ECC71")
	errorColor     = lipgloss.Color("#E74C3C")
	warningColor   = lipgloss.Color("#F39C12")
	mutedColor     = lipgloss.Color("#7F8C8D")
	bgColor        = lipgloss.Color("#1A1A2E")

	// Styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor).
			Padding(0, 2).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			MarginBottom(1)

	inputStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(secondaryColor).
			Padding(0, 1)

	resultBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(mutedColor).
			Padding(1, 2).
			MarginTop(1)

	blockedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(errorColor)

	accessibleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(successColor)

	statusStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Italic(true)

	helpStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			MarginTop(1)

	historyStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			PaddingLeft(2)

	errorMsgStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true)
)

// ============================================================================
// TUI MODEL
// ============================================================================

// TUIState represents the current state of the TUI
type TUIState int

const (
	stateInput TUIState = iota
	stateQuerying
	stateResult
	stateError
)

// HistoryItem represents a queried domain result
type HistoryItem struct {
	Domain       string       `json:"domain"`
	Result       *QueryResult `json:"result,omitempty"`
	DurationMs   int64        `json:"durationMs"`
	Error        string       `json:"error,omitempty"`
	Timestamp    time.Time    `json:"timestamp"`
	duration     time.Duration
}

// HistoryFile represents the history.json structure
type HistoryFile struct {
	Version string        `json:"version"`
	Updated time.Time     `json:"updated"`
	Items   []HistoryItem `json:"items"`
}

const historyFileName = "history.json"
const maxHistoryItems = 100

// loadHistory loads history from history.json
func loadHistory() []HistoryItem {
	data, err := os.ReadFile(historyFileName)
	if err != nil {
		return []HistoryItem{}
	}

	var hf HistoryFile
	if err := json.Unmarshal(data, &hf); err != nil {
		return []HistoryItem{}
	}

	// Convert DurationMs back to duration
	for i := range hf.Items {
		hf.Items[i].duration = time.Duration(hf.Items[i].DurationMs) * time.Millisecond
	}

	return hf.Items
}

// saveHistory saves history to history.json
func saveHistory(items []HistoryItem) error {
	// Limit history size
	if len(items) > maxHistoryItems {
		items = items[len(items)-maxHistoryItems:]
	}

	// Convert duration to DurationMs for JSON
	for i := range items {
		items[i].DurationMs = items[i].duration.Milliseconds()
	}

	hf := HistoryFile{
		Version: Version,
		Updated: time.Now(),
		Items:   items,
	}

	data, err := json.MarshalIndent(hf, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(historyFileName, data, 0644)
}

// TUIModel is the Bubbletea model for the TUI
type TUIModel struct {
	textInput     textinput.Model
	state         TUIState
	config        *Config
	currentQuery  string
	result        *QueryResult
	duration      time.Duration
	errorMsg      string
	history       []HistoryItem
	historyOffset int // Scroll offset for history view
	width         int
	height        int
	quitting      bool
}

// QueryMsg is sent when a query completes
type QueryMsg struct {
	Result   *QueryResult
	Duration time.Duration
	Error    error
}

// NewTUIModel creates a new TUI model
func NewTUIModel(cfg *Config) TUIModel {
	ti := textinput.New()
	ti.Placeholder = "örn: discord.com"
	ti.Focus()
	ti.CharLimit = 253
	ti.Width = 40
	ti.PromptStyle = lipgloss.NewStyle().Foreground(secondaryColor)
	ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))

	// Load existing history
	history := loadHistory()

	return TUIModel{
		textInput:     ti,
		state:         stateInput,
		config:        cfg,
		history:       history,
		historyOffset: 0,
		width:         80,
		height:        24,
	}
}

// getVisibleHistoryCount returns how many history items to show
func (m TUIModel) getVisibleHistoryCount() int {
	// Calculate available lines for history (screen height - header - input - help - margins)
	available := m.height - 10
	if available < 5 {
		available = 5
	}
	if available > 15 {
		available = 15
	}
	if available > len(m.history) {
		return len(m.history)
	}
	return available
}

// Init implements tea.Model
func (m TUIModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model
func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			if m.state == stateResult || m.state == stateError {
				// Go back to input
				m.state = stateInput
				m.textInput.SetValue("")
				m.textInput.Focus()
				return m, textinput.Blink
			}
			m.quitting = true
			return m, tea.Quit

		case "enter":
			if m.state == stateInput && m.textInput.Value() != "" {
				domain := strings.TrimSpace(m.textInput.Value())
				if isValidDomain(domain) {
					m.currentQuery = domain
					m.state = stateQuerying
					m.textInput.Blur()
					return m, m.queryDomain(domain)
				}
				m.errorMsg = "Geçersiz domain formatı"
				m.state = stateError
				return m, nil
			}
			if m.state == stateResult || m.state == stateError {
				// Go back to input
				m.state = stateInput
				m.textInput.SetValue("")
				m.textInput.Focus()
				return m, textinput.Blink
			}

		case "tab":
			// Cycle through history if available
			if m.state == stateInput && len(m.history) > 0 {
				// Set last queried domain
				m.textInput.SetValue(m.history[len(m.history)-1].Domain)
				m.textInput.CursorEnd()
			}

		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			// Select and query from history using number keys
			if m.state == stateInput && len(m.history) > 0 {
				idx, _ := strconv.Atoi(msg.String())
				idx-- // Convert 1-9 to 0-8

				// Calculate visible range
				visibleCount := m.getVisibleHistoryCount()
				start := len(m.history) - visibleCount - m.historyOffset
				if start < 0 {
					start = 0
				}

				// Check if index is valid
				actualIdx := start + idx
				if idx < visibleCount && actualIdx < len(m.history) {
					domain := m.history[actualIdx].Domain
					m.currentQuery = domain
					m.state = stateQuerying
					m.textInput.Blur()
					return m, m.queryDomain(domain)
				}
			}

		case "up", "k":
			// Scroll history up (show older items)
			if m.state == stateInput && len(m.history) > m.getVisibleHistoryCount() {
				maxOffset := len(m.history) - m.getVisibleHistoryCount()
				if m.historyOffset < maxOffset {
					m.historyOffset++
				}
			}

		case "down", "j":
			// Scroll history down (show newer items)
			if m.state == stateInput && m.historyOffset > 0 {
				m.historyOffset--
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case QueryMsg:
		if msg.Error != nil {
			m.errorMsg = msg.Error.Error()
			m.state = stateError
			m.history = append(m.history, HistoryItem{
				Domain:    m.currentQuery,
				Error:     m.errorMsg,
				Timestamp: time.Now(),
			})
		} else {
			m.result = msg.Result
			m.duration = msg.Duration
			m.state = stateResult
			m.history = append(m.history, HistoryItem{
				Domain:    m.currentQuery,
				Result:    msg.Result,
				duration:  msg.Duration,
				Timestamp: time.Now(),
			})
		}
		// Save history to file
		saveHistory(m.history)
		return m, nil
	}

	// Update text input
	if m.state == stateInput {
		m.textInput, cmd = m.textInput.Update(msg)
	}

	return m, cmd
}

// queryDomain performs the domain query asynchronously
func (m TUIModel) queryDomain(domain string) tea.Cmd {
	return func() tea.Msg {
		startTime := time.Now()
		var lastErr error

		for retry := 0; retry < MaxRetries; retry++ {
			// Get CAPTCHA
			captchaResult, err := getCaptcha(m.config, nil)
			if err != nil {
				lastErr = err
				if retry < MaxRetries-1 {
					time.Sleep(RetryDelay)
				}
				continue
			}

			// Solve CAPTCHA
			captchaCode, err := solveCaptchaWithGemini(captchaResult.ImageBuffer, m.config)
			if err != nil {
				lastErr = err
				if retry < MaxRetries-1 {
					time.Sleep(RetryDelay)
				}
				continue
			}

			// Query domain
			html, err := sorgulaSite(domain, captchaCode, captchaResult.Cookies, m.config)
			if err != nil {
				lastErr = err
				if retry < MaxRetries-1 {
					time.Sleep(RetryDelay)
				}
				continue
			}

			// Check for CAPTCHA error
			if isCaptchaError(html) {
				lastErr = fmt.Errorf("CAPTCHA kodu hatalı")
				if retry < MaxRetries-1 {
					time.Sleep(RetryDelay)
				}
				continue
			}

			// Success
			result := parseHTML(html, domain)
			return QueryMsg{
				Result:   result,
				Duration: time.Since(startTime),
			}
		}

		return QueryMsg{Error: lastErr}
	}
}

// View implements tea.Model
func (m TUIModel) View() string {
	if m.quitting {
		return "\n  👋 Görüşürüz!\n\n"
	}

	var s strings.Builder

	// Title
	s.WriteString("\n")
	s.WriteString(titleStyle.Render(" 🔍 GİH Sorgu "))
	s.WriteString("\n")
	s.WriteString(subtitleStyle.Render("Güvenli İnternet Hizmeti Sorgu Aracı"))
	s.WriteString("\n\n")

	switch m.state {
	case stateInput:
		s.WriteString("  Domain girin:\n")
		s.WriteString("  ")
		s.WriteString(inputStyle.Render(m.textInput.View()))
		s.WriteString("\n")

		// Show history
		if len(m.history) > 0 {
			s.WriteString("\n")
			visibleCount := m.getVisibleHistoryCount()
			canScrollUp := m.historyOffset < len(m.history)-visibleCount
			canScrollDown := m.historyOffset > 0

			// Header with scroll indicators
			scrollInfo := ""
			if len(m.history) > visibleCount {
				scrollInfo = fmt.Sprintf(" [%d/%d]", len(m.history)-m.historyOffset, len(m.history))
			}
			s.WriteString(historyStyle.Render(fmt.Sprintf("📜 Geçmiş%s:", scrollInfo)))
			s.WriteString("\n")

			// Show scroll up indicator
			if canScrollUp {
				s.WriteString(historyStyle.Render("     ▲ (↑ daha eski)"))
				s.WriteString("\n")
			}

			// Calculate visible range
			end := len(m.history) - m.historyOffset
			start := end - visibleCount
			if start < 0 {
				start = 0
			}

			// Show items with numbers
			num := 1
			for i := start; i < end; i++ {
				item := m.history[i]
				icon := "✅"
				if item.Error != "" {
					icon = "❌"
				} else if item.Result != nil && item.Result.EngelliMi {
					icon = "🚫"
				}
				s.WriteString(historyStyle.Render(fmt.Sprintf("  [%d] %s %s", num, icon, item.Domain)))
				s.WriteString("\n")
				num++
			}

			// Show scroll down indicator
			if canScrollDown {
				s.WriteString(historyStyle.Render("     ▼ (↓ daha yeni)"))
				s.WriteString("\n")
			}
		}

		s.WriteString("\n")
		s.WriteString(helpStyle.Render("  enter: sorgula • 1-9: geçmişten • ↑↓: kaydır • esc: çıkış"))

	case stateQuerying:
		s.WriteString("  ")
		s.WriteString(statusStyle.Render(fmt.Sprintf("⏳ %s sorgulanıyor...", m.currentQuery)))
		s.WriteString("\n\n")
		s.WriteString(helpStyle.Render("  Lütfen bekleyin..."))

	case stateResult:
		s.WriteString(m.renderResult())
		s.WriteString("\n")
		s.WriteString(helpStyle.Render("  enter: yeni sorgu • esc: çıkış"))

	case stateError:
		s.WriteString("  ")
		s.WriteString(errorMsgStyle.Render(fmt.Sprintf("❌ Hata: %s", m.errorMsg)))
		s.WriteString("\n\n")
		s.WriteString(helpStyle.Render("  enter: yeni sorgu • esc: çıkış"))
	}

	s.WriteString("\n")
	return s.String()
}

// renderResult renders the query result
func (m TUIModel) renderResult() string {
	if m.result == nil {
		return ""
	}

	var content strings.Builder

	// Domain header
	content.WriteString(fmt.Sprintf("📌 Domain: %s\n", m.result.Domain))
	content.WriteString(fmt.Sprintf("⏱️  Süre: %s\n\n", formatDuration(m.duration)))

	// Status
	if m.result.EngelliMi {
		content.WriteString(blockedStyle.Render("🚫 Durum: ENGELLİ"))
	} else {
		content.WriteString(accessibleStyle.Render("✅ Durum: ERİŞİLEBİLİR"))
	}
	content.WriteString("\n\n")

	// Profiles
	aileIcon := "✅"
	if m.result.AileProfili == "engelli" {
		aileIcon = "❌"
	}
	content.WriteString(fmt.Sprintf("👨‍👩‍👧 Aile Profili: %s %s\n", aileIcon, profilDurum(m.result.AileProfili)))

	cocukIcon := "✅"
	if m.result.CocukProfili == "engelli" {
		cocukIcon = "❌"
	}
	content.WriteString(fmt.Sprintf("👶 Çocuk Profili: %s %s\n", cocukIcon, profilDurum(m.result.CocukProfili)))

	// Block date
	if m.result.EngelTarihi != nil {
		content.WriteString(fmt.Sprintf("\n📅 Engel Tarihi: %s", *m.result.EngelTarihi))
	}

	return resultBoxStyle.Render(content.String())
}

// profilDurum converts profile status to Turkish
func profilDurum(status string) string {
	if status == "engelli" {
		return "Engelli"
	}
	return "Erişilebilir"
}

// runTUI starts the TUI application
func runTUI(cfg *Config) error {
	// Suppress logs in TUI mode
	jsonOutputMode = true

	model := NewTUIModel(cfg)
	p := tea.NewProgram(model, tea.WithAltScreen())

	_, err := p.Run()
	return err
}

// ============================================================================
// INITIALIZATION
// ============================================================================

func init() {
	rand.Seed(time.Now().UnixNano())

	// Secure HTTP client for Gemini API
	secureClient = &http.Client{
		Timeout: DefaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	// Insecure HTTP client for guvenlinet.org.tr (cert chain issues)
	insecureClient = &http.Client{
		Timeout: DefaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			// Preserve cookies across redirects
			if len(via) > 0 {
				for key, val := range via[len(via)-1].Header {
					if key == "Cookie" {
						req.Header[key] = val
					}
				}
			}
			return nil
		},
	}
}

// ============================================================================
// LOGGING
// ============================================================================

// log prints message only in non-JSON mode
func log(format string, args ...interface{}) {
	if !jsonOutputMode {
		fmt.Printf(format, args...)
	}
}

// logln prints message with newline only in non-JSON mode
func logln(msg string) {
	if !jsonOutputMode {
		fmt.Println(msg)
	}
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// clamp restricts value to [min, max] range
func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// minInt returns minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// formatDuration formats duration in human-readable form
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := d.Seconds() - float64(mins*60)
	return fmt.Sprintf("%dm %.1fs", mins, secs)
}

// ============================================================================
// .ENV FILE PARSER
// ============================================================================

// loadEnvFile loads environment variables from .env file
func loadEnvFile() error {
	envPath := filepath.Join(".", ".env")

	file, err := os.Open(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Silent fail if .env doesn't exist
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Find first = sign
		idx := strings.Index(line, "=")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Remove surrounding quotes
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		// Only set if not already defined (system env takes precedence)
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}

// loadConfig loads and validates configuration
func loadConfig() (*Config, error) {
	cfg := &Config{
		GeminiAPIKey: os.Getenv("GEMINI_API_KEY"),
		GeminiModel:  os.Getenv("GEMINI_MODEL"),
		UserAgent:    os.Getenv("USER_AGENT"),
	}

	// Set defaults
	if cfg.GeminiModel == "" {
		cfg.GeminiModel = DefaultGeminiModel
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}

	// Parse GEMINI_MAX_TOKENS
	if maxTokens := os.Getenv("GEMINI_MAX_TOKENS"); maxTokens != "" {
		if val, err := strconv.Atoi(maxTokens); err == nil {
			cfg.GeminiMaxTokens = clamp(val, 1, MaxTokensCap)
		}
	}
	if cfg.GeminiMaxTokens == 0 {
		cfg.GeminiMaxTokens = DefaultMaxTokens
	}

	// Parse RATE_LIMIT_DELAY
	if rateLimit := os.Getenv("RATE_LIMIT_DELAY"); rateLimit != "" {
		if val, err := strconv.Atoi(rateLimit); err == nil {
			cfg.RateLimitDelay = clamp(val, 0, MaxRateLimit)
		}
	}
	if cfg.RateLimitDelay == 0 && os.Getenv("RATE_LIMIT_DELAY") == "" {
		cfg.RateLimitDelay = DefaultRateLimitDelay
	}

	// Validation
	if cfg.GeminiAPIKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY is required")
	}

	return cfg, nil
}

// ============================================================================
// DOMAIN VALIDATION
// ============================================================================

// isValidDomain checks if a domain name is valid
func isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	d := strings.ToLower(strings.TrimSpace(domain))

	// Length check: 1-253 characters
	if len(d) == 0 || len(d) > 253 {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(d, ".") {
		return false
	}

	labels := strings.Split(d, ".")
	for _, label := range labels {
		// Each label: 1-63 characters
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		// Cannot start or end with hyphen
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		// Only alphanumeric and hyphen allowed
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
		}
	}

	// TLD validation
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}

	// TLD must be letters only (unless punycode xn--)
	if !strings.HasPrefix(tld, "xn--") {
		for _, r := range tld {
			if !unicode.IsLetter(r) {
				return false
			}
		}
	}

	return true
}

// ============================================================================
// COOKIE MANAGEMENT
// ============================================================================

// parseCookies extracts cookies from http.Cookie slice
func parseCookies(cookies []*http.Cookie) map[string]string {
	result := make(map[string]string)
	for _, c := range cookies {
		result[c.Name] = c.Value
	}
	return result
}

// cookiesToString converts cookie map to header string
func cookiesToString(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for k, v := range cookies {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, "; ")
}

// ============================================================================
// HTTP HELPERS
// ============================================================================

// setDefaultHeaders sets common headers for GIH requests
func setDefaultHeaders(req *http.Request, cfg *Config) {
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate") // No brotli in stdlib
	req.Header.Set("Origin", BaseURL)
	req.Header.Set("Referer", BaseURL+RefererPath)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
}

// decompressResponse decompresses response body based on encoding
func decompressResponse(body io.ReadCloser, encoding string) ([]byte, error) {
	defer body.Close()

	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	case "deflate":
		reader := flate.NewReader(body)
		defer reader.Close()
		return io.ReadAll(reader)
	default:
		return io.ReadAll(body)
	}
}

// ============================================================================
// SESSION AND CAPTCHA
// ============================================================================

// getSessionCookies gets session cookies from main page
func getSessionCookies(cfg *Config) (map[string]string, error) {
	logln("🔗 Session başlatılıyor...")

	req, err := http.NewRequest("GET", BaseURL+RefererPath, nil)
	if err != nil {
		return nil, err
	}
	setDefaultHeaders(req, cfg)

	resp, err := insecureClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("session request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("session failed: HTTP %d", resp.StatusCode)
	}

	cookies := parseCookies(resp.Cookies())
	log("✅ Session alındı: %d cookie\n", len(cookies))

	return cookies, nil
}

// getCaptcha downloads CAPTCHA image
func getCaptcha(cfg *Config, existingSession map[string]string) (*CaptchaResult, error) {
	session := existingSession
	var err error
	if session == nil {
		session, err = getSessionCookies(cfg)
		if err != nil {
			return nil, err
		}
	}

	// Build URL with random parameter
	captchaURL := fmt.Sprintf("%s%s?rnd=%f", BaseURL, CaptchaPath, rand.Float64())

	logln("📥 CAPTCHA indiriliyor...")

	req, err := http.NewRequest("GET", captchaURL, nil)
	if err != nil {
		return nil, err
	}

	// Set CAPTCHA-specific headers
	req.Header.Set("Accept", "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5")
	req.Header.Set("Accept-Encoding", "identity") // No compression for images
	req.Header.Set("Sec-Fetch-Dest", "image")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Referer", BaseURL+RefererPath)

	// Add cookies (CRITICAL: don't add empty Cookie header)
	cookieStr := cookiesToString(session)
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
	}

	resp, err := insecureClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CAPTCHA download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CAPTCHA download failed: HTTP %d", resp.StatusCode)
	}

	// Merge cookies
	newCookies := parseCookies(resp.Cookies())
	for k, v := range newCookies {
		session[k] = v
	}

	// Read image data
	imageData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Validate JPEG magic bytes (FF D8)
	if len(imageData) < 2 || imageData[0] != 0xFF || imageData[1] != 0xD8 {
		// Check for WAF block
		preview := string(imageData[:minInt(100, len(imageData))])
		if strings.Contains(preview, "Request Rejected") {
			return nil, fmt.Errorf("CAPTCHA request blocked by WAF - cookie issue")
		}
		return nil, fmt.Errorf("invalid CAPTCHA response: not a JPEG")
	}

	log("✅ CAPTCHA indirildi: %d bytes\n", len(imageData))

	return &CaptchaResult{
		Cookies:     session,
		ImageBuffer: imageData,
	}, nil
}

// ============================================================================
// GEMINI API
// ============================================================================

// solveCaptchaWithGemini sends CAPTCHA to Gemini API for solving
func solveCaptchaWithGemini(imageBuffer []byte, cfg *Config) (string, error) {
	logln("🤖 Gemini API ile CAPTCHA çözülüyor...")

	// Encode image to base64
	base64Image := base64.StdEncoding.EncodeToString(imageBuffer)

	// Build request
	reqBody := GeminiRequest{
		Contents: []GeminiContent{{
			Parts: []GeminiPart{
				{Text: GeminiPrompt},
				{InlineData: &GeminiInlineData{
					MimeType: "image/jpeg",
					Data:     base64Image,
				}},
			},
		}},
		GenerationConfig: GeminiGenerationConfig{
			Temperature:     0,
			MaxOutputTokens: cfg.GeminiMaxTokens,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	// Build URL
	apiURL := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent",
		cfg.GeminiModel,
	)

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", cfg.GeminiAPIKey)

	resp, err := secureClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Gemini API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		var geminiErr GeminiError
		json.Unmarshal(body, &geminiErr)

		switch resp.StatusCode {
		case 429:
			return "", fmt.Errorf("Gemini API kota aşıldı: %s", geminiErr.Error.Message)
		case 401, 403:
			return "", fmt.Errorf("Gemini API yetkilendirme hatası: %s", geminiErr.Error.Message)
		default:
			return "", fmt.Errorf("Gemini API hatası: HTTP %d - %s", resp.StatusCode, geminiErr.Error.Message)
		}
	}

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return "", fmt.Errorf("failed to parse Gemini response: %w", err)
	}

	// Check for safety filter
	if geminiResp.PromptFeedback != nil && geminiResp.PromptFeedback.BlockReason != "" {
		return "", fmt.Errorf("Gemini güvenlik filtresi: %s", geminiResp.PromptFeedback.BlockReason)
	}

	// Extract text
	if len(geminiResp.Candidates) == 0 {
		return "", fmt.Errorf("Gemini API boş yanıt döndü")
	}

	candidate := geminiResp.Candidates[0]
	if candidate.FinishReason != "" && candidate.FinishReason != "STOP" {
		return "", fmt.Errorf("Gemini yanıt tamamlanamadı: %s", candidate.FinishReason)
	}

	if len(candidate.Content.Parts) == 0 || candidate.Content.Parts[0].Text == "" {
		return "", fmt.Errorf("Gemini API metin yanıtı vermedi")
	}

	// Clean CAPTCHA code - only alphanumeric, lowercase
	text := candidate.Content.Parts[0].Text
	var captchaCode strings.Builder
	for _, r := range strings.ToLower(text) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			captchaCode.WriteRune(r)
		}
	}

	code := captchaCode.String()
	if len(code) < 4 || len(code) > 8 {
		return "", fmt.Errorf("geçersiz CAPTCHA çıktısı: %q -> %q (%d karakter)", text, code, len(code))
	}

	log("✅ CAPTCHA çözüldü: %s\n", code)
	return code, nil
}

// ============================================================================
// GIH QUERY
// ============================================================================

// sorgulaSite queries a domain on GIH
func sorgulaSite(domain, captchaCode string, cookies map[string]string, cfg *Config) (string, error) {
	log("\n🔍 Sorgulanıyor: %s\n", domain)

	// Build form data
	formData := url.Values{}
	formData.Set("domain_name", domain)
	formData.Set("security_code", captchaCode)

	req, err := http.NewRequest("POST", BaseURL+SorguPath, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", err
	}

	setDefaultHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	// Add cookies (CRITICAL: don't add empty Cookie header)
	cookieStr := cookiesToString(cookies)
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
	}

	resp, err := insecureClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("query failed: HTTP %d", resp.StatusCode)
	}

	// Decompress response
	encoding := resp.Header.Get("Content-Encoding")
	body, err := decompressResponse(resp.Body, encoding)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// isCaptchaError checks if response indicates CAPTCHA error
func isCaptchaError(html string) bool {
	return strings.Contains(html, "Güvenlik kodu hatalı") ||
		strings.Contains(html, "security code") ||
		strings.Contains(html, "Doğrulama kodu") ||
		strings.Contains(html, "Hatalı kod") ||
		(len(strings.TrimSpace(html)) < 50 && !strings.Contains(html, "tbl_sorgu"))
}

// ============================================================================
// HTML PARSING
// ============================================================================

// parseHTML extracts query result from HTML response
func parseHTML(html, domain string) *QueryResult {
	result := &QueryResult{
		Domain: domain,
	}

	// Check mixed status first (different family/child profiles in table)
	profiles := profileImgRegex.FindAllStringSubmatch(html, -1)
	if len(profiles) >= 2 {
		if strings.Contains(profiles[0][1], "error.png") {
			result.AileProfili = "engelli"
		} else {
			result.AileProfili = "erisim"
		}

		if strings.Contains(profiles[1][1], "error.png") {
			result.CocukProfili = "engelli"
		} else {
			result.CocukProfili = "erisim"
		}

		result.EngelliMi = result.AileProfili == "engelli" || result.CocukProfili == "engelli"

		// Extract date and message based on status
		if result.EngelliMi {
			if matches := engelTarihiRegex.FindStringSubmatch(html); len(matches) > 1 {
				result.EngelTarihi = &matches[1]
			}
			if matches := errorMesajRegex.FindStringSubmatch(html); len(matches) > 1 {
				msg := strings.TrimSpace(matches[1])
				result.Mesaj = &msg
			}
		} else {
			if matches := successMesajRegex.FindStringSubmatch(html); len(matches) > 1 {
				msg := strings.TrimSpace(matches[1])
				result.Mesaj = &msg
			}
		}
		return result
	}

	// Fallback: Check for blocked status (error.png)
	if strings.Contains(html, "error.png") {
		result.EngelliMi = true
		result.AileProfili = "engelli"
		result.CocukProfili = "engelli"

		// Extract block date
		if matches := engelTarihiRegex.FindStringSubmatch(html); len(matches) > 1 {
			result.EngelTarihi = &matches[1]
		}

		// Extract error message
		if matches := errorMesajRegex.FindStringSubmatch(html); len(matches) > 1 {
			msg := strings.TrimSpace(matches[1])
			result.Mesaj = &msg
		}
		return result
	}

	// Fallback: Check for accessible status (success.png or tbl_sorgu table)
	if strings.Contains(html, "success.png") || strings.Contains(html, "tbl_sorgu") {
		result.EngelliMi = false
		result.AileProfili = "erisim"
		result.CocukProfili = "erisim"

		// Extract success message
		if matches := successMesajRegex.FindStringSubmatch(html); len(matches) > 1 {
			msg := strings.TrimSpace(matches[1])
			result.Mesaj = &msg
		}
	}

	return result
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

// printResult prints result in text format
func printResult(result *QueryResult, duration time.Duration) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 60))
	fmt.Printf("📌 Domain: %s\n", result.Domain)
	if duration > 0 {
		fmt.Printf("⏱️  Sorgu Süresi: %s\n", formatDuration(duration))
	}
	fmt.Println(strings.Repeat("═", 60))

	if result.EngelliMi {
		fmt.Println("🚫 Durum: ENGELLİ")
		fmt.Println(strings.Repeat("─", 60))

		aileDurum := "✅ Erişilebilir"
		if result.AileProfili == "engelli" {
			aileDurum = "❌ Engelli"
		}
		fmt.Printf("👨‍👩‍👧 Aile Profili: %s\n", aileDurum)

		cocukDurum := "✅ Erişilebilir"
		if result.CocukProfili == "engelli" {
			cocukDurum = "❌ Engelli"
		}
		fmt.Printf("👶 Çocuk Profili: %s\n", cocukDurum)

		if result.EngelTarihi != nil {
			fmt.Printf("📅 Engel Tarihi: %s\n", *result.EngelTarihi)
		}
	} else {
		fmt.Println("✅ Durum: ERİŞİLEBİLİR")
		fmt.Println(strings.Repeat("─", 60))
		fmt.Println("👨‍👩‍👧 Aile Profili: ✅ Erişilebilir")
		fmt.Println("👶 Çocuk Profili: ✅ Erişilebilir")
	}

	if result.Mesaj != nil {
		fmt.Println(strings.Repeat("─", 60))
		fmt.Printf("📝 Mesaj: %s\n", *result.Mesaj)
	}

	fmt.Println(strings.Repeat("═", 60))
	fmt.Println()
}

// outputJSON outputs result in JSON format
func outputJSON(result *QueryResult, duration time.Duration) {
	durationMs := duration.Milliseconds()
	durationFormatted := formatDuration(duration)

	output := JSONOutput{
		Timestamp:              time.Now().UTC().Format(time.RFC3339),
		Status:                 true,
		QueryDuration:          &durationMs,
		QueryDurationFormatted: &durationFormatted,
		Domain:                 result.Domain,
		AileProfili:            result.AileProfili,
		CocukProfili:           result.CocukProfili,
		EngelliMi:              result.EngelliMi,
		Mesaj:                  result.Mesaj,
		EngelTarihi:            result.EngelTarihi,
	}

	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(jsonBytes))
}

// outputJSONError outputs error in JSON format
func outputJSONError(domain *string, message string) {
	output := JSONErrorOutput{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    false,
		Domain:    domain,
		Error:     message,
	}

	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(jsonBytes))
}

// ============================================================================
// CLI PARSING
// ============================================================================

// parseArgs parses command line arguments
func parseArgs() *CLIArgs {
	args := &CLIArgs{}
	osArgs := os.Args[1:]

	for i := 0; i < len(osArgs); i++ {
		arg := osArgs[i]

		switch arg {
		case "--help", "-h":
			args.ShowHelp = true
		case "--version", "-v":
			args.ShowVersion = true
		case "--json":
			args.JSONOutput = true
		case "--liste":
			if i+1 < len(osArgs) {
				args.ListFile = osArgs[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(arg, "--") {
				args.Domains = append(args.Domains, arg)
			}
		}
	}

	return args
}

// loadDomainsFromFile reads domains from a file
func loadDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("dosya bulunamadı: %s", filename)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}

	return domains, scanner.Err()
}

// showHelp displays help message
func showHelp() {
	fmt.Printf(`
╔════════════════════════════════════════════════════════════╗
║     Güvenli İnternet Hizmeti (GİH) Sorgu Aracı             ║
╚════════════════════════════════════════════════════════════╝

v%s

Kullanım:
  gih-sorgu                         İnteraktif TUI modu başlat
  gih-sorgu <domain>                Tek domain sorgula
  gih-sorgu [seçenekler] <domain>   Seçeneklerle sorgula

Seçenekler:
  --liste <dosya>     Dosyadan site listesi oku
  --json              JSON formatında çıktı
  --version, -v       Versiyon bilgisini göster
  --help, -h          Bu yardım mesajını göster

TUI Modu:
  Argümansız çalıştırıldığında interaktif arayüz açılır.
  - Domain girin ve Enter ile sorgulayın
  - Tab ile geçmiş sorguları görün
  - Esc ile çıkın

Örnekler:
  gih-sorgu                             # TUI modu
  gih-sorgu discord.com                 # Tek domain
  gih-sorgu discord.com twitter.com     # Çoklu domain
  gih-sorgu --liste sites.txt           # Dosyadan
  gih-sorgu --json twitter.com          # JSON çıktı

Ortam Değişkenleri (.env dosyası veya sistem ortamı):
  GEMINI_API_KEY      Google Gemini API anahtarı (ZORUNLU)
  GEMINI_MODEL        Gemini model adı (varsayılan: gemini-2.5-flash)
  GEMINI_MAX_TOKENS   Maksimum token sayısı (varsayılan: 256)
  RATE_LIMIT_DELAY    Sorgular arası bekleme ms (varsayılan: 500)

.env Dosyası Örneği:
  GEMINI_API_KEY=AIzaSy...your_api_key_here
  GEMINI_MODEL=gemini-2.5-flash

API Anahtarı Alma:
  https://aistudio.google.com/app/apikey

Kaynak:
  https://www.guvenlinet.org.tr/sorgula
`, Version)
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	// Load .env file
	if err := loadEnvFile(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  .env dosyası okunamadı: %s\n", err)
	}

	// Parse arguments
	args := parseArgs()

	// Handle --version
	if args.ShowVersion {
		fmt.Printf("Güvenli İnternet Sorgu Aracı v%s (%s)\n", Version, BuildCommit)
		if BuildTime != "unknown" {
			fmt.Printf("Build: %s\n", BuildTime)
		}
		return ExitSuccess
	}

	// Handle --help
	if args.ShowHelp {
		showHelp()
		return ExitSuccess
	}

	// No arguments = TUI mode
	if len(args.Domains) == 0 && args.ListFile == "" {
		// Load config for TUI
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %s\n", err)
			fmt.Println()
			fmt.Println("   Seçenek 1: .env dosyası oluşturun")
			fmt.Println("   GEMINI_API_KEY=your_api_key")
			fmt.Println()
			fmt.Println("   Seçenek 2: Ortam değişkeni ayarlayın")
			fmt.Println("   Windows: set GEMINI_API_KEY=your_api_key")
			fmt.Println("   Linux/Mac: export GEMINI_API_KEY=your_api_key")
			fmt.Println()
			fmt.Println("   API anahtarı almak için: https://aistudio.google.com/app/apikey")
			fmt.Println()
			fmt.Print("   Çıkmak için Enter'a basın...")
			bufio.NewReader(os.Stdin).ReadBytes('\n')
			return ExitConfigError
		}

		if err := runTUI(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "❌ TUI hatası: %s\n", err)
			fmt.Println()
			fmt.Print("Çıkmak için Enter'a basın...")
			bufio.NewReader(os.Stdin).ReadBytes('\n')
			return ExitGeneralError
		}
		return ExitSuccess
	}

	// Set JSON output mode
	jsonOutputMode = args.JSONOutput

	// Load domains from file if specified
	if args.ListFile != "" {
		fileDomains, err := loadDomainsFromFile(args.ListFile)
		if err != nil {
			if jsonOutputMode {
				outputJSONError(nil, err.Error())
			} else {
				fmt.Fprintf(os.Stderr, "❌ %s\n", err)
			}
			return ExitInvalidArgs
		}
		args.Domains = append(args.Domains, fileDomains...)
	}

	// Validate domains
	var validDomains []string
	for _, d := range args.Domains {
		if isValidDomain(d) {
			validDomains = append(validDomains, d)
		} else {
			if jsonOutputMode {
				log("Geçersiz domain atlandı: %s\n", d)
			} else {
				fmt.Fprintf(os.Stderr, "⚠️  Geçersiz domain atlandı: %s\n", d)
			}
		}
	}

	if len(validDomains) == 0 {
		if jsonOutputMode {
			outputJSONError(nil, "Geçerli domain bulunamadı")
		} else {
			fmt.Fprintln(os.Stderr, "❌ Geçerli domain bulunamadı!")
		}
		return ExitInvalidArgs
	}

	// Load config
	cfg, err := loadConfig()
	if err != nil {
		if jsonOutputMode {
			outputJSONError(nil, err.Error())
		} else {
			fmt.Fprintf(os.Stderr, "❌ %s\n", err)
			fmt.Println()
			fmt.Println("   Seçenek 1: .env dosyası oluşturun")
			fmt.Println("   GEMINI_API_KEY=your_api_key")
			fmt.Println()
			fmt.Println("   Seçenek 2: Ortam değişkeni ayarlayın")
			fmt.Println("   Windows: set GEMINI_API_KEY=your_api_key")
			fmt.Println("   Linux/Mac: export GEMINI_API_KEY=your_api_key")
			fmt.Println()
			fmt.Println("   API anahtarı almak için: https://aistudio.google.com/app/apikey")
		}
		return ExitConfigError
	}

	// Print header
	logln(`
╔════════════════════════════════════════════════════════════╗
║     Güvenli İnternet Hizmeti (GİH) Sorgu Aracı             ║
╚════════════════════════════════════════════════════════════╝
`)

	log("📋 Sorgulanacak %d site: %s\n", len(validDomains), strings.Join(validDomains, ", "))
	log("🤖 Model: %s\n\n", cfg.GeminiModel)

	// Query domains
	var results []*QueryResult
	var sharedSession map[string]string

	for i, domain := range validDomains {
		var result *QueryResult
		var queryDuration time.Duration
		var lastErr error

		for retry := 0; retry < MaxRetries; retry++ {
			startTime := time.Now()

			// Get CAPTCHA
			captchaResult, err := getCaptcha(cfg, sharedSession)
			if err != nil {
				lastErr = err
				if !jsonOutputMode {
					fmt.Fprintf(os.Stderr, "❌ CAPTCHA hatası: %s\n", err)
				}
				sharedSession = nil
				if retry < MaxRetries-1 {
					logln("🔄 Yeniden deneniyor...")
					time.Sleep(RetryDelay)
				}
				continue
			}
			sharedSession = captchaResult.Cookies

			// Solve CAPTCHA
			captchaCode, err := solveCaptchaWithGemini(captchaResult.ImageBuffer, cfg)
			if err != nil {
				lastErr = err
				if !jsonOutputMode {
					fmt.Fprintf(os.Stderr, "❌ CAPTCHA çözülemedi: %s\n", err)
				}
				if retry < MaxRetries-1 {
					log("🔄 Yeniden deneniyor (%d/%d)...\n", retry+1, MaxRetries)
					time.Sleep(RetryDelay)
				}
				continue
			}

			// Query domain
			html, err := sorgulaSite(domain, captchaCode, captchaResult.Cookies, cfg)
			if err != nil {
				lastErr = err
				if !jsonOutputMode {
					fmt.Fprintf(os.Stderr, "❌ Sorgu hatası: %s\n", err)
				}
				sharedSession = nil
				if retry < MaxRetries-1 {
					logln("🔄 Yeniden deneniyor...")
					time.Sleep(RetryDelay)
				}
				continue
			}

			// Check for CAPTCHA error
			if isCaptchaError(html) {
				lastErr = fmt.Errorf("CAPTCHA kodu hatalı")
				logln("⚠️  CAPTCHA kodu hatalı!")
				sharedSession = nil
				if retry < MaxRetries-1 {
					log("🔄 Yeni CAPTCHA ile deneniyor (%d/%d)...\n", retry+1, MaxRetries)
					time.Sleep(RetryDelay)
				}
				continue
			}

			// Success
			queryDuration = time.Since(startTime)
			result = parseHTML(html, domain)
			lastErr = nil
			break
		}

		// Handle result
		if result != nil {
			results = append(results, result)
			if jsonOutputMode {
				outputJSON(result, queryDuration)
			} else {
				printResult(result, queryDuration)
			}
		} else {
			if jsonOutputMode {
				outputJSONError(&domain, lastErr.Error())
			} else {
				fmt.Fprintf(os.Stderr, "❌ %s sorgulanırken hata: %s\n", domain, lastErr)
			}
		}

		// Rate limiting
		if i < len(validDomains)-1 && cfg.RateLimitDelay > 0 {
			time.Sleep(time.Duration(cfg.RateLimitDelay) * time.Millisecond)
		}
	}

	// Print summary for multiple domains
	if !jsonOutputMode && len(validDomains) > 1 {
		fmt.Println("\n📊 ÖZET")
		fmt.Println(strings.Repeat("═", 60))

		blocked := 0
		accessible := 0
		for _, r := range results {
			if r.EngelliMi {
				blocked++
			} else {
				accessible++
			}
		}
		failed := len(validDomains) - len(results)

		fmt.Printf("   🚫 Engelli: %d\n", blocked)
		fmt.Printf("   ✅ Erişilebilir: %d\n", accessible)
		if failed > 0 {
			fmt.Printf("   ❓ Hatalı: %d\n", failed)
		}
		fmt.Println(strings.Repeat("═", 60))
	}

	return ExitSuccess
}

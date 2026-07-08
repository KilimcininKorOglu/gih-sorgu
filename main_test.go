package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{name: "simple", domain: "example.com", want: true},
		{name: "subdomain", domain: "www.example.com.tr", want: true},
		{name: "punycode", domain: "xn--rnek-4qa.com", want: true},
		{name: "empty", domain: "", want: false},
		{name: "no dot", domain: "localhost", want: false},
		{name: "leading hyphen", domain: "-example.com", want: false},
		{name: "trailing hyphen", domain: "example-.com", want: false},
		{name: "short tld", domain: "example.c", want: false},
		{name: "numeric tld", domain: "example.123", want: false},
		{name: "underscore", domain: "bad_domain.com", want: false},
		{name: "empty label", domain: "example..com", want: false},
		{name: "too long label", domain: strings.Repeat("a", 64) + ".com", want: false},
		{name: "turkish chars", domain: "çalışma.com", want: false},
		{name: "german umlaut", domain: "münchen.de", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDomain(tt.domain); got != tt.want {
				t.Fatalf("isValidDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want CLIArgs
	}{
		{
			name: "domains and json",
			args: []string{"gih-sorgu", "--json", "example.com", "google.com"},
			want: CLIArgs{Domains: []string{"example.com", "google.com"}, JSONOutput: true},
		},
		{
			name: "list file",
			args: []string{"gih-sorgu", "--liste", "sites.txt"},
			want: CLIArgs{ListFile: "sites.txt"},
		},
		{
			name: "missing list file",
			args: []string{"gih-sorgu", "--liste"},
			want: CLIArgs{Error: "--liste seçeneği bir dosya adı gerektirir"},
		},
		{
			name: "help",
			args: []string{"gih-sorgu", "--help"},
			want: CLIArgs{ShowHelp: true},
		},
		{
			name: "version",
			args: []string{"gih-sorgu", "-v"},
			want: CLIArgs{ShowVersion: true},
		},
	}

	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			got := parseArgs()

			if strings.Join(got.Domains, ",") != strings.Join(tt.want.Domains, ",") {
				t.Fatalf("Domains = %#v, want %#v", got.Domains, tt.want.Domains)
			}
			if got.ListFile != tt.want.ListFile {
				t.Fatalf("ListFile = %q, want %q", got.ListFile, tt.want.ListFile)
			}
			if got.JSONOutput != tt.want.JSONOutput {
				t.Fatalf("JSONOutput = %v, want %v", got.JSONOutput, tt.want.JSONOutput)
			}
			if got.ShowHelp != tt.want.ShowHelp {
				t.Fatalf("ShowHelp = %v, want %v", got.ShowHelp, tt.want.ShowHelp)
			}
			if got.ShowVersion != tt.want.ShowVersion {
				t.Fatalf("ShowVersion = %v, want %v", got.ShowVersion, tt.want.ShowVersion)
			}
			if got.Error != tt.want.Error {
				t.Fatalf("Error = %q, want %q", got.Error, tt.want.Error)
			}
		})
	}
}

func TestLoadEnvFileAt(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := strings.Join([]string{
		"# ignored",
		"GIH_TEST_API_KEY=from-file",
		"GIH_TEST_QUOTED=\"quoted value\"",
		"GIH_TEST_EXISTING=from-file",
		"export GIH_TEST_EXPORT=export-value",
		"malformed",
		"",
	}, "\n")

	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	t.Setenv("GIH_TEST_API_KEY", "")
	t.Setenv("GIH_TEST_QUOTED", "")
	t.Setenv("GIH_TEST_EXISTING", "from-system")
	t.Setenv("GIH_TEST_EXPORT", "")

	if err := loadEnvFileAt(envPath); err != nil {
		t.Fatalf("loadEnvFileAt returned error: %v", err)
	}

	if got := os.Getenv("GIH_TEST_API_KEY"); got != "from-file" {
		t.Fatalf("GIH_TEST_API_KEY = %q, want from-file", got)
	}
	if got := os.Getenv("GIH_TEST_QUOTED"); got != "quoted value" {
		t.Fatalf("GIH_TEST_QUOTED = %q, want quoted value", got)
	}
	if got := os.Getenv("GIH_TEST_EXISTING"); got != "from-system" {
		t.Fatalf("GIH_TEST_EXISTING = %q, want from-system", got)
	}
	if got := os.Getenv("GIH_TEST_EXPORT"); got != "export-value" {
		t.Fatalf("GIH_TEST_EXPORT = %q, want export-value", got)
	}
}

func TestParseHTML(t *testing.T) {
	t.Run("blocked", func(t *testing.T) {
		html := `<div class="error">Bu alan adı aile ve çocuk profilinde görüntülenememektedir.</div>
			<img src="/assets/error.png">
			görüntülenememektedir. (2024-10-20 22:34:15)`

		got := parseHTML(html, "discord.com")
		if !got.Parsed || !got.EngelliMi {
			t.Fatalf("got Parsed=%v EngelliMi=%v, want blocked parsed result", got.Parsed, got.EngelliMi)
		}
		if got.EngelTarihi == nil || *got.EngelTarihi != "2024-10-20 22:34:15" {
			t.Fatalf("EngelTarihi = %#v, want 2024-10-20 22:34:15", got.EngelTarihi)
		}
		if got.Mesaj == nil || *got.Mesaj == "" {
			t.Fatalf("Mesaj was not parsed")
		}
	})

	t.Run("accessible", func(t *testing.T) {
		html := `<table id="tbl_sorgu"><tr><td><img src="/assets/success.png"></td></tr></table>
			<div class="success">Bu alan adı görüntülenebilir.</div>`

		got := parseHTML(html, "example.com")
		if !got.Parsed || got.EngelliMi {
			t.Fatalf("got Parsed=%v EngelliMi=%v, want accessible parsed result", got.Parsed, got.EngelliMi)
		}
		if got.AileProfili != "erisim" || got.CocukProfili != "erisim" {
			t.Fatalf("profiles = %q/%q, want erisim/erisim", got.AileProfili, got.CocukProfili)
		}
	})

	t.Run("mixed profiles", func(t *testing.T) {
		html := `<td id="profile"><img src="/assets/success.png"></td>
			<td id="profile"><img src="/assets/error.png"></td>
			<div class="error">Çocuk profilinde görüntülenememektedir.</div>`

		got := parseHTML(html, "example.com")
		if !got.Parsed || !got.EngelliMi {
			t.Fatalf("got Parsed=%v EngelliMi=%v, want mixed blocked result", got.Parsed, got.EngelliMi)
		}
		if got.AileProfili != "erisim" || got.CocukProfili != "engelli" {
			t.Fatalf("profiles = %q/%q, want erisim/engelli", got.AileProfili, got.CocukProfili)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		got := parseHTML("<html><body>unexpected response</body></html>", "example.com")
		if got.Parsed {
			t.Fatalf("Parsed = true, want false for unknown HTML")
		}
	})
}

func TestIsCaptchaError(t *testing.T) {
	if !isCaptchaError("Güvenlik kodu hatalı") {
		t.Fatalf("expected Turkish CAPTCHA error to be detected")
	}
	if isCaptchaError("short") {
		t.Fatalf("did not expect short response to be detected as CAPTCHA error")
	}
	if isCaptchaError(`<table id="tbl_sorgu"><tr><td>ok</td></tr></table>`) {
		t.Fatalf("did not expect result table to be detected as CAPTCHA error")
	}
}

func TestClamp(t *testing.T) {
	tests := []struct {
		name  string
		value int
		min   int
		max   int
		want  int
	}{
		{"within range", 5, 0, 10, 5},
		{"below min", -5, 0, 10, 0},
		{"above max", 15, 0, 10, 10},
		{"at min", 0, 0, 10, 0},
		{"at max", 10, 0, 10, 10},
		{"negative range", -5, -10, 0, -5},
		{"all equal", 5, 5, 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clamp(tt.value, tt.min, tt.max); got != tt.want {
				t.Fatalf("clamp(%d, %d, %d) = %d, want %d", tt.value, tt.min, tt.max, got, tt.want)
			}
		})
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{5, 10, 5},
		{10, 5, 5},
		{-5, 5, -5},
		{5, -5, -5},
		{0, 0, 0},
		{5, 5, 5},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := minInt(tt.a, tt.b); got != tt.want {
				t.Fatalf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{100 * time.Millisecond, "100ms"},
		{1 * time.Second, "1.00s"},
		{1500 * time.Millisecond, "1.50s"},
		{5 * time.Second, "5.00s"},
		{1 * time.Minute, "1m 0.0s"},
		{90 * time.Second, "1m 30.0s"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := formatDuration(tt.d); got != tt.want {
				t.Fatalf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestProfilDurum(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"erisim", "Erişilebilir"},
		{"engelli", "Engelli"},
		{"bilinmiyor", "Erişilebilir"},
		{"", "Erişilebilir"},
		{"unknown", "Erişilebilir"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := profilDurum(tt.status); got != tt.want {
				t.Fatalf("profilDurum(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestParseCookies(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "session", Value: "abc123"},
		{Name: "user", Value: "john"},
		{Name: "token", Value: "xyz"},
	}

	got := parseCookies(cookies)
	if got["session"] == nil || got["session"].Value != "abc123" {
		t.Fatalf("session = %v, want abc123", got["session"])
	}
	if got["user"] == nil || got["user"].Value != "john" {
		t.Fatalf("user = %v, want john", got["user"])
	}
	if got["token"] == nil || got["token"].Value != "xyz" {
		t.Fatalf("token = %v, want xyz", got["token"])
	}
}

func TestCookiesToString(t *testing.T) {
	cookies := map[string]*http.Cookie{
		"session": {Name: "session", Value: "abc123"},
		"user":    {Name: "user", Value: "john"},
	}

	got := cookiesToString(cookies)
	if !strings.Contains(got, "session=abc123") {
		t.Fatalf("missing session cookie in %q", got)
	}
	if !strings.Contains(got, "user=john") {
		t.Fatalf("missing user cookie in %q", got)
	}
}

func TestMergeCookies(t *testing.T) {
	existing := map[string]*http.Cookie{
		"session": {Name: "session", Value: "old"},
		"legacy":  {Name: "legacy", Value: "keep"},
	}
	incoming := []*http.Cookie{
		{Name: "session", Value: "new"},
		{Name: "deleted", Value: "", MaxAge: 0},
		{Name: "expired", Value: "", MaxAge: -1},
	}

	got := mergeCookies(existing, parseCookies(incoming))
	if got["session"] == nil || got["session"].Value != "new" {
		t.Fatalf("session not updated: %v", got["session"])
	}
	if got["legacy"] == nil || got["legacy"].Value != "keep" {
		t.Fatalf("legacy cookie missing: %v", got["legacy"])
	}
	if got["deleted"] != nil {
		t.Fatalf("deleted cookie should be removed: %v", got["deleted"])
	}
	if got["expired"] != nil {
		t.Fatalf("expired cookie should be removed: %v", got["expired"])
	}
}

func TestBatchProgress(t *testing.T) {
	dir := t.TempDir()
	progressFile := filepath.Join(dir, "progress.json")

	bp := &BatchProgress{
		Domains: []string{"example.com", "test.com"},
		Results: []*QueryResult{
			{Domain: "example.com", EngelliMi: false, Parsed: true, AileProfili: "erisim", CocukProfili: "erisim"},
			{Domain: "test.com", EngelliMi: true, Parsed: true, AileProfili: "engelli", CocukProfili: "engelli"},
		},
	}

	if err := saveBatchProgress(progressFile, bp); err != nil {
		t.Fatalf("saveBatchProgress error: %v", err)
	}

	loaded, err := loadBatchProgress(progressFile)
	if err != nil {
		t.Fatalf("loadBatchProgress error: %v", err)
	}

	if len(loaded.Domains) != 2 || loaded.Domains[0] != "example.com" {
		t.Fatalf("domains mismatch: %v", loaded.Domains)
	}
	if len(loaded.Results) != 2 || loaded.Results[0].Domain != "example.com" {
		t.Fatalf("results mismatch: %v", loaded.Results)
	}

	if progressFileName("sites.txt") != "sites.txt.progress.json" {
		t.Fatalf("unexpected progress file name: %s", progressFileName("sites.txt"))
	}
	if progressFileName("") != "gih-sorgu-progress.json" {
		t.Fatalf("unexpected default progress file name: %s", progressFileName(""))
	}
}

func TestDecompressResponse(t *testing.T) {
	t.Run("gzip", func(t *testing.T) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte("test data"))
		gz.Close()

		body := io.NopCloser(&buf)
		got, err := decompressResponse(body, "gzip")
		if err != nil {
			t.Fatalf("decompressResponse error: %v", err)
		}
		if string(got) != "test data" {
			t.Fatalf("got %q, want test data", string(got))
		}
	})

	t.Run("identity", func(t *testing.T) {
		body := io.NopCloser(bytes.NewReader([]byte("test data")))
		got, err := decompressResponse(body, "")
		if err != nil {
			t.Fatalf("decompressResponse error: %v", err)
		}
		if string(got) != "test data" {
			t.Fatalf("got %q, want test data", string(got))
		}
	})
}

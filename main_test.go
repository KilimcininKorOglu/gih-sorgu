package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		"malformed",
		"",
	}, "\n")

	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	t.Setenv("GIH_TEST_API_KEY", "")
	t.Setenv("GIH_TEST_QUOTED", "")
	t.Setenv("GIH_TEST_EXISTING", "from-system")

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
	if !isCaptchaError("short") {
		t.Fatalf("expected short non-result response to be detected")
	}
	if isCaptchaError(`<table id="tbl_sorgu"><tr><td>ok</td></tr></table>`) {
		t.Fatalf("did not expect result table to be detected as CAPTCHA error")
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("YKVAULT_TEST_CLI") == "1" {
		if filepath.Base(os.Args[0]) == "ykchalresp" {
			if err := os.WriteFile(os.Getenv("YKVAULT_TEST_CALL"), []byte(strings.Join(os.Args[1:], " ")), 0600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if os.Getenv("YKVAULT_TEST_HMAC_FAIL") == "true" {
				os.Exit(1)
			}
			if len(os.Args) != 4 || os.Args[1] != "-H" || (os.Args[2] != "-1" && os.Args[2] != "-2") || os.Args[3] != "token" {
				fmt.Fprintln(os.Stderr, "unexpected YubiKey arguments")
				os.Exit(1)
			}
			fmt.Print("test-hmac" + os.Args[2])
			os.Exit(0)
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSet(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	if err := os.Symlink(executable, filepath.Join(binDir, "ykchalresp")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("YKVAULT_TEST_CLI", "1")
	t.Setenv("YKVAULT_PRESERVE_NEWLINE", "")

	cases := []struct {
		name       string
		existing   string
		envSlot    string
		args       []string
		wantSlot   string
		wantError  string
		emptyInput bool
		failHMAC   bool
	}{
		{
			name: "create with default slot", args: []string{"set", "token"}, wantSlot: "2",
		},
		{
			name: "create with environment slot", envSlot: "1", args: []string{"set", "token"}, wantSlot: "1",
		},
		{
			name: "create with flag overriding environment", envSlot: "2", args: []string{"-slot", "1", "set", "token"}, wantSlot: "1",
		},
		{
			name: "force creates with default slot", args: []string{"set", "--force", "token"}, wantSlot: "2",
		},
		{
			name: "force creates with environment slot", envSlot: "1", args: []string{"set", "--force", "token"}, wantSlot: "1",
		},
		{
			name: "force creates with flag overriding environment", envSlot: "2", args: []string{"-slot=1", "set", "--force", "token"}, wantSlot: "1",
		},
		{
			name: "overwrite ignores default slot", existing: "token.ykv.slot1", args: []string{"set", "--force", "token"}, wantSlot: "1",
		},
		{
			name: "overwrite slot 1 ignores environment slot 2", existing: "token.ykv.slot1", envSlot: "2", args: []string{"set", "--force", "token"}, wantSlot: "1",
		},
		{
			name: "overwrite slot 2 ignores environment slot 1", existing: "token.ykv.slot2", envSlot: "1", args: []string{"set", "--force", "token"}, wantSlot: "2",
		},
		{
			name: "overwrite accepts matching flag", existing: "token.ykv.slot2", envSlot: "1", args: []string{"-slot", "2", "set", "--force", "token"}, wantSlot: "2",
		},
		{
			name: "overwrite rejects conflicting flag", existing: "token.ykv.slot2", envSlot: "2", args: []string{"-slot", "1", "set", "--force", "token"},
			wantError: "uses slot 2, but -slot 1 was requested; omit -slot to overwrite using slot 2",
		},
		{
			name: "overwrite rejects explicit default slot", existing: "token.ykv.slot1", args: []string{"-slot=2", "set", "--force", "token"},
			wantError: "uses slot 1, but -slot 2 was requested; omit -slot to overwrite using slot 1",
		},
		{
			name: "legacy overwrite preserves path and slot", existing: "token.ykv", envSlot: "1", args: []string{"set", "--force", "token"}, wantSlot: "2",
		},
		{
			name: "legacy overwrite accepts matching flag", existing: "token.ykv", envSlot: "1", args: []string{"-slot", "2", "set", "--force", "token"}, wantSlot: "2",
		},
		{
			name: "legacy overwrite rejects conflicting flag", existing: "token.ykv", args: []string{"-slot", "1", "set", "--force", "token"},
			wantError: "uses slot 2, but -slot 1 was requested; omit -slot to overwrite using slot 2",
		},
		{
			name: "existing secret requires force", existing: "token.ykv.slot1", envSlot: "2", args: []string{"set", "token"}, wantError: "already exists",
		},
		{
			name: "legacy secret requires force", existing: "token.ykv", args: []string{"set", "token"}, wantError: "already exists",
		},
		{
			name: "force false refuses overwrite", existing: "token.ykv.slot2", args: []string{"set", "--force=false", "token"}, wantError: "already exists",
		},
		{
			name: "empty input preserves existing secret", existing: "token.ykv.slot1", args: []string{"set", "--force", "token"}, wantError: "no value provided", emptyInput: true,
		},
		{
			name: "YubiKey failure preserves existing secret", existing: "token.ykv.slot1", args: []string{"set", "--force", "token"}, wantSlot: "1", wantError: "YubiKey challenge failed", failHMAC: true,
		},
		{
			name: "missing ID fails before input", args: []string{"set", "--force"}, wantError: "usage: set [--force] <id>",
		},
		{
			name: "misplaced force fails before input", args: []string{"set", "token", "--force"}, wantError: "usage: set [--force] <id>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			vaultDir := filepath.Join(dir, "vault")
			callPath := filepath.Join(dir, "hmac-call")
			t.Setenv("YKVAULT_DIR", vaultDir)
			t.Setenv("YKVAULT_SLOT", tc.envSlot)
			t.Setenv("YKVAULT_TEST_CALL", callPath)
			t.Setenv("YKVAULT_TEST_HMAC_FAIL", fmt.Sprint(tc.failHMAC))
			original := []byte("original ciphertext")
			if tc.existing != "" {
				if err := os.Mkdir(vaultDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(vaultDir, tc.existing), original, 0600); err != nil {
					t.Fatal(err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, tc.args...)
			earlyRejection := tc.wantError != "" && !tc.emptyInput && !tc.failHMAC
			if earlyRejection {
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				defer writer.Close()
				cmd.Stdin = reader
			} else if !tc.emptyInput {
				cmd.Stdin = strings.NewReader("replacement-value\n")
			}
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("command did not finish without stdin: %v\n%s", ctx.Err(), output)
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(string(output), tc.wantError) {
					t.Fatalf("want error containing %q, got %v\n%s", tc.wantError, err, output)
				}
			} else if err != nil {
				t.Fatalf("set failed: %v\n%s", err, output)
			}
			if earlyRejection && bytes.Contains(output, []byte("Enter your secret")) {
				t.Fatalf("prompted for stdin before rejecting command: %s", output)
			}

			call, err := os.ReadFile(callPath)
			if tc.wantError == "" || tc.failHMAC {
				wantCall := "-H -" + tc.wantSlot + " token"
				if err != nil || string(call) != wantCall {
					t.Fatalf("want YubiKey call %q, got %q: %v", wantCall, call, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("unexpected YubiKey call %q: %v", call, err)
			}

			entries, err := os.ReadDir(vaultDir)
			if tc.existing == "" && tc.wantError != "" {
				if !os.IsNotExist(err) || len(entries) != 0 {
					t.Fatalf("rejected command changed vault directory: %v, %v", entries, err)
				}
				return
			}
			wantFile := tc.existing
			if wantFile == "" {
				wantFile = "token.ykv.slot" + tc.wantSlot
			}
			if err != nil || len(entries) != 1 || entries[0].Name() != wantFile {
				t.Fatalf("want only %q in vault, got %v: %v", wantFile, entries, err)
			}
			path := filepath.Join(vaultDir, wantFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantError != "" {
				if !bytes.Equal(data, original) {
					t.Fatalf("rejected overwrite changed ciphertext: %q", data)
				}
				return
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("want file permissions 0600, got %04o", info.Mode().Perm())
			}
			ciphertext, err := base64.StdEncoding.DecodeString(string(data))
			if err != nil {
				t.Fatal(err)
			}
			key, iv := deriveKey("test-hmac-" + tc.wantSlot)
			plaintext, err := decryptAES(ciphertext, key, iv)
			if err != nil || string(plaintext) != "replacement-value" {
				t.Fatalf("want replacement value encrypted with slot %s, got %q: %v", tc.wantSlot, plaintext, err)
			}
			if !bytes.Contains(output, []byte("Stored: token (slot "+tc.wantSlot+")")) {
				t.Fatalf("missing success message with selected slot: %s", output)
			}
		})
	}
}

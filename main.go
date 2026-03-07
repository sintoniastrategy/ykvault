package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const encSuffix = ".ykv"

var slot string

func secretsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ykvault")
}

func secretPath(id string) string {
	return filepath.Join(secretsDir(), id+encSuffix)
}

func yubiKeyHMAC(id string) (string, error) {
	out, err := exec.Command("ykchalresp", "-H", "-"+slot, id).Output()
	if err != nil {
		return "", fmt.Errorf("YubiKey challenge failed")
	}
	return strings.TrimSpace(string(out)), nil
}

// deriveKey matches the shell script:
//
//	key = SHA256(hmac)          — 32 bytes
//	iv  = SHA256(hmac+"iv")[:16] — 16 bytes
func deriveKey(hmac string) (key, iv []byte) {
	k := sha256.Sum256([]byte(hmac))
	i := sha256.Sum256([]byte(hmac + "iv"))
	return k[:], i[:16]
}

func pkcs7Pad(data []byte) []byte {
	pad := aes.BlockSize - len(data)%aes.BlockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	n := len(data)
	if n == 0 || n%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid data length")
	}
	pad := int(data[n-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range data[n-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:n-pad], nil
}

func encryptAES(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return ct, nil
}

func decryptAES(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	pt := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ciphertext)
	return pkcs7Unpad(pt)
}

// base64Wrap encodes to base64 with 64-char line wraps (matches OpenSSL -base64).
func base64Wrap(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)
	var buf bytes.Buffer
	for i := 0; i < len(encoded); i += 64 {
		end := i + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func setSecret(id string) error {
	if id == "" {
		return fmt.Errorf("usage: set <id>")
	}
	path := secretPath(id)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("secret %q already exists; remove it first: rm %q", id, path)
	}

	fmt.Fprintf(os.Stderr, "Enter your secret %s (finish with ctrl-d):\n", id)
	value, err := io.ReadAll(os.Stdin)
	if err != nil || len(bytes.TrimSpace(value)) == 0 {
		return fmt.Errorf("no value provided")
	}

	fmt.Fprintf(os.Stderr, "Touch your YubiKey to set %s ...\n", id)
	hmac, err := yubiKeyHMAC(id)
	if err != nil {
		return err
	}
	key, iv := deriveKey(hmac)

	ct, err := encryptAES(value, key, iv)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(secretsDir(), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, base64Wrap(ct), 0600); err != nil {
		return err
	}
	fmt.Printf("Stored: %s\n", id)
	return nil
}

func getSecret(id string) error {
	if id == "" {
		return fmt.Errorf("usage: get <id>")
	}
	data, err := os.ReadFile(secretPath(id))
	if err != nil {
		return fmt.Errorf("secret not found: %s", id)
	}

	fmt.Fprintf(os.Stderr, "Touch your YubiKey to get %s ...\n", id)
	hmac, err := yubiKeyHMAC(id)
	if err != nil {
		return err
	}
	key, iv := deriveKey(hmac)

	cleaned := strings.ReplaceAll(string(data), "\n", "")
	ct, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return fmt.Errorf("invalid ciphertext: %w", err)
	}

	pt, err := decryptAES(ct, key, iv)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong key or corrupted data)")
	}
	os.Stdout.Write(pt)
	return nil
}

func renameSecret(oldID, newID string) error {
	if oldID == "" || newID == "" {
		return fmt.Errorf("usage: rename <old_id> <new_id>")
	}
	oldPath := secretPath(oldID)
	newPath := secretPath(newID)

	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return fmt.Errorf("secret not found: %s", oldID)
	}
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("secret %q already exists", newID)
	}

	// Decrypt with old ID (touch 1)
	data, err := os.ReadFile(oldPath)
	if err != nil {
		return fmt.Errorf("secret not found: %s", oldID)
	}

	fmt.Fprintf(os.Stderr, "Touch your YubiKey to decrypt %s ...\n", oldID)
	hmacOld, err := yubiKeyHMAC(oldID)
	if err != nil {
		return err
	}
	key, iv := deriveKey(hmacOld)

	cleaned := strings.ReplaceAll(string(data), "\n", "")
	ct, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return fmt.Errorf("invalid ciphertext: %w", err)
	}
	pt, err := decryptAES(ct, key, iv)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong key or corrupted data)")
	}

	// Re-encrypt with new ID (touch 2)
	fmt.Fprintf(os.Stderr, "Touch your YubiKey to encrypt as %s ...\n", newID)
	hmacNew, err := yubiKeyHMAC(newID)
	if err != nil {
		return err
	}
	keyNew, ivNew := deriveKey(hmacNew)

	ct2, err := encryptAES(pt, keyNew, ivNew)
	if err != nil {
		return err
	}

	if err := os.WriteFile(newPath, base64Wrap(ct2), 0600); err != nil {
		return err
	}

	if err := os.Remove(oldPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("failed to remove old secret: %w", err)
	}

	fmt.Printf("Renamed: %s -> %s\n", oldID, newID)
	return nil
}

func listSecrets() error {
	entries, err := os.ReadDir(secretsDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if name := e.Name(); strings.HasSuffix(name, encSuffix) {
			fmt.Println(strings.TrimSuffix(name, encSuffix))
		}
	}
	return nil
}

func usage() {
	name := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s [-slot N] {set <id> | get <id> | rename <old_id> <new_id> | list}\n", name)
	fmt.Fprintf(os.Stderr, "  set: reads value from stdin\n")
	fmt.Fprintf(os.Stderr, "       echo 'mysecret' | %s set myid\n", name)
	fmt.Fprintf(os.Stderr, "  env: YKVAULT_SLOT=1 to set default slot\n")
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func main() {
	defaultSlot := "2"
	if env := os.Getenv("YKVAULT_SLOT"); env != "" {
		defaultSlot = env
	}
	flag.StringVar(&slot, "slot", defaultSlot, "YubiKey slot (env: YKVAULT_SLOT)")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}

	var err error
	switch args[0] {
	case "set":
		err = setSecret(arg(args, 1))
	case "get":
		err = getSecret(arg(args, 1))
	case "rename":
		err = renameSecret(arg(args, 1), arg(args, 2))
	case "list":
		err = listSecrets()
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

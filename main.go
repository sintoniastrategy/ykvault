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
	"sort"
	"strings"
)

const legacySuffix = ".ykv" // compat: old files without slot suffix

var slot string

func secretsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ykvault")
}

func slottedPath(id string) string {
	return filepath.Join(secretsDir(), id+".ykv.slot"+slot)
}

// findSecret returns (path, fileSlot) for the given ID.
// Tries .ykv.slot<slot> first, then legacy .ykv (compat, slot "2").
func findSecret(id string) (path, fileSlot string) {
	p := slottedPath(id)
	if _, err := os.Stat(p); err == nil {
		return p, slot
	}
	legacy := filepath.Join(secretsDir(), id+legacySuffix)
	if _, err := os.Stat(legacy); err == nil {
		return legacy, "2"
	}
	return "", ""
}

func yubiKeyHMAC(id, s string) (string, error) {
	out, err := exec.Command("ykchalresp", "-H", "-"+s, id).Output()
	if err != nil {
		return "", fmt.Errorf("YubiKey challenge failed")
	}
	return strings.TrimSpace(string(out)), nil
}

// deriveKey matches the shell script:
//
//	key = SHA256(hmac)           — 32 bytes
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

func readAndDecrypt(path, id, s string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %s", id)
	}
	hmac, err := yubiKeyHMAC(id, s)
	if err != nil {
		return nil, err
	}
	key, iv := deriveKey(hmac)
	cleaned := strings.ReplaceAll(string(data), "\n", "")
	ct, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	return decryptAES(ct, key, iv)
}

func setSecret(id string) error {
	if id == "" {
		return fmt.Errorf("usage: set <id>")
	}
	if path, _ := findSecret(id); path != "" {
		return fmt.Errorf("secret %q already exists", id)
	}

	fmt.Fprintf(os.Stderr, "Enter your secret %s (finish with ctrl-d):\n", id)
	value, err := io.ReadAll(os.Stdin)
	if err != nil || len(bytes.TrimSpace(value)) == 0 {
		return fmt.Errorf("no value provided")
	}

	fmt.Fprintf(os.Stderr, "Touch your YubiKey to set %s (slot %s) ...\n", id, slot)
	hmac, err := yubiKeyHMAC(id, slot)
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
	path := slottedPath(id)
	if err := os.WriteFile(path, base64Wrap(ct), 0600); err != nil {
		return err
	}
	fmt.Printf("Stored: %s (slot %s)\n", id, slot)
	return nil
}

func getSecret(id string) error {
	if id == "" {
		return fmt.Errorf("usage: get <id>")
	}
	path, fileSlot := findSecret(id)
	if path == "" {
		return fmt.Errorf("secret not found: %s", id)
	}

	fmt.Fprintf(os.Stderr, "Touch your YubiKey to get %s (slot %s) ...\n", id, fileSlot)
	pt, err := readAndDecrypt(path, id, fileSlot)
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

	oldPath, oldSlot := findSecret(oldID)
	if oldPath == "" {
		return fmt.Errorf("secret not found: %s", oldID)
	}
	if path, _ := findSecret(newID); path != "" {
		return fmt.Errorf("secret %q already exists", newID)
	}

	// Decrypt with slot encoded in old filename (touch 1)
	fmt.Fprintf(os.Stderr, "Touch your YubiKey to decrypt %s (slot %s) ...\n", oldID, oldSlot)
	pt, err := readAndDecrypt(oldPath, oldID, oldSlot)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong key or corrupted data)")
	}

	// Re-encrypt with new ID under current slot (touch 2)
	fmt.Fprintf(os.Stderr, "Touch your YubiKey to encrypt as %s (slot %s) ...\n", newID, slot)
	hmacNew, err := yubiKeyHMAC(newID, slot)
	if err != nil {
		return err
	}
	keyNew, ivNew := deriveKey(hmacNew)

	ct, err := encryptAES(pt, keyNew, ivNew)
	if err != nil {
		return err
	}

	newPath := slottedPath(newID)
	if err := os.WriteFile(newPath, base64Wrap(ct), 0600); err != nil {
		return err
	}

	if err := os.Remove(oldPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("failed to remove old secret: %w", err)
	}

	fmt.Printf("Renamed: %s -> %s (slot %s)\n", oldID, newID, slot)
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
	seen := make(map[string]bool)
	for _, e := range entries {
		name := e.Name()
		var id string
		if i := strings.Index(name, ".ykv"); i != -1 {
			id = name[:i]
		} else {
			continue
		}
		if !seen[id] {
			seen[id] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Println(id)
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

# ykvault

**Hardware-encrypted secrets vault for the CLI.** Every secret is encrypted with a key derived from your YubiKey — and decryption requires a physical touch, every time. No master password to forget, no cloud to trust, no daemon to run.

[![Go Reference](https://pkg.go.dev/badge/github.com/sintoniastrategy/ykvault.svg)](https://pkg.go.dev/github.com/sintoniastrategy/ykvault)
[![Latest Release](https://img.shields.io/github/v/release/sintoniastrategy/ykvault)](https://github.com/sintoniastrategy/ykvault/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/sintoniastrategy/ykvault)](https://goreportcard.com/report/github.com/sintoniastrategy/ykvault)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```sh
echo "my_api_key" | ykvault set mytoken    # store (touch YubiKey)
ykvault get mytoken                         # retrieve (touch YubiKey)
ykvault mv mytoken mytoken_v2               # re-encrypt under new ID (2 touches)
ykvault rm mytoken_v2                       # delete a secret
ykvault ls                                  # show all secret IDs
```

## Why ykvault

- **Hardware-bound.** Encryption key is derived from a YubiKey HMAC-SHA1 challenge-response. The YubiKey's secret never leaves the device, so the key is impossible to extract — even with root access to the file and full memory.
- **Physical touch per access.** Every `get` / `set` / `mv` requires you to touch the key. No silent reads, no background unlocks, no agent caching.
- **No master password.** Nothing to remember, nothing to phish, nothing to brute-force.
- **Offline by default.** No cloud, no sync service, no telemetry. Files live in `~/.ykvault/`. Back them up however you back up the rest of your dotfiles.
- **One static binary.** ~2 MB, no runtime, no daemon. Drop it on any Linux box and go.

## Install

```sh
go install github.com/sintoniastrategy/ykvault@latest
```

Or grab a prebuilt binary from [releases](https://github.com/sintoniastrategy/ykvault/releases).

**Requirements:** `ykchalresp` (from [yubikey-personalization](https://developers.yubico.com/yubikey-personalization/)) in `PATH`, and a YubiKey slot configured for HMAC-SHA1 challenge-response with touch:

```sh
ykman otp chalresp 2 --touch --generate
```

## Usage

### Slot selection

For a new secret, `-slot` overrides `YKVAULT_SLOT`, which overrides the default slot 2. `get` reads the slot from the filename. `mv` reads the old secret's slot from its filename and uses the selected slot for the new file.

```sh
YKVAULT_SLOT=1 ykvault set mytoken    # store using slot 1
ykvault -slot 1 set mytoken           # same via flag
ykvault get mytoken                   # slot auto-detected
```

To replace an existing value, use `set --force <id>`:

```sh
echo 'replacement' | ykvault set --force mytoken
```

Overwriting preserves the exact filename and uses its slot, ignoring `YKVAULT_SLOT` and the default slot. Legacy `.ykv` files are overwritten in place using slot 2. An explicit `-slot` must match the existing file's slot; a mismatch fails before reading stdin or requesting a YubiKey touch.

For example, with an existing `mytoken.ykv.slot2`, `YKVAULT_SLOT=1 ykvault set --force mytoken` still uses slot 2. `YKVAULT_SLOT=2 ykvault -slot 1 set --force mytoken` fails because the explicit flag conflicts with the file.

Without `--force`, existing secrets are rejected. If the secret does not exist, `--force` creates it using the normal slot precedence. `--force` does not change an existing secret's slot. Place `-slot` before `set` and `--force` before the ID.

### Custom secrets directory

```sh
YKVAULT_DIR=/mnt/usb/secrets ykvault ls
```

### Preserve trailing newline

By default a single trailing `\r\n` / `\n` / `\r` is stripped from `set` input. To keep it:

```sh
echo "key-with-newline" | YKVAULT_PRESERVE_NEWLINE=1 ykvault set mykey
```

## How it works

```
challenge = <secret id>           ── e.g. "github_token"
response  = HMAC-SHA1(yubikey_secret, challenge)   ── computed on the YubiKey
key       = SHA-256(response)                       ── 32 bytes, AES-256
iv        = SHA-256(response || "iv")[:16]          ── 16 bytes
ciphertext = AES-256-CBC(key, iv, plaintext)        ── PKCS#7 padded
```

The ciphertext (base64) is written to `~/.ykvault/<id>.ykv.slot<N>` with mode `0600`. Decryption is the same path in reverse: the YubiKey recomputes the HMAC for the same challenge, you get the same key. Determinism is the point — there's nothing else to store, nothing else to lose.

### Threat model

**ykvault protects against**

- Full disk compromise: leaked, stolen, or backed-up vault files are useless without the physical YubiKey.
- Malware exfiltrating files at rest: ciphertext-only, no plaintext cache, no daemon to hijack.
- Forgotten master passwords: there isn't one.

**ykvault does *not* protect against**

- Loss of the YubiKey itself with no backup key configured with the same HMAC secret. Provision a second YubiKey with the same secret if you need redundancy.
- Active malware on a machine where you're actively using ykvault: a process watching stdout during `get` can capture the plaintext just like with any other secret manager.
- Discovery of secret **IDs**. Filenames in `~/.ykvault/` are not encrypted; only values are.

## Bash completions

```sh
# From a release tarball:
source completions/ykvault.bash

# Or permanently:
cp completions/ykvault.bash /etc/bash_completion.d/ykvault
```

## FAQ

**What if I lose my YubiKey?**
Your secrets are gone — that's the design. Provision a second YubiKey with the *same* HMAC secret (`ykman otp chalresp 2 <hex-secret> --touch`) and keep it in a safe. Save the hex secret somewhere offline at provisioning time, or you won't be able to recreate it.

**Can I use the same vault on multiple machines?**
Yes. The vault is just a directory of files. Sync `~/.ykvault/` across machines (Syncthing, git-crypt-free git, rsync, whatever), and any machine with a YubiKey holding the same HMAC secret can decrypt.

**Why HMAC-SHA1 and not something modern?**
Because that's what YubiKey OTP challenge-response slots compute. SHA-1 here is used as a PRF inside HMAC, which is not affected by SHA-1 collision attacks. The output is then run through SHA-256 to derive AES-256 keys.

**Why AES-CBC instead of AES-GCM?**
Compatibility with the original `ykvault.sh` shell version, which relies on `openssl enc`. The Go binary is the recommended path; CBC vs GCM is not a meaningful difference at this scale (single-user, local file, integrity provided by the touch requirement and PKCS#7 padding validation).

**Is this audited?**
No. Read [`main.go`](main.go) — it's under 400 lines of standard-library Go.

## Shell version

`ykvault.sh` has identical crypto and file format but depends on `openssl enc`, whose behaviour varies across versions and distros. Use the Go binary for reliable cross-platform operation.

## License

MIT — see [LICENSE](LICENSE).

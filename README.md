# ykvault

Encrypted secrets vault backed by YubiKey. Secrets can't be decrypted without physical key presence.

```sh
echo "my_api_key" | ykvault set mytoken   # store (touch YubiKey)
ykvault get mytoken                        # retrieve (touch YubiKey)
ykvault mv mytoken mytoken_v2             # re-encrypt under new ID (2 touches)
ykvault rm mytoken_v2                     # delete a secret
ykvault ls                                 # show all secret IDs
```

## Install

```sh
go install github.com/sintoniastrategy/ykvault@latest
```

Or download a binary from [releases](https://github.com/sintoniastrategy/ykvault/releases).

**Requires:** `ykchalresp` in PATH and YubiKey slot 2 configured:
```sh
ykman otp chalresp 2 --touch --generate
```

## Slot

Slot is only relevant when **storing** a secret. For `get`/`rename` it is auto-detected from the filename.

```sh
YKVAULT_SLOT=1 ykvault set mytoken    # store using slot 1
ykvault -slot 1 set mytoken           # same via flag
ykvault get mytoken                   # slot auto-detected, no flag needed
```

Override secrets directory:
```sh
YKVAULT_DIR=/mnt/usb/secrets ykvault list
```

## How it works

AES-256-CBC. Key and IV derived from YubiKey HMAC-SHA1 response to the secret ID as challenge — deterministic, non-extractable. Files stored in `~/.ykvault/<id>.ykv.slot<N>`.

## Bash completions

```sh
# From a release tarball:
source completions/ykvault.bash

# Or permanently:
cp completions/ykvault.bash /etc/bash_completion.d/ykvault
```

## Bash version

`ykvault.sh` has identical crypto and file format but depends on `openssl enc`, whose behaviour varies across versions and distros. Use the Go binary for reliable cross-platform operation.

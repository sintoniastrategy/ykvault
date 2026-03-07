#!/bin/sh
# YubiKey simple encrypted secrets storage
#
# Prerequisites:
# ykman otp chalresp 2 --touch --generate # generate hw-based non-extractable secret in slot 2

SECRETS_DIR="${HOME}/.ykvault"
ENC_SUFF=".ykv"
SLOT="${YKVAULT_SLOT:-2}"

# Derive key ourselves — OpenSSL just does raw AES
# Format: 16-byte IV + ciphertext (no "Salted__" magic, no KDF)
# OpenSSL 3.x: -K/-iv bypass KDF entirely; no warnings, no salt header.

set_secret() {
    local id="$1"
    local value

    if [ -z "$id" ]; then
        echo "Usage: set <id> (value from stdin)" >&2
        return 1
    fi

    mkdir -p "$SECRETS_DIR"

    # Check if file already exists
    if [ -f "${SECRETS_DIR}/${id}${ENC_SUFF}" ]; then
        echo "Error: secret '$id' already exists" >&2
        echo "Remove it first: rm '${SECRETS_DIR}/${id}${ENC_SUFF}'" >&2
        return 1
    fi

    echo "Enter your secret $id (finish with ctrl-d):" >&2
    # Read value from stdin
    value=$(cat)

    if [ -z "$value" ]; then
        echo "Error: no value provided via stdin" >&2
        return 1
    fi

    echo "Touch your YubiKey to set $id ..." >&2
    local hmac
    hmac=$(ykchalresp -H -${SLOT} "$id" 2>/dev/null)

    if [ -z "$hmac" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    # We derive key and IV from HMAC output (deterministic)
    # HMAC = 40 hex chars = 20 bytes
    # SHA256(HMAC) = 64 hex chars = 32 bytes for AES-256 key
    # SHA256(HMAC + "iv") = take first 32 hex = 16 bytes for IV
    local key iv
    key=$(printf '%s' "$hmac" | openssl dgst -sha256 -r | cut -c1-64)
    iv=$(printf '%s' "${hmac}iv" | openssl dgst -sha256 -r | cut -c1-32)

    printf '%s' "$value" | openssl enc -aes-256-cbc -K "$key" -iv "$iv" -base64 > "${SECRETS_DIR}/${id}${ENC_SUFF}"

    echo "Stored: $id"
}

get_secret() {
    local id="$1"

    if [ -z "$id" ]; then
        echo "Usage: get <id>" >&2
        return 1
    fi

    if [ ! -f "${SECRETS_DIR}/${id}${ENC_SUFF}" ]; then
        echo "Secret not found: $id" >&2
        return 1
    fi

    echo "Touch your YubiKey to get $id ..." >&2
    local hmac
    hmac=$(ykchalresp -H -${SLOT} "$id" 2>/dev/null)

    if [ -z "$hmac" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    local key iv
    key=$(printf '%s' "$hmac" | openssl dgst -sha256 -r | cut -c1-64)
    iv=$(printf '%s' "${hmac}iv" | openssl dgst -sha256 -r | cut -c1-32)

    openssl enc -aes-256-cbc -d -K "$key" -iv "$iv" -base64 < "${SECRETS_DIR}/${id}${ENC_SUFF}" 2>/dev/null
}

rename_secret() {
    local old_id="$1"
    local new_id="$2"

    if [ -z "$old_id" ] || [ -z "$new_id" ]; then
        echo "Usage: rename <old_id> <new_id>" >&2
        return 1
    fi

    if [ ! -f "${SECRETS_DIR}/${old_id}${ENC_SUFF}" ]; then
        echo "Secret not found: $old_id" >&2
        return 1
    fi

    if [ -f "${SECRETS_DIR}/${new_id}${ENC_SUFF}" ]; then
        echo "Error: secret '$new_id' already exists" >&2
        return 1
    fi

    # Step 1: decrypt with old ID (touch 1)
    echo "Touch your YubiKey to decrypt $old_id ..." >&2
    local hmac_old
    hmac_old=$(ykchalresp -H -${SLOT} "$old_id" 2>/dev/null)

    if [ -z "$hmac_old" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    local key_old iv_old
    key_old=$(printf '%s' "$hmac_old" | openssl dgst -sha256 -r | cut -c1-64)
    iv_old=$(printf '%s' "${hmac_old}iv" | openssl dgst -sha256 -r | cut -c1-32)

    local value
    value=$(openssl enc -aes-256-cbc -d -K "$key_old" -iv "$iv_old" -base64 \
        < "${SECRETS_DIR}/${old_id}${ENC_SUFF}" 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$value" ]; then
        echo "Decryption failed" >&2
        return 1
    fi

    # Step 2: re-encrypt with new ID (touch 2)
    echo "Touch your YubiKey to encrypt as $new_id ..." >&2
    local hmac_new
    hmac_new=$(ykchalresp -H -${SLOT} "$new_id" 2>/dev/null)

    if [ -z "$hmac_new" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    local key_new iv_new
    key_new=$(printf '%s' "$hmac_new" | openssl dgst -sha256 -r | cut -c1-64)
    iv_new=$(printf '%s' "${hmac_new}iv" | openssl dgst -sha256 -r | cut -c1-32)

    printf '%s' "$value" | openssl enc -aes-256-cbc -K "$key_new" -iv "$iv_new" -base64 \
        > "${SECRETS_DIR}/${new_id}${ENC_SUFF}"

    if [ $? -ne 0 ]; then
        echo "Encryption failed" >&2
        rm -f "${SECRETS_DIR}/${new_id}${ENC_SUFF}"
        return 1
    fi

    rm "${SECRETS_DIR}/${old_id}${ENC_SUFF}"
    echo "Renamed: $old_id -> $new_id"
}

list_secrets() {
    if [ -d "$SECRETS_DIR" ]; then
        for f in "$SECRETS_DIR"/*${ENC_SUFF}; do
            [ -e "$f" ] && basename "$f" ${ENC_SUFF}
        done
    fi
}

case "$1" in
    set)    set_secret "$2" ;;
    get)    get_secret "$2" ;;
    rename) rename_secret "$2" "$3" ;;
    list)   list_secrets ;;
    *)
        echo "Usage: $0 {set <id> | get <id> | rename <old_id> <new_id> | list}" >&2
        echo "  set: reads value from stdin" >&2
        echo "       echo 'secret' | $(basename $0) set myid" >&2
        echo "  env: YKVAULT_SLOT=1 to override slot (default: 2)" >&2
        exit 1
        ;;
esac

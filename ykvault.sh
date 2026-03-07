#!/bin/sh
# YubiKey simple encrypted secrets storage
#
# Prerequisites:
# ykman otp chalresp 2 --touch --generate # generate hw-based non-extractable secret in slot 2

SECRETS_DIR="${HOME}/.ykvault"
SLOT="${YKVAULT_SLOT:-2}"

# Derive key ourselves — OpenSSL just does raw AES
# Format: 16-byte IV + ciphertext (no "Salted__" magic, no KDF)
# OpenSSL 3.x: -K/-iv bypass KDF entirely; no warnings, no salt header.
# Files stored as <id>.ykv.slot<N>; legacy <id>.ykv treated as slot 2.

# Returns path to existing secret file for given ID, or empty string.
# Slot is read from the filename — SLOT var is irrelevant for reads.
secret_file() {
    local id="$1"
    # Check any .ykv.slotN file for this ID
    for f in "${SECRETS_DIR}/${id}.ykv.slot"[0-9]*; do
        [ -f "$f" ] && echo "$f" && return
    done
    # Legacy .ykv (no slot suffix)
    [ -f "${SECRETS_DIR}/${id}.ykv" ] && echo "${SECRETS_DIR}/${id}.ykv"
}

# Returns the slot number encoded in a file path.
# foo.ykv.slot2 -> 2; foo.ykv -> 2 (compat default)
file_slot() {
    local file="$1"
    case "$file" in
        *.ykv.slot*) echo "${file##*.slot}" ;;
        *)           echo "2" ;;
    esac
}

derive_key_iv() {
    local hmac="$1"
    KEY=$(printf '%s' "$hmac" | openssl dgst -sha256 -r | cut -c1-64)
    IV=$(printf '%s' "${hmac}iv" | openssl dgst -sha256 -r | cut -c1-32)
}

set_secret() {
    local id="$1"

    if [ -z "$id" ]; then
        echo "Usage: set <id> (value from stdin)" >&2
        return 1
    fi

    mkdir -p "$SECRETS_DIR"

    if [ -n "$(secret_file "$id")" ]; then
        echo "Error: secret '$id' already exists" >&2
        return 1
    fi

    echo "Enter your secret $id (finish with ctrl-d):" >&2
    local value
    value=$(cat)

    if [ -z "$value" ]; then
        echo "Error: no value provided via stdin" >&2
        return 1
    fi

    echo "Touch your YubiKey to set $id (slot $SLOT) ..." >&2
    local hmac
    hmac=$(ykchalresp -H -${SLOT} "$id" 2>/dev/null)

    if [ -z "$hmac" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    derive_key_iv "$hmac"
    printf '%s' "$value" | openssl enc -aes-256-cbc -K "$KEY" -iv "$IV" -base64 \
        > "${SECRETS_DIR}/${id}.ykv.slot${SLOT}"

    echo "Stored: $id (slot $SLOT)"
}

get_secret() {
    local id="$1"

    if [ -z "$id" ]; then
        echo "Usage: get <id>" >&2
        return 1
    fi

    local file
    file=$(secret_file "$id")
    if [ -z "$file" ]; then
        echo "Secret not found: $id" >&2
        return 1
    fi

    local s
    s=$(file_slot "$file")
    echo "Touch your YubiKey to get $id (slot $s) ..." >&2
    local hmac
    hmac=$(ykchalresp -H -${s} "$id" 2>/dev/null)

    if [ -z "$hmac" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    derive_key_iv "$hmac"
    openssl enc -aes-256-cbc -d -K "$KEY" -iv "$IV" -base64 < "$file" 2>/dev/null
}

rename_secret() {
    local old_id="$1"
    local new_id="$2"

    if [ -z "$old_id" ] || [ -z "$new_id" ]; then
        echo "Usage: rename <old_id> <new_id>" >&2
        return 1
    fi

    local old_file
    old_file=$(secret_file "$old_id")
    if [ -z "$old_file" ]; then
        echo "Secret not found: $old_id" >&2
        return 1
    fi

    if [ -n "$(secret_file "$new_id")" ]; then
        echo "Error: secret '$new_id' already exists" >&2
        return 1
    fi

    # Decrypt with slot encoded in old filename (touch 1)
    local old_slot
    old_slot=$(file_slot "$old_file")
    echo "Touch your YubiKey to decrypt $old_id (slot $old_slot) ..." >&2
    local hmac_old
    hmac_old=$(ykchalresp -H -${old_slot} "$old_id" 2>/dev/null)

    if [ -z "$hmac_old" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    derive_key_iv "$hmac_old"
    local value
    value=$(openssl enc -aes-256-cbc -d -K "$KEY" -iv "$IV" -base64 < "$old_file" 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$value" ]; then
        echo "Decryption failed" >&2
        return 1
    fi

    # Re-encrypt with new ID under current slot (touch 2)
    echo "Touch your YubiKey to encrypt as $new_id (slot $SLOT) ..." >&2
    local hmac_new
    hmac_new=$(ykchalresp -H -${SLOT} "$new_id" 2>/dev/null)

    if [ -z "$hmac_new" ]; then
        echo "YubiKey challenge failed" >&2
        return 1
    fi

    derive_key_iv "$hmac_new"
    printf '%s' "$value" | openssl enc -aes-256-cbc -K "$KEY" -iv "$IV" -base64 \
        > "${SECRETS_DIR}/${new_id}.ykv.slot${SLOT}"

    if [ $? -ne 0 ]; then
        echo "Encryption failed" >&2
        rm -f "${SECRETS_DIR}/${new_id}.ykv.slot${SLOT}"
        return 1
    fi

    rm "$old_file"
    echo "Renamed: $old_id -> $new_id (slot $SLOT)"
}

list_secrets() {
    if [ ! -d "$SECRETS_DIR" ]; then
        return 0
    fi
    # Collect IDs from both .ykv.slotN and legacy .ykv files
    for f in "$SECRETS_DIR"/*.ykv.slot[0-9]* "$SECRETS_DIR"/*.ykv; do
        [ -e "$f" ] || continue
        name=$(basename "$f")
        # Strip .ykv and everything after (handles both formats)
        echo "${name%%.ykv*}"
    done | sort -u
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

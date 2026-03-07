_ykvault() {
    local cur prev words cword
    _init_completion || return

    # Find the subcommand (skip -slot and its value)
    local cmd="" cmd_idx=0
    for ((i = 1; i < ${#words[@]} - 1; i++)); do
        case "${words[i]}" in
            -slot) ((i++)); continue ;;
            set | get | mv | rm | ls) cmd="${words[i]}"; cmd_idx=$i; break ;;
        esac
    done

    if [[ -z "$cmd" ]]; then
        case "$prev" in
            -slot) COMPREPLY=($(compgen -W "1 2" -- "$cur")); return ;;
        esac
        COMPREPLY=($(compgen -W "set get mv rm ls -slot" -- "$cur"))
        return
    fi

    local num_after=$((cword - cmd_idx))
    case "$cmd" in
        get | rm)
            if [[ $num_after -eq 1 ]]; then
                local ids
                ids=$(ykvault ls 2>/dev/null)
                COMPREPLY=($(compgen -W "$ids" -- "$cur"))
            fi
            ;;
        mv)
            if [[ $num_after -eq 1 ]]; then
                local ids
                ids=$(ykvault ls 2>/dev/null)
                COMPREPLY=($(compgen -W "$ids" -- "$cur"))
            fi
            ;;
    esac
}

complete -F _ykvault ykvault

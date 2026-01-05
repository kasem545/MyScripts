#!/usr/bin/env zsh
# ctf-env.zsh — CTF/Pentest Profile Manager v1.3


if [[ "${ZSH_EVAL_CONTEXT:-}" != *:file ]]; then
  echo "[!] This file must be sourced: source ${(%):-%x}"
  return 1 2>/dev/null || exit 1
fi

# Storage
typeset -gA __CTF_USER __CTF_PASS __CTF_HASH __CTF_DCS __CTF_HOSTS __CTF_TARGET
typeset -g CTF_ACTIVE=""
typeset -ga CTF_DC_LIST=()
typeset -ga CTF_HOST_LIST=()

# Colors
typeset -g RED=$'\e[31m' GREEN=$'\e[32m' YELLOW=$'\e[33m'
typeset -g BLUE=$'\e[34m' CYAN=$'\e[36m' BOLD=$'\e[1m' RESET=$'\e[0m'

# ---------- helpers ----------
_ctf-has-profile() {
  local name="${1:-}"
  (( ${+__CTF_USER[$name]} )) || (( ${+__CTF_TARGET[$name]} )) || (( ${+__CTF_PASS[$name]} )) || (( ${+__CTF_HASH[$name]} ))
}

_ctf-readline() {
  local __var="$1" __prompt="$2" __val=""
  vared -p "$__prompt" __val
  : ${(P)__var::="$__val"}
}

_ctf-ask-yn() {
  local ans=""
  vared -p "$1" ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

_ctf-ask-type() {

  local __var="$1" __prompt="$2" __default="$3"
  local ans=""
  vared -p "$__prompt" ans
  ans="${ans:-$__default}"
  : ${(P)__var::="$ans"}
}

# ---------- commands ----------
ctf-add() {
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    print "${RED}Usage:${RESET} ctf-add <profile_name>"
    return 1
  fi

  local ptype=""
  _ctf-ask-type ptype "${BOLD}Profile type${RESET} [s=Simple / d=DC] (default: s): " "s"

  if [[ "$ptype" =~ ^[Dd]$ ]]; then
    local user pass hash target_ip
    _ctf-readline user "Username: "
    _ctf-readline pass "Password: "
    _ctf-readline hash "Hash: "
    _ctf-readline target_ip "Target IP (optional): "

    print ""
    print "${BOLD}Enter DCs (one per line)${RESET}"
    print "Format: ${CYAN}IP FQDN [DOMAIN] [SHORT_NAME]${RESET}"
    print "Press Enter on empty line when done:"

    local -a dc_entries=()
    while IFS= read -r line; do
      [[ -z "$line" ]] && break
      dc_entries+=("$line")
    done

    print ""
    print "${BOLD}Enter other hosts (one per line, same format)${RESET}"
    print "Press Enter on empty line when done:"

    local -a host_entries=()
    while IFS= read -r line; do
      [[ -z "$line" ]] && break
      host_entries+=("$line")
    done

    __CTF_USER[$name]="$user"
    __CTF_PASS[$name]="$pass"
    __CTF_HASH[$name]="$hash"
    __CTF_TARGET[$name]="$target_ip"
    __CTF_DCS[$name]="${(F)dc_entries}"
    __CTF_HOSTS[$name]="${(F)host_entries}"

    print "${GREEN}✓${RESET} Saved profile: ${CYAN}$name${RESET} (DC)"
    print "  DCs: ${#dc_entries[@]}, Hosts: ${#host_entries[@]}"
  else
    local target user pass
    _ctf-readline target "Target (optional): "
    _ctf-readline user "Username: "
    _ctf-readline pass "Password: "

    __CTF_USER[$name]="$user"
    __CTF_PASS[$name]="$pass"
    __CTF_HASH[$name]=""
    __CTF_DCS[$name]=""
    __CTF_HOSTS[$name]=""
    __CTF_TARGET[$name]="$target"

    print "${GREEN}✓${RESET} Saved profile: ${CYAN}$name${RESET} (simple)"
  fi
}

ctf-edit() {
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    print "${RED}Usage:${RESET} ctf-edit <profile_name>"
    return 1
  fi

  if ! _ctf-has-profile "$name"; then
    print "${RED}Error:${RESET} Profile '${CYAN}$name${RESET}' not found"
    return 1
  fi

  local is_dc=0
  [[ -n "${__CTF_DCS[$name]:-}" ]] && is_dc=1

  if (( is_dc )); then
    print "${BLUE}Editing DC profile: ${CYAN}$name${RESET}"

    local user pass hash target
    _ctf-readline user "Username [${__CTF_USER[$name]}]: "
    _ctf-readline pass "Password (empty to keep): "
    _ctf-readline hash "Hash (empty to keep): "
    _ctf-readline target "Target IP [${__CTF_TARGET[$name]}] (optional): "

    __CTF_USER[$name]="${user:-${__CTF_USER[$name]}}"
    __CTF_TARGET[$name]="${target:-${__CTF_TARGET[$name]}}"
    [[ -n "$pass" ]] && __CTF_PASS[$name]="$pass"
    [[ -n "$hash" ]] && __CTF_HASH[$name]="$hash"

    print ""
    if _ctf-ask-yn "${YELLOW}Append new DCs and Hosts? [y/N]:${RESET} "; then
      print ""
      print "${BOLD}Append DCs (one per line)${RESET}"
      print "Format: ${CYAN}IP FQDN [DOMAIN] [SHORT_NAME]${RESET}"
      print "Press Enter on empty line when done:"

      local -a dc_entries=()
      while IFS= read -r line; do
        [[ -z "$line" ]] && break
        dc_entries+=("$line")
      done

      if (( ${#dc_entries[@]} > 0 )); then
        if [[ -n "${__CTF_DCS[$name]:-}" ]]; then
          __CTF_DCS[$name]+=$'\n'"${(F)dc_entries}"
        else
          __CTF_DCS[$name]="${(F)dc_entries}"
        fi
        print "${GREEN}✓${RESET} Appended DCs: ${#dc_entries[@]}"
      else
        print "${BLUE}No DCs appended${RESET}"
      fi

      print ""
      print "${BOLD}Append other hosts (one per line)${RESET}"
      print "Format: ${CYAN}IP FQDN [DOMAIN] [SHORT_NAME]${RESET}"
      print "Press Enter on empty line when done:"

      local -a host_entries=()
      while IFS= read -r line; do
        [[ -z "$line" ]] && break
        host_entries+=("$line")
      done

      if (( ${#host_entries[@]} > 0 )); then
        if [[ -n "${__CTF_HOSTS[$name]:-}" ]]; then
          __CTF_HOSTS[$name]+=$'\n'"${(F)host_entries}"
        else
          __CTF_HOSTS[$name]="${(F)host_entries}"
        fi
        print "${GREEN}✓${RESET} Appended Hosts: ${#host_entries[@]}"
      else
        print "${BLUE}No hosts appended${RESET}"
      fi
    fi

    print "${GREEN}✓${RESET} Updated: ${CYAN}$name${RESET}"
    [[ "$CTF_ACTIVE" == "$name" ]] && ctf-use "$name"
    return 0
  fi

  print "${BLUE}Editing simple profile: ${CYAN}$name${RESET}"
  local target user pass
  _ctf-readline target "Target [${__CTF_TARGET[$name]}] (optional): "
  _ctf-readline user "Username [${__CTF_USER[$name]}]: "
  _ctf-readline pass "Password (empty to keep): "

  __CTF_TARGET[$name]="${target:-${__CTF_TARGET[$name]}}"
  __CTF_USER[$name]="${user:-${__CTF_USER[$name]}}"
  [[ -n "$pass" ]] && __CTF_PASS[$name]="$pass"

  print "${GREEN}✓${RESET} Updated: ${CYAN}$name${RESET}"
  [[ "$CTF_ACTIVE" == "$name" ]] && ctf-use "$name"
}

ctf-delete() {
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    print "${RED}Usage:${RESET} ctf-delete <profile_name>"
    return 1
  fi

  if ! _ctf-has-profile "$name"; then
    print "${RED}Error:${RESET} Profile '${CYAN}$name${RESET}' not found"
    return 1
  fi

  if ! _ctf-ask-yn "${YELLOW}Delete '${CYAN}$name${YELLOW}'? [y/N]:${RESET} "; then
    return 0
  fi

  unset "__CTF_USER[$name]" "__CTF_PASS[$name]" "__CTF_HASH[$name]"
  unset "__CTF_DCS[$name]" "__CTF_HOSTS[$name]" "__CTF_TARGET[$name]"

  if [[ "$CTF_ACTIVE" == "$name" ]]; then
    unset CTF_ACTIVE DOMAIN USER PASS HASH DC_IP DC_FQDN DC_NAME TARGET HOST_IP HOST_FQDN HOST_NAME 2>/dev/null
    CTF_DC_LIST=()
    CTF_HOST_LIST=()
  fi

  print "${GREEN}✓${RESET} Deleted: ${CYAN}$name${RESET}"
}

ctf-use() {
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    print "${RED}Usage:${RESET} ctf-use <profile_name>"
    return 1
  fi

  if ! _ctf-has-profile "$name"; then
    print "${RED}Error:${RESET} Profile '${CYAN}$name${RESET}' not found"
    return 1
  fi

  setopt localoptions no_xtrace no_verbose
  exec 3>&1 4>&2
  {
    export CTF_ACTIVE="$name"
    export USER="${__CTF_USER[$name]}"
    export PASS="${__CTF_PASS[$name]}"
    export HASH="${__CTF_HASH[$name]}"
    export TARGET="${__CTF_TARGET[$name]}"

    CTF_DC_LIST=()
    if [[ -n "${__CTF_DCS[$name]:-}" ]]; then
      local -a lines
      lines=(${(f)__CTF_DCS[$name]})
      local line ip fqdn domain short
      for line in "${lines[@]}"; do
        [[ -z "${line// /}" ]] && continue
        read -r ip fqdn domain short <<< "$line"
        [[ -z "$ip" || -z "$fqdn" ]] && continue
        CTF_DC_LIST+=("${ip}:${fqdn}:${domain:-}:${short:-}")
      done

      if (( ${#CTF_DC_LIST[@]} > 0 )); then
        local -a first=(${(@s.:.)CTF_DC_LIST[1]})
        export DC_IP="${first[1]}"
        export DC_FQDN="${first[2]}"
        export DOMAIN="${first[3]}"
        export DC_NAME="${first[4]}"
      fi
    else
      unset DC_IP DC_FQDN DOMAIN DC_NAME 2>/dev/null
    fi

    CTF_HOST_LIST=()
    if [[ -n "${__CTF_HOSTS[$name]:-}" ]]; then
      local -a hlines
      hlines=(${(f)__CTF_HOSTS[$name]})
      local hline hip hfqdn hdomain hshort
      for hline in "${hlines[@]}"; do
        [[ -z "${hline// /}" ]] && continue
        read -r hip hfqdn hdomain hshort <<< "$hline"
        [[ -z "$hip" || -z "$hfqdn" ]] && continue
        CTF_HOST_LIST+=("${hip}:${hfqdn}:${hdomain:-}:${hshort:-}")
      done
    fi
  } 1>/dev/null 2>/dev/null
  exec 1>&3 2>&4
  exec 3>&- 4>&-

  print "${GREEN}✓${RESET} Activated: ${CYAN}$name${RESET}"
  ctf-show
}

ctf-show() {
  if [[ -z "$CTF_ACTIVE" ]]; then
    print "${BLUE}No active profile${RESET}"
    return 0
  fi

  print ""
  print "${BOLD}${CYAN}═══ Profile: $CTF_ACTIVE ═══${RESET}"
  print "${BOLD}USER${RESET}      : ${USER}"
  print "${BOLD}PASS${RESET}      : ${PASS:-${BLUE}(not set)${RESET}}"
  [[ -n "${HASH:-}" ]] && print "${BOLD}HASH${RESET}      : ${HASH}"

  if [[ -n "${DC_IP:-}" ]]; then
    print "${BOLD}DC-IP${RESET}     : ${DC_IP}"
    print "${BOLD}DC-FQDN${RESET}   : ${DC_FQDN}"
    [[ -n "${DOMAIN:-}" ]] && print "${BOLD}DOMAIN${RESET}    : ${DOMAIN}"
    [[ -n "${DC_NAME:-}" ]] && print "${BOLD}DC-NAME${RESET}   : ${DC_NAME}"
  fi

  print "${BOLD}TARGET${RESET}    : ${TARGET:-${BLUE}(not set)${RESET}}"

  if [[ -n "${HOST_IP:-}" ]]; then
    print "${BOLD}HOST-IP${RESET}   : ${HOST_IP}"
    print "${BOLD}HOST-FQDN${RESET} : ${HOST_FQDN}"
    print "${BOLD}HOST-NAME${RESET} : ${HOST_NAME:-${BLUE}(not set)${RESET}}"
  fi

  if (( ${#CTF_DC_LIST[@]} > 0 )); then
    print ""
    print "${BOLD}Domain Controllers:${RESET}"
    local i=1 dc_entry
    for dc_entry in "${CTF_DC_LIST[@]}"; do
      local -a p=(${(@s.:.)dc_entry})
      local marker="  "
      [[ "${p[1]}" == "$DC_IP" ]] && marker="${GREEN}▶${RESET} "

      printf "%s%d) %-18s %-35s" "$marker" "$i" "${p[1]}" "${p[2]}"
      [[ -n "${p[3]}" ]] && printf " %s" "${p[3]}"
      [[ -n "${p[4]}" ]] && printf " (%s)" "${p[4]}"
      print
      ((i++))
    done
  fi

  if (( ${#CTF_HOST_LIST[@]} > 0 )); then
    print ""
    print "${BOLD}Other Hosts:${RESET}"
    local i=1 host_entry
    for host_entry in "${CTF_HOST_LIST[@]}"; do
      local -a p=(${(@s.:.)host_entry})
      local marker="  "
      [[ "${p[1]}" == "$TARGET" ]] && marker="${GREEN}▶${RESET} "

      printf "%s%d) %-18s %-35s" "$marker" "$i" "${p[1]}" "${p[2]}"
      [[ -n "${p[3]}" ]] && printf " %s" "${p[3]}"
      [[ -n "${p[4]}" ]] && printf " (%s)" "${p[4]}"
      print
      ((i++))
    done
  fi

  print ""
}

ctf-dc() {
  if [[ -z "$CTF_ACTIVE" ]]; then
    print "${RED}Error:${RESET} No active profile"
    return 1
  fi
  if (( ${#CTF_DC_LIST[@]} == 0 )); then
    print "${RED}Error:${RESET} No DCs configured"
    return 1
  fi

  local arg="${1:-}"

  if [[ -z "$arg" ]]; then
    print ""
    print "${BOLD}Available DCs:${RESET}"
    local i=1 dc_entry
    for dc_entry in "${CTF_DC_LIST[@]}"; do
      local -a p=(${(@s.:.)dc_entry})
      local marker="  "
      [[ "${p[1]}" == "$DC_IP" ]] && marker="${GREEN}▶${RESET} "
      printf "%s%d) %-18s %-35s" "$marker" "$i" "${p[1]}" "${p[2]}"
      [[ -n "${p[3]}" ]] && printf " %s" "${p[3]}"
      [[ -n "${p[4]}" ]] && printf " (%s)" "${p[4]}"
      print
      ((i++))
    done
    print ""
    return 0
  fi

  local chosen=""

  if [[ "$arg" =~ ^[0-9]+$ ]]; then
    chosen="${CTF_DC_LIST[$arg]}"
  else
    local dc_entry
    for dc_entry in "${CTF_DC_LIST[@]}"; do
      local -a p=(${(@s.:.)dc_entry})
      if [[ "${p[1]}" == "$arg" ]] || [[ "${p[2]}" == "$arg" ]] || [[ "${p[4]}" == "$arg" ]]; then
        chosen="$dc_entry"
        break
      fi
    done
  fi

  if [[ -z "$chosen" ]]; then
    print "${RED}Error:${RESET} DC not found: $arg"
    return 1
  fi

  local -a p=(${(@s.:.)chosen})
  export DC_IP="${p[1]}"
  export DC_FQDN="${p[2]}"
  export DOMAIN="${p[3]}"
  export DC_NAME="${p[4]}"

  print "${GREEN}✓${RESET} Switched to:"
  print "  ${BOLD}IP${RESET}:     ${CYAN}${DC_IP}${RESET}"
  print "  ${BOLD}FQDN${RESET}:   ${CYAN}${DC_FQDN}${RESET}"
  [[ -n "${DOMAIN:-}" ]] && print "  ${BOLD}Domain${RESET}: ${CYAN}$DOMAIN${RESET}"
  [[ -n "${DC_NAME:-}" ]] && print "  ${BOLD}Name${RESET}:   ${CYAN}${DC_NAME}${RESET}"
}

ctf-host() {
  if [[ -z "$CTF_ACTIVE" ]]; then
    print "${RED}Error:${RESET} No active profile"
    return 1
  fi
  if (( ${#CTF_HOST_LIST[@]} == 0 )); then
    print "${RED}Error:${RESET} No hosts configured"
    return 1
  fi

  local arg="${1:-}"

  if [[ -z "$arg" ]]; then
    print ""
    print "${BOLD}Available Hosts:${RESET}"
    local i=1 host_entry
    for host_entry in "${CTF_HOST_LIST[@]}"; do
      local -a p=(${(@s.:.)host_entry})
      local marker="  "
      [[ "${p[1]}" == "$TARGET" ]] && marker="${GREEN}▶${RESET} "
      printf "%s%d) %-18s %-35s" "$marker" "$i" "${p[1]}" "${p[2]}"
      [[ -n "${p[3]}" ]] && printf " %s" "${p[3]}"
      [[ -n "${p[4]}" ]] && printf " (%s)" "${p[4]}"
      print
      ((i++))
    done
    print ""
    return 0
  fi

  local chosen=""

  if [[ "$arg" =~ ^[0-9]+$ ]]; then
    if (( arg > 0 && arg <= ${#CTF_HOST_LIST[@]} )); then
      chosen="${CTF_HOST_LIST[$arg]}"
    fi
  else
    local host_entry
    for host_entry in "${CTF_HOST_LIST[@]}"; do
      local -a p=(${(@s.:.)host_entry})
      if [[ "${p[1]}" == "$arg" ]] || [[ "${p[2]}" == "$arg" ]] || [[ "${p[4]}" == "$arg" ]]; then
        chosen="$host_entry"
        break
      fi
    done
  fi

  if [[ -z "$chosen" ]]; then
    print "${RED}Error:${RESET} Host not found: $arg"
    return 1
  fi

  local -a p=(${(@s.:.)chosen})
  export TARGET="${p[1]}"
  export HOST_IP="${p[1]}"
  export HOST_FQDN="${p[2]}"
  export HOST_NAME="${p[4]:-}"

  __CTF_TARGET[$CTF_ACTIVE]="$TARGET"

  print "${GREEN}✓${RESET} Switched to host:"
  print "  ${BOLD}IP${RESET}:   ${CYAN}${HOST_IP}${RESET}"
  print "  ${BOLD}FQDN${RESET} : ${CYAN}${HOST_FQDN}${RESET}"
  [[ -n "${HOST_NAME:-}" ]] && print "  ${BOLD}Name${RESET}: ${CYAN}${HOST_NAME}${RESET}"
}

ctf-wipe() {
  if ! _ctf-ask-yn "${YELLOW}Delete ALL profiles? [y/N]:${RESET} "; then
    return 0
  fi

  unset CTF_ACTIVE DOMAIN USER PASS HASH DC_IP DC_FQDN DC_NAME TARGET HOST_IP HOST_FQDN HOST_NAME 2>/dev/null
  CTF_DC_LIST=()
  CTF_HOST_LIST=()
  __CTF_USER=()
  __CTF_PASS=()
  __CTF_HASH=()
  __CTF_DCS=()
  __CTF_HOSTS=()
  __CTF_TARGET=()

  print "${GREEN}✓${RESET} All profiles deleted"
}

ctf-help() {
  cat <<'EOF'

CTF ENVIRONMENT MANAGER

Commands:
  ctf-add <n>          Add profile (simple or DC)
  ctf-edit <n>         Edit profile (auto-detect type)
  ctf-delete <n>       Delete profile
  ctf-use <n>          Activate profile
  ctf-show             Show active profile
  ctf-dc [arg]         Switch DC (by index/IP/FQDN/name)
  ctf-host [arg]       Switch to host (by index/IP/FQDN/name)
  ctf-wipe             Delete all profiles

EOF
}

_ctf_complete() {
  local -a profiles=(${(k)__CTF_USER})
  _describe 'profile' profiles
}
compdef _ctf_complete ctf-use ctf-edit ctf-delete

alias ctf='ctf-show'

#print "${GREEN}✓${RESET} CTF Environment Manager loaded (type ctf-help)"

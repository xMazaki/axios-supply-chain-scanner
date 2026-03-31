#!/usr/bin/env bash
# axios supply chain attack scanner
# CVE: pending | 2026-03-31
# Affected: axios@1.14.1, axios@0.30.4 + plain-crypto-js@4.2.1
# Read-only — no changes made to the system

set -euo pipefail

# ------------------------------------------------------------------ #
#  Config
# ------------------------------------------------------------------ #

BAD_AXIOS_VERSIONS=("1.14.1" "0.30.4")
BAD_PACKAGES=("plain-crypto-js" "@shadanai/openclaw" "@qqbrowser/openclaw-qbot")
C2_DOMAIN="sfrclak.com"
SCAN_ROOTS=("/app" "/usr/src" "/home" "/root" "/srv" "/opt" "/var/www")
HOST_SCAN_ROOTS=("/home" "/root" "/srv" "/opt" "/var/www" "/app" "/usr/src")
LOCKFILES=("package-lock.json" "yarn.lock" "pnpm-lock.yaml")

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'
BOLD='\033[1m'

FINDINGS=0
WARNINGS=0

# ------------------------------------------------------------------ #
#  Helpers
# ------------------------------------------------------------------ #

sep()  { printf "${DIM}%s${RST}\n" "--------------------------------------------------------------------------------"; }
hdr()  { echo; printf "${BOLD}${CYN}>>  %s${RST}\n" "$*"; sep; }
hit()  { printf "  ${RED}[HIT]${RST}     %s\n" "$*"; FINDINGS=$((FINDINGS+1)); }
warn() { printf "  ${YEL}[WARN]${RST}    %s\n" "$*"; WARNINGS=$((WARNINGS+1)); }
ok()   { printf "  ${GRN}[OK]${RST}      %s\n" "$*"; }
info() { printf "  ${DIM}[INFO]${RST}    %s\n" "$*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo
        printf "${YEL}[!] Not running as root. Some paths inside containers or on the host may be inaccessible.${RST}\n"
        printf "    Re-run with: sudo bash %s\n" "$0"
        echo
    fi
}

# ------------------------------------------------------------------ #
#  Docker: scan a single container
# ------------------------------------------------------------------ #

scan_container() {
    local cid="$1"
    local name
    name=$(docker inspect --format='{{.Name}}' "$cid" | sed 's/\///')

    local found=0

    # 1. plain-crypto-js directory (presence alone = dropper ran)
    local pcjs_paths
    pcjs_paths=$(docker exec "$cid" sh -c \
        "find / -path '*/node_modules/plain-crypto-js' -type d 2>/dev/null" 2>/dev/null || true)

    if [[ -n "$pcjs_paths" ]]; then
        hit "[$name] node_modules/plain-crypto-js found — dropper likely executed"
        while IFS= read -r p; do
            info "  path: $p"
        done <<< "$pcjs_paths"
        found=1
    fi

    # 2. axios version in installed node_modules
    local axios_ver
    axios_ver=$(docker exec "$cid" sh -c \
        "find / -path '*/node_modules/axios/package.json' ! -path '*/node_modules/*/node_modules/*' 2>/dev/null \
         | xargs grep -h '\"version\"' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -5" 2>/dev/null || true)

    for ver in $axios_ver; do
        for bad in "${BAD_AXIOS_VERSIONS[@]}"; do
            if [[ "$ver" == "$bad" ]]; then
                hit "[$name] axios@${ver} installed (compromised version)"
                found=1
            fi
        done
    done

    # 3. lockfiles
    for lf in "${LOCKFILES[@]}"; do
        local lf_results
        lf_results=$(docker exec "$cid" sh -c \
            "find / -name '$lf' 2>/dev/null | head -20 | xargs grep -lE 'plain-crypto-js|\"axios\": \"1\.14\.1\"|\"axios\": \"0\.30\.4\"|axios-1\.14\.1|axios-0\.30\.4' 2>/dev/null" 2>/dev/null || true)
        if [[ -n "$lf_results" ]]; then
            hit "[$name] IOC found in $lf"
            while IFS= read -r p; do
                info "  file: $p"
            done <<< "$lf_results"
            found=1
        fi
    done

    # 4. secondary malicious packages
    for pkg in "${BAD_PACKAGES[@]}"; do
        local pkg_dir
        pkg_dir=$(docker exec "$cid" sh -c \
            "find / -path '*/node_modules/${pkg}' -type d 2>/dev/null | head -3" 2>/dev/null || true)
        if [[ -n "$pkg_dir" ]]; then
            hit "[$name] secondary malicious package found: ${pkg}"
            found=1
        fi
    done

    # 5. active C2 connection
    local c2_conn
    c2_conn=$(docker exec "$cid" sh -c \
        "command -v ss >/dev/null 2>&1 && ss -tnp 2>/dev/null | grep '${C2_DOMAIN}' || true; \
         command -v netstat >/dev/null 2>&1 && netstat -tnp 2>/dev/null | grep '${C2_DOMAIN}' || true" 2>/dev/null || true)
    if [[ -n "$c2_conn" ]]; then
        hit "[$name] ACTIVE connection to C2 ${C2_DOMAIN} detected"
        found=1
    fi

    if [[ $found -eq 0 ]]; then
        ok "[$name] clean"
        if [[ -n "$axios_ver" ]]; then
            info "[$name] axios installed: $(echo "$axios_ver" | tr '\n' ' ')"
        fi
    fi

    return $found 2>/dev/null || true
}

# ------------------------------------------------------------------ #
#  Host: scan filesystem directly
# ------------------------------------------------------------------ #

scan_host() {
    hdr "Scanning host filesystem"

    # build find path args from existing roots
    local existing_roots=()
    for r in "${HOST_SCAN_ROOTS[@]}"; do
        [[ -d "$r" ]] && existing_roots+=("$r")
    done

    if [[ ${#existing_roots[@]} -eq 0 ]]; then
        warn "No standard project directories found on host"
        return
    fi

    info "Search roots: ${existing_roots[*]}"
    echo

    # 1. plain-crypto-js
    local pcjs
    pcjs=$(find "${existing_roots[@]}" -path '*/node_modules/plain-crypto-js' -type d 2>/dev/null || true)
    if [[ -n "$pcjs" ]]; then
        hit "node_modules/plain-crypto-js found on host — dropper likely executed"
        while IFS= read -r p; do
            info "path: $p"
        done <<< "$pcjs"
    fi

    # 2. axios version in node_modules
    local axios_pkgs
    axios_pkgs=$(find "${existing_roots[@]}" \
        -path '*/node_modules/axios/package.json' \
        ! -path '*/node_modules/*/node_modules/*' 2>/dev/null | head -50 || true)

    while IFS= read -r pkg_file; do
        [[ -z "$pkg_file" ]] && continue
        local ver
        ver=$(grep -o '"version": *"[^"]*"' "$pkg_file" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        for bad in "${BAD_AXIOS_VERSIONS[@]}"; do
            if [[ "$ver" == "$bad" ]]; then
                hit "axios@${ver} installed — $(dirname "$(dirname "$pkg_file")")"
            fi
        done
        if [[ -n "$ver" ]]; then
            local safe=1
            for bad in "${BAD_AXIOS_VERSIONS[@]}"; do
                [[ "$ver" == "$bad" ]] && safe=0
            done
            [[ $safe -eq 1 ]] && ok "axios@${ver} — ${pkg_file}"
        fi
    done <<< "$axios_pkgs"

    # 3. lockfiles
    for lf in "${LOCKFILES[@]}"; do
        local hits
        hits=$(find "${existing_roots[@]}" -name "$lf" 2>/dev/null | head -50 \
            | xargs grep -lE 'plain-crypto-js|"axios": "1\.14\.1"|"axios": "0\.30\.4"' 2>/dev/null || true)
        if [[ -n "$hits" ]]; then
            while IFS= read -r h; do
                hit "IOC in ${lf}: $h"
            done <<< "$hits"
        fi
    done

    # 4. secondary packages
    for pkg in "${BAD_PACKAGES[@]}"; do
        local found_pkg
        found_pkg=$(find "${existing_roots[@]}" -path "*/node_modules/${pkg}" -type d 2>/dev/null | head -5 || true)
        if [[ -n "$found_pkg" ]]; then
            hit "secondary malicious package on host: ${pkg}"
            while IFS= read -r p; do info "path: $p"; done <<< "$found_pkg"
        fi
    done

    # 5. C2 in network connections
    if command -v ss &>/dev/null; then
        local c2
        c2=$(ss -tnp 2>/dev/null | grep "$C2_DOMAIN" || true)
        [[ -n "$c2" ]] && hit "ACTIVE connection to C2 ${C2_DOMAIN} on host"
    fi

    # 6. leftover RAT artifacts in /tmp
    local tmp_artifacts
    tmp_artifacts=$(find /tmp /var/tmp -name '*.sh' -o -name '*.bin' -o -name '*.elf' 2>/dev/null \
        | xargs grep -lE 'sfrclak|plain-crypto' 2>/dev/null || true)
    if [[ -n "$tmp_artifacts" ]]; then
        hit "Suspicious RAT artifact found in temp directory"
        while IFS= read -r a; do info "file: $a"; done <<< "$tmp_artifacts"
    fi
}

# ------------------------------------------------------------------ #
#  Network: check C2 in recent connections (host level)
# ------------------------------------------------------------------ #

scan_network() {
    hdr "Network — C2 indicator check (host)"

    local found_c2=0

    # active connections
    if command -v ss &>/dev/null; then
        local active
        active=$(ss -tnp 2>/dev/null | grep "$C2_DOMAIN" || true)
        if [[ -n "$active" ]]; then
            hit "Active connection to ${C2_DOMAIN} detected"
            echo "$active"
            found_c2=1
        fi
    fi

    # DNS cache
    if command -v systemd-resolve &>/dev/null; then
        local dns
        dns=$(systemd-resolve --statistics 2>/dev/null | grep -i "$C2_DOMAIN" || true)
        [[ -n "$dns" ]] && warn "C2 domain seen in systemd-resolve cache" && found_c2=1
    fi

    # recent connections in logs
    if [[ -f /var/log/syslog ]]; then
        local syslog_hit
        syslog_hit=$(grep -i "sfrclak" /var/log/syslog 2>/dev/null | tail -5 || true)
        if [[ -n "$syslog_hit" ]]; then
            hit "C2 domain found in /var/log/syslog"
            echo "$syslog_hit"
            found_c2=1
        fi
    fi

    if [[ $found_c2 -eq 0 ]]; then
        ok "No active C2 connections detected"
        info "Note: the RAT self-deletes — absence of connection does not mean clean"
    fi
}

# ------------------------------------------------------------------ #
#  Report
# ------------------------------------------------------------------ #

print_report() {
    echo
    sep
    printf "${BOLD}  SCAN COMPLETE${RST}\n"
    sep
    printf "  Findings : ${RED}%d${RST}\n" "$FINDINGS"
    printf "  Warnings : ${YEL}%d${RST}\n" "$WARNINGS"
    sep

    if [[ $FINDINGS -gt 0 ]]; then
        echo
        printf "${RED}${BOLD}  SYSTEM LIKELY COMPROMISED — recommended actions:${RST}\n"
        echo
        printf "  1.  Assume all credentials on this system are stolen\n"
        printf "      Rotate: SSH keys, API tokens, DB passwords, cloud IAM, env vars\n"
        echo
        printf "  2.  Downgrade axios immediately\n"
        printf "      npm install axios@1.14.0   (1.x branch)\n"
        printf "      npm install axios@0.30.3   (0.x branch)\n"
        echo
        printf "  3.  Block C2 at the firewall level\n"
        printf "      iptables -A OUTPUT -d sfrclak.com -j DROP\n"
        echo
        printf "  4.  Audit CI/CD pipeline runs between 2026-03-31 00:21 UTC and 03:15 UTC\n"
        printf "      Any build that ran npm install during that window may have distributed\n"
        printf "      the infected artifact to production\n"
        echo
        printf "  5.  Check for related malicious packages in your dependency tree\n"
        printf "      @shadanai/openclaw (versions 2026.3.28-x / 2026.3.31-x)\n"
        printf "      @qqbrowser/openclaw-qbot@0.0.130\n"
        echo
        printf "  6.  Consider full container/machine rebuild for affected systems\n"
        printf "      The RAT self-deletes — you cannot trust the current state of the filesystem\n"
        echo
    else
        echo
        printf "${GRN}${BOLD}  No compromise indicators found.${RST}\n"
        echo
        printf "  Reminder: the malware self-deletes after execution.\n"
        printf "  If you ran npm install between 2026-03-31 00:21 and 03:15 UTC,\n"
        printf "  consider rotating credentials regardless of this scan result.\n"
        echo
    fi

    sep
    printf "${DIM}  IOC reference\n"
    printf "  Compromised packages : axios@1.14.1 / axios@0.30.4\n"
    printf "  Malicious dependency : plain-crypto-js@4.2.1\n"
    printf "  C2                  : sfrclak.com:8000\n"
    printf "  Published by        : nrwise@proton.me (compromised jasonsaayman npm account)\n"
    printf "  Sources             : stepsecurity.io / socket.dev${RST}\n"
    sep
    echo
}

# ------------------------------------------------------------------ #
#  Main
# ------------------------------------------------------------------ #

main() {
    clear
    echo
    printf "${BOLD}  axios supply chain attack — scanner${RST}\n"
    printf "${DIM}  2026-03-31 | read-only, no changes made${RST}\n"
    echo
    sep

    check_root

    # Docker path
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        local containers
        containers=$(docker ps -q 2>/dev/null || true)

        if [[ -n "$containers" ]]; then
            hdr "Docker containers detected — scanning each one"

            local count=0
            while IFS= read -r cid; do
                [[ -z "$cid" ]] && continue
                local name
                name=$(docker inspect --format='{{.Name}}' "$cid" | sed 's/\///')
                printf "\n  ${DIM}Scanning container: %s (%s)${RST}\n" "$name" "$cid"
                scan_container "$cid" || true
                count=$((count+1))
            done <<< "$containers"

            info "$count container(s) scanned"

            # also check host lockfiles in case the app is mounted
            echo
            hdr "Host lockfiles (mounted volumes / bare installs)"
            scan_host
        else
            warn "Docker is available but no running containers found"
            info "Falling back to host filesystem scan"
            scan_host
        fi
    else
        info "Docker not available or not running — scanning host filesystem"
        scan_host
    fi

    scan_network
    print_report
}

main "$@"

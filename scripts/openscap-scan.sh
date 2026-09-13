#!/usr/bin/env bash
# ---------------------------------------------------------------------
# openscap-scan.sh - OpenSCAP DISA STIG scan for RHEL01 (Rocky Linux 9)
#
# Usage:
#   sudo ./openscap-scan.sh list                  # enumerate available profiles
#   sudo ./openscap-scan.sh scan baseline         # pre-remediation scan
#   sudo ./openscap-scan.sh scan post             # post-remediation scan
#   sudo ./openscap-scan.sh fix                   # GENERATE (not run) fix script
#
# SNAPSHOT THE VM BEFORE RUNNING 'fix' OUTPUT. STIG remediation can lock you
# out of SSH, break sudo, or leave the system unbootable. That is not a
# hypothetical warning.
# ---------------------------------------------------------------------
set -euo pipefail

OUTDIR="${OUTDIR:-/root/scap-results}"
DATE="$(date +%Y%m%d-%H%M)"
HOSTLABEL="${HOSTLABEL:-rhel01}"

# The data stream filename and profile ID differ between RHEL, Rocky, and
# scap-security-guide versions. Never hardcode them from a blog post -
# enumerate and confirm. 'list' does exactly that.
DS="${DS:-}"
PROFILE="${PROFILE:-}"

die() { echo "ERROR: $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "run with sudo"
}

install_deps() {
    if ! rpm -q openscap-scanner >/dev/null 2>&1 || ! rpm -q scap-security-guide >/dev/null 2>&1; then
        echo ">> installing openscap-scanner and scap-security-guide"
        dnf install -y openscap-scanner scap-security-guide
    fi
}

find_datastream() {
    if [[ -n "$DS" ]]; then
        [[ -f "$DS" ]] || die "data stream not found: $DS"
        return
    fi
    # Rocky 9 normally ships ssg-rl9-ds.xml; fall back to any RHEL 9 stream.
    for candidate in \
        /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml \
        /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
    do
        if [[ -f "$candidate" ]]; then DS="$candidate"; return; fi
    done
    DS="$(find /usr/share/xml/scap/ssg/content -name 'ssg-*9-ds.xml' | head -n1 || true)"
    [[ -n "$DS" ]] || die "no SCAP data stream found under /usr/share/xml/scap/ssg/content"
}

cmd_list() {
    install_deps
    find_datastream
    echo ">> data stream: $DS"
    echo
    oscap info "$DS"
    echo
    echo ">> profiles containing 'stig':"
    oscap info "$DS" | grep -i 'stig' || echo "   (none matched - read the full list above)"
    echo
    echo "Copy the exact profile ID and pass it as:  PROFILE=<id> sudo -E ./openscap-scan.sh scan baseline"
}

resolve_profile() {
    if [[ -z "$PROFILE" ]]; then
        PROFILE="$(oscap info "$DS" 2>/dev/null \
            | grep -oE 'xccdf_org\.ssgproject\.content_profile_stig(_gui)?' \
            | head -n1 || true)"
    fi
    [[ -n "$PROFILE" ]] || die "no STIG profile resolved. Run './openscap-scan.sh list' and set PROFILE=<id>."
}

cmd_scan() {
    local stage="${1:-baseline}"
    install_deps
    find_datastream
    resolve_profile
    mkdir -p "$OUTDIR"

    local base="${OUTDIR}/${HOSTLABEL}-${stage}-${DATE}"
    echo ">> data stream : $DS"
    echo ">> profile     : $PROFILE"
    echo ">> output      : ${base}.html"
    echo

    # oscap exits 2 when rules fail. That is the normal case on a baseline
    # scan, so do not let 'set -e' treat it as an error.
    set +e
    oscap xccdf eval \
        --profile "$PROFILE" \
        --results        "${base}.xml" \
        --results-arf    "${base}-arf.xml" \
        --report         "${base}.html" \
        "$DS"
    local rc=$?
    set -e
    [[ $rc -le 2 ]] || die "oscap exited $rc"

    echo
    echo "----------------------------------------------------------"
    echo " Result counts"
    echo "----------------------------------------------------------"
    for r in pass fail notapplicable notchecked error; do
        printf " %-16s %s\n" "$r" "$(grep -c "<result>${r}</result>" "${base}.xml" || echo 0)"
    done

    local p f
    p=$(grep -c '<result>pass</result>' "${base}.xml" || echo 0)
    f=$(grep -c '<result>fail</result>' "${base}.xml" || echo 0)
    if (( p + f > 0 )); then
        echo
        printf " Compliance (pass / pass+fail): %.1f%%\n" "$(echo "scale=4; 100*$p/($p+$f)" | bc)"
        echo " ^ record this in the README metrics table"
    fi

    echo
    echo " ARF XML is NOT for the repo - .gitignore blocks it."
    echo " Commit ${base##*/}.html after reviewing it for hostnames and accounts."
}

cmd_fix() {
    install_deps
    find_datastream
    resolve_profile
    mkdir -p "$OUTDIR"
    local fixfile="${OUTDIR}/${HOSTLABEL}-remediate-${DATE}.sh"

    oscap xccdf generate fix \
        --profile "$PROFILE" \
        --fix-type bash \
        --output "$fixfile" \
        "$DS"

    chmod 0700 "$fixfile"
    echo ">> generated: $fixfile"
    echo ">> lines    : $(wc -l < "$fixfile")"
    echo
    echo "DO NOT RUN THIS YET."
    echo "  1. Snapshot the VM."
    echo "  2. Read it. Search for sshd, sudo, pam, fapolicyd, grub, audit."
    echo "  3. Apply in stages and reboot between stages."
    echo "  4. Confirm you can still log in before applying the next stage."
}

require_root
case "${1:-}" in
    list) cmd_list ;;
    scan) cmd_scan "${2:-baseline}" ;;
    fix)  cmd_fix ;;
    *)    echo "usage: $0 {list|scan [baseline|post]|fix}"; exit 1 ;;
esac

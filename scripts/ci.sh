#!/usr/bin/env bash
#
# ci.sh - the full gate for this package, plus a preflight that explains the
# environment before running it.
#
# The preflight is not ceremony. This package binds to a specific libcrypto,
# and the failures that come from getting that wrong are some of the least
# obvious in the whole project: a header/library mismatch links and runs and
# simply lacks whatever the older library lacked, so algorithms fetch as
# "unsupported" and version-gated tests skip themselves into a green run that
# proves nothing. Reporting what was actually found, up front, is cheaper
# than diagnosing that later.
#
# Optional dependencies (the FIPS module, the PKCS#11 provider and a SoftHSM
# token) are reported rather than required. Their tests skip when absent, so
# a green run without them is honest but narrower -- and the summary says so
# rather than letting the count of passing tests imply more coverage than
# there was.
#
# Usage:
#   scripts/ci.sh                       # full gate
#   OPENSSL_PREFIX=/opt/other scripts/ci.sh
#   scripts/ci.sh --preflight-only      # just report the environment

set -euo pipefail

OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/openssl3.5.2}"
REQUIRED_MAJOR=3
REQUIRED_MINOR=5

cd "$(dirname "$0")/.."

if [ -t 1 ]; then
    bold=$'\033[1m'; red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'; reset=$'\033[0m'
else
    bold=''; red=''; green=''; yellow=''; reset=''
fi

ok()   { printf '  %s✓%s %s\n' "$green" "$reset" "$1"; }
warn() { printf '  %s!%s %s\n' "$yellow" "$reset" "$1"; }
die()  { printf '  %s✗%s %s\n' "$red" "$reset" "$1"; exit 1; }
head_() { printf '\n%s%s%s\n' "$bold" "$1" "$reset"; }

optional_missing=()

head_ "Preflight"

[ -d "$OPENSSL_PREFIX" ] || die "OPENSSL_PREFIX=$OPENSSL_PREFIX does not exist"
ok "prefix          $OPENSSL_PREFIX"

pkgconfig_dir=""
for d in "$OPENSSL_PREFIX/lib64/pkgconfig" "$OPENSSL_PREFIX/lib/pkgconfig"; do
    [ -f "$d/libcrypto.pc" ] && { pkgconfig_dir="$d"; break; }
done
[ -n "$pkgconfig_dir" ] || die "no libcrypto.pc under $OPENSSL_PREFIX/{lib64,lib}/pkgconfig"

export PKG_CONFIG_PATH="$pkgconfig_dir"
libdir="$(dirname "$pkgconfig_dir")"
export CGO_LDFLAGS="-Wl,-rpath,$libdir"

pc_version="$(pkg-config --modversion libcrypto)"
ok "libcrypto.pc    $pc_version"

case "$pc_version" in
    "$REQUIRED_MAJOR.$REQUIRED_MINOR"*|"$REQUIRED_MAJOR."[6-9]*)
        ;;
    *)
        die "libcrypto $pc_version is older than the required $REQUIRED_MAJOR.$REQUIRED_MINOR (ML-KEM, ML-DSA and SLH-DSA need 3.5)"
        ;;
esac

command -v go >/dev/null || die "go is not on PATH"
ok "go              $(go version | awk '{print $3}')"

if [ "${CGO_ENABLED:-1}" = "0" ]; then
    die "CGO_ENABLED=0 in the environment; the cgo half of the gate cannot run"
fi

# Optional: FIPS module.
if [ -f "$OPENSSL_PREFIX/ssl/fipsmodule.cnf" ] && \
   { [ -f "$libdir/ossl-modules/fips.so" ] || [ -f "$OPENSSL_PREFIX/lib/ossl-modules/fips.so" ]; }; then
    ok "fips module     present (FIPS tests will run)"
else
    warn "fips module     absent (FIPS tests will skip; run 'openssl fipsinstall')"
    optional_missing+=("FIPS")
fi

# Optional: PKCS#11 provider and a SoftHSM token.
pkcs11_provider=""
for p in /opt/openssl-pkcs11/lib/ossl-modules/pkcs11.so "$libdir/ossl-modules/pkcs11.so"; do
    [ -f "$p" ] && { pkcs11_provider="$p"; break; }
done
if [ -n "$pkcs11_provider" ] && [ -f /usr/local/lib/softhsm/libsofthsm2.so ]; then
    ok "pkcs11          $pkcs11_provider"
else
    warn "pkcs11          absent (PKCS#11 tests will skip)"
    optional_missing+=("PKCS#11")
fi

if [ "${1:-}" = "--preflight-only" ]; then
    head_ "Preflight only; not running the gate."
    exit 0
fi

head_ "Gate"

step() {
    printf '\n%s--> %s%s\n' "$bold" "$1" "$reset"
    shift
    "$@"
}

step "gofmt"              make fmt-check
step "go vet"             make vet
step "build"              make build
step "tests (race)"       make test-race
step "tests (cgocheck2)"  make cgocheck2
step "non-cgo build"      make nocgo
step "API parity"         make api-parity

head_ "Summary"
ok "all gate steps passed against libcrypto $pc_version"
if [ ${#optional_missing[@]} -gt 0 ]; then
    warn "skipped optional coverage: ${optional_missing[*]}"
    printf '    a green run here does not cover those paths.\n'
fi

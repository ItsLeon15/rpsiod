#!/usr/bin/env bash

set -u
set -o pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
SRC_DIR="${SRC_DIR:-$ROOT_DIR/src}"
LOCAL_URL="${LOCAL_URL:-http://127.0.0.1}"

detect_default_host() {
	local sites_file="${SITES_FILE:-/etc/rpsiod/sites.yml}"
	local detected

	detected="$(awk '
		/domains:/ { in_domains = 1; next }
		in_domains && /^[[:space:]]*-/ {
			host = $2
			gsub(/["'\'']/, "", host)
			if (host ~ /[A-Za-z]/) {
				print host
				exit
			}
			if (fallback == "") {
				fallback = host
			}
		}
		in_domains && /^[^[:space:]-]/ { in_domains = 0 }
		END {
			if (fallback != "" && !printed) {
				print fallback
			}
		}
	' "$sites_file" 2>/dev/null | head -n 1)"

	if [ -n "$detected" ]; then
		printf '%s\n' "$detected"
	else
		printf '%s\n' "localhost"
	fi
}

HOST_HEADER="${HOST_HEADER:-$(detect_default_host)}"
TARGET_URL="${TARGET_URL:-https://$HOST_HEADER}"
HEADER_PATH="${HEADER_PATH:-/}"
PHP_TEST_URL="${PHP_TEST_URL:-$TARGET_URL/pma/js/messages.php?l=en&v=5.2.3&lang=en}"
REPORT_DIR="${REPORT_DIR:-$ROOT_DIR/security-check-results}"
TIMESTAMP="$(date +"%Y-%m-%d_%H-%M-%S")"
REPORT_FILE="$REPORT_DIR/report-$TIMESTAMP.txt"

PASSED=0
WARNED=0
FAILED=0

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
RESET="\033[0m"

mkdir -p "$REPORT_DIR"

log() {
	echo -e "$1" | tee -a "$REPORT_FILE"
}

pass() {
	PASSED=$((PASSED + 1))
	log "${GREEN}[PASS]${RESET} $1"
}

warn() {
	WARNED=$((WARNED + 1))
	log "${YELLOW}[WARN]${RESET} $1"
}

fail() {
	FAILED=$((FAILED + 1))
	log "${RED}[FAIL]${RESET} $1"
}

section() {
	log ""
	log "${BLUE}============================================================${RESET}"
	log "${BLUE}$1${RESET}"
	log "${BLUE}============================================================${RESET}"
}

command_exists() {
	command -v "$1" >/dev/null 2>&1
}

check_file_exists() {
	local file="$1"

	if [ -f "$file" ]; then
		pass "$file exists"
	else
		warn "$file does not exist"
	fi
}

grep_source() {
	local pattern="$1"
	local label="$2"

	if grep -RIn --exclude="*.o" --exclude="rpsiod" "$pattern" "$SRC_DIR" >> "$REPORT_FILE" 2>/dev/null; then
		warn "$label found. Review matches above."
	else
		pass "$label not found"
	fi
}

check_cppcheck() {
	section "Cppcheck"

	if ! command_exists cppcheck; then
		warn "cppcheck not installed"
		return
	fi

	local output_file="$REPORT_DIR/cppcheck-$TIMESTAMP.txt"

	cppcheck --enable=all --inconclusive --check-level=exhaustive "$SRC_DIR" > "$output_file" 2>&1

	cat "$output_file" >> "$REPORT_FILE"

	if grep -Eiq "error:|warning:" "$output_file"; then
		warn "cppcheck found warnings/errors"
	else
		pass "cppcheck did not find warnings/errors"
	fi

	if grep -Eiq "knownConditionTrueFalse|duplicateCondition|incompleteArrayFill|buffer|overflow|leak|uninit|nullPointer|memleak|invalid" "$output_file"; then
		warn "cppcheck found issues worth reviewing"
	else
		pass "cppcheck did not find obvious logic/memory warnings"
	fi
}

check_dangerous_c_functions() {
	section "Dangerous C function scan"

	grep_source "[^a-zA-Z0-9_]strcpy[[:space:]]*\\(" "strcpy usage"
	grep_source "[^a-zA-Z0-9_]strcat[[:space:]]*\\(" "strcat usage"
	grep_source "[^a-zA-Z0-9_]sprintf[[:space:]]*\\(" "sprintf usage"
	grep_source "[^a-zA-Z0-9_]gets[[:space:]]*\\(" "gets usage"
	grep_source "[^a-zA-Z0-9_]scanf[[:space:]]*\\(" "scanf usage"
	grep_source "[^a-zA-Z0-9_]system[[:space:]]*\\(" "system usage"
	grep_source "[^a-zA-Z0-9_]popen[[:space:]]*\\(" "popen usage"
	grep_source "[^a-zA-Z0-9_]memcpy[[:space:]]*\\(" "memcpy usage"
	grep_source "[^a-zA-Z0-9_]memmove[[:space:]]*\\(" "memmove usage"
}

check_known_cppcheck_patterns() {
	section "Known issue pattern scan"

	grep_source "retry_stalled_backend" "retry_stalled_backend references"
	grep_source "use_br || use_gzip" "duplicate compression condition candidates"
	grep_source "meta != NULL && meta->blocked" "always-true meta null check candidate"
	grep_source "!cert_exists && !key_exists" "TLS cert/key existence condition candidate"
	grep_source "host\\[0\\] == '\\\\0'" "host empty-check candidate"
}

check_build_warnings() {
	section "Compiler warning build"

	if ! command_exists make; then
		warn "make not installed"
		return
	fi

	local output_file="$REPORT_DIR/build-warnings-$TIMESTAMP.txt"

	(
		cd "$ROOT_DIR" || exit 1
		make clean >/dev/null 2>&1 || true
		CFLAGS="-O2 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Werror=format-security" make
	) > "$output_file" 2>&1

	cat "$output_file" >> "$REPORT_FILE"

	if grep -Eiq "warning:|error:" "$output_file"; then
		warn "Compiler produced warnings/errors"
	else
		pass "Compiler warning build completed cleanly"
	fi
}

check_asan_build() {
	section "ASAN/UBSAN build"

	if ! command_exists make; then
		warn "make not installed"
		return
	fi

	local output_file="$REPORT_DIR/asan-build-$TIMESTAMP.txt"

	(
		cd "$ROOT_DIR" || exit 1
		make clean >/dev/null 2>&1 || true
		CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wformat=2 -Werror=format-security" LDFLAGS="-fsanitize=address,undefined" make
	) > "$output_file" 2>&1

	cat "$output_file" >> "$REPORT_FILE"

	if grep -Eiq "error:" "$output_file"; then
		warn "ASAN/UBSAN build failed"
	else
		pass "ASAN/UBSAN build completed"
	fi
}

curl_status() {
	local url="$1"

	curl -k -s -o /tmp/rpsiod-check-body.tmp -w "%{http_code}" --max-time 10 -H "Host: $HOST_HEADER" "$url"
}

check_http_security() {
	section "HTTP security request tests"

	local paths=(
		"/.env"
		"/composer.json"
		"/composer.lock"
		"/.git/config"
		"/.htaccess"
		"/../.env"
		"/../../etc/passwd"
		"/%2e%2e/%2e%2e/etc/passwd"
		"/..%2f..%2fetc%2fpasswd"
		"/%252e%252e/%252e%252e/etc/passwd"
		"/.%2e/.%2e/etc/passwd"
	)

	for path in "${paths[@]}"; do
		local status
		local body

		status="$(curl_status "$TARGET_URL$path")"
		body="$(cat /tmp/rpsiod-check-body.tmp 2>/dev/null || true)"

		if echo "$body" | grep -q "root:x:"; then
			fail "$path exposed /etc/passwd-like content"
		elif echo "$body" | grep -qi "SECRET\\|DB_PASSWORD\\|APP_KEY"; then
			fail "$path exposed secret-looking content"
		elif [ "$status" = "400" ] || [ "$status" = "403" ] || [ "$status" = "404" ]; then
			pass "$path blocked with $status"
		else
			warn "$path returned $status"
		fi
	done
}

check_malformed_headers() {
	section "Malformed header tests"

	if ! command_exists nc; then
		warn "nc not installed"
		return
	fi

	local response

	response="$(printf 'GET / HTTP/1.1\r\nHost: %s\r\nBad Header: value\r\n\r\n' "$HOST_HEADER" | nc -w 5 127.0.0.1 80 2>/dev/null | head -n 1 || true)"

	if echo "$response" | grep -q "400"; then
		pass "Header name with space rejected"
	elif [ -z "$response" ]; then
		warn "No response for malformed header test"
	else
		warn "Header name with space response: $response"
	fi

	response="$(printf 'GET / HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' "$HOST_HEADER" | nc -w 5 127.0.0.1 80 2>/dev/null | head -n 1 || true)"

	if echo "$response" | grep -q "400"; then
		pass "Content-Length + Transfer-Encoding rejected"
	elif [ -z "$response" ]; then
		warn "No response for CL+TE test"
	else
		warn "CL+TE response: $response"
	fi

	response="$(printf 'TRACE / HTTP/1.1\r\nHost: %s\r\n\r\n' "$HOST_HEADER" | nc -w 5 127.0.0.1 80 2>/dev/null | head -n 1 || true)"

	if echo "$response" | grep -Eq "403|405|501"; then
		pass "TRACE blocked"
	elif [ -z "$response" ]; then
		warn "No response for TRACE test"
	else
		warn "TRACE response: $response"
	fi
}

check_php_chunk_leak() {
	section "PHP chunk framing leak test"

	local output_file="$REPORT_DIR/php-messages-$TIMESTAMP.out"
	local status_file="$REPORT_DIR/php-messages-$TIMESTAMP.status"
	local status

	status="$(curl -k -s --max-time 15 -o "$output_file" -w "%{http_code}" -H "Host: $HOST_HEADER" "$PHP_TEST_URL")"
	printf '%s\n' "$status" > "$status_file"

	if [ "$status" = "404" ]; then
		pass "PHP messages endpoint not present; chunk framing test skipped"
		return
	fi

	if [ "$status" != "200" ]; then
		warn "PHP messages endpoint returned $status"
		return
	fi

	if head -n 3 "$output_file" | grep -q "var Messages"; then
		pass "PHP messages body starts correctly"
	else
		warn "PHP messages body does not start with expected var Messages"
	fi

	if grep -nE '^[0-9a-fA-F]+$' "$output_file" | head -n 10 >> "$REPORT_FILE"; then
		warn "Possible raw chunk-size lines found in PHP output"
	else
		pass "No standalone hex chunk-size lines found in PHP output"
	fi

	if grep -q "<?php" "$output_file"; then
		fail "PHP source code exposed in response"
	else
		pass "PHP source code not exposed"
	fi
}

check_headers() {
	section "Header checks"

	local headers_file="$REPORT_DIR/headers-$TIMESTAMP.txt"

	curl -k -s -I --max-time 10 -H "Host: $HOST_HEADER" "$TARGET_URL$HEADER_PATH" > "$headers_file"

	cat "$headers_file" >> "$REPORT_FILE"

	if grep -qi "^server:" "$headers_file"; then
		warn "Server header is present"
	else
		pass "Server header is hidden"
	fi

	if grep -qi "^x-content-type-options:" "$headers_file"; then
		pass "X-Content-Type-Options present"
	else
		warn "X-Content-Type-Options missing"
	fi

	if grep -qi "^x-frame-options:" "$headers_file"; then
		pass "X-Frame-Options present"
	else
		warn "X-Frame-Options missing"
	fi

	if grep -qi "^strict-transport-security:" "$headers_file"; then
		pass "HSTS present"
	else
		warn "HSTS missing"
	fi
}

check_tls() {
	section "TLS checks"

	if ! command_exists openssl; then
		warn "openssl not installed"
		return
	fi

	local host
	host="$(echo "$TARGET_URL" | sed -E 's#^https?://##; s#/.*##')"

	if [ -z "$host" ]; then
		warn "Could not parse host from TARGET_URL"
		return
	fi

	if echo | openssl s_client -connect "$host:443" -tls1_3 -servername "$host" >/dev/null 2>&1; then
		pass "TLS 1.3 works"
	else
		warn "TLS 1.3 failed"
	fi

	if echo | openssl s_client -connect "$host:443" -tls1_2 -servername "$host" >/dev/null 2>&1; then
		pass "TLS 1.2 works"
	else
		warn "TLS 1.2 failed"
	fi

	if echo | openssl s_client -connect "$host:443" -tls1_1 -servername "$host" >/dev/null 2>&1; then
		fail "TLS 1.1 is enabled"
	else
		pass "TLS 1.1 is disabled"
	fi

	if echo | openssl s_client -connect "$host:443" -tls1 -servername "$host" >/dev/null 2>&1; then
		fail "TLS 1.0 is enabled"
	else
		pass "TLS 1.0 is disabled"
	fi
}

check_runtime_tools() {
	section "Runtime tool checks"

	if command_exists rpsiod; then
		if rpsiod configtest >> "$REPORT_FILE" 2>&1; then
			pass "rpsiod configtest passed"
		else
			fail "rpsiod configtest failed"
		fi

		if rpsiod doctor >> "$REPORT_FILE" 2>&1; then
			pass "rpsiod doctor passed"
		else
			warn "rpsiod doctor reported issues"
		fi
	else
		warn "rpsiod command not found in PATH"
	fi
}

check_wrk_smoke() {
	section "wrk smoke benchmark"

	if ! command_exists wrk; then
		warn "wrk not installed"
		return
	fi

	local output_file="$REPORT_DIR/wrk-$TIMESTAMP.txt"

	wrk -t4 -c100 -d10s -H "Host: $HOST_HEADER" "$LOCAL_URL/index.html" > "$output_file" 2>&1

	cat "$output_file" >> "$REPORT_FILE"

	if grep -qi "Non-2xx\\|Socket errors\\|timeout" "$output_file"; then
		warn "wrk reported possible errors"
	else
		pass "wrk smoke benchmark completed without obvious errors"
	fi
}

check_fd_leak() {
	section "Quick FD leak check"

	local pid
	pid="$(pidof rpsiod || true)"

	if [ -z "$pid" ]; then
		warn "rpsiod process not found"
		return
	fi

	local before
	local after

	before="$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)"

	for i in $(seq 1 500); do
		curl -k -s -o /dev/null --max-time 3 -H "Host: $HOST_HEADER" "$LOCAL_URL/index.html" || true
	done

	sleep 2

	after="$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)"

	log "FD before: $before"
	log "FD after:  $after"

	if [ "$after" -le $((before + 20)) ]; then
		pass "No obvious FD leak"
	else
		warn "FD count increased noticeably"
	fi
}

check_project_files() {
	section "Project file checks"

	check_file_exists "$ROOT_DIR/.gitignore"
	check_file_exists "$ROOT_DIR/Makefile"
	check_file_exists "$ROOT_DIR/rpsiod.service"
	check_file_exists "$ROOT_DIR/config/server.yml"
	check_file_exists "$ROOT_DIR/config/sites.yml"

	if find "$ROOT_DIR" -path "$ROOT_DIR/build" -prune -o -name "*.o" -print | grep -q .; then
		warn "Object files are present outside build/"
	else
		pass "No object files found outside build/"
	fi

	if [ -f "$ROOT_DIR/rpsiod" ]; then
		warn "Built binary exists in repo root"
	else
		pass "No built binary in repo root"
	fi

	if [ -f "$ROOT_DIR/build/rpsiod" ]; then
		pass "Built binary is under build/"
	else
		warn "build/rpsiod does not exist"
	fi
}

print_summary() {
	section "Summary"

	log "Report: $REPORT_FILE"
	log "Passed: $PASSED"
	log "Warnings: $WARNED"
	log "Failed: $FAILED"

	if [ "$FAILED" -gt 0 ]; then
		log "${RED}Security check completed with failures.${RESET}"
		exit 1
	fi

	if [ "$WARNED" -gt 0 ]; then
		log "${YELLOW}Security check completed with warnings.${RESET}"
		exit 0
	fi

	log "${GREEN}Security check completed cleanly.${RESET}"
}

main() {
	section "rpsiod simple issue checker"

	log "Started: $(date)"
	log "ROOT_DIR=$ROOT_DIR"
	log "SRC_DIR=$SRC_DIR"
	log "TARGET_URL=$TARGET_URL"
	log "LOCAL_URL=$LOCAL_URL"
	log "HOST_HEADER=$HOST_HEADER"
	log "HEADER_PATH=$HEADER_PATH"
	log "PHP_TEST_URL=$PHP_TEST_URL"

	check_project_files
	check_dangerous_c_functions
	check_known_cppcheck_patterns
	check_cppcheck
	check_build_warnings
	check_asan_build
	check_runtime_tools
	check_http_security
	check_malformed_headers
	check_php_chunk_leak
	check_headers
	check_tls
	check_wrk_smoke
	check_fd_leak
	print_summary
}

main

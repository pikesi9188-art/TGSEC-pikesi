#!/usr/bin/env bash
# Decrypt Jasypt ENC(...) using vendor JRE + jasypt.jar
# Usage: jasypt_decrypt.sh <password> <ENC_ciphertext_or_plain_ENC(...)> [algorithm]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAVA="$("$ROOT/bin/resolve_java.sh" 2>/dev/null || true)"
JAR="$ROOT/vendor/jasypt-1.9.3.jar"
if [[ -z "${JAVA:-}" || ! -x "$JAVA" ]]; then
  echo "missing JRE; run: bash $ROOT/bin/install_vendor.sh" >&2
  exit 1
fi
PASS="$1"
CT="$2"
ALG="${3:-PBEWITHSHA1ANDRC2_40}"
# strip ENC(...) wrapper if present
if [[ "$CT" == ENC\(*\) ]]; then
  CT="${CT#ENC(}"
  CT="${CT%)}"
fi
# jasypt CLI: org.jasypt.intf.cli.JasyptPBEStringDecryptionCLI
"$JAVA" -cp "$JAR" org.jasypt.intf.cli.JasyptPBEStringDecryptionCLI \
  input="$CT" password="$PASS" algorithm="$ALG" \
  ivGeneratorClassName=org.jasypt.iv.NoIvGenerator

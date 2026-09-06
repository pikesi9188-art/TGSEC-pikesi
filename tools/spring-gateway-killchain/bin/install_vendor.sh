#!/usr/bin/env bash
# Install Temurin 17 JRE + jasypt into tools/spring-gateway-killchain/vendor
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor"
mkdir -p "$VENDOR"
cd "$VENDOR"

if [[ ! -f jasypt-1.9.3.jar ]]; then
  curl -fsSL -o jasypt-1.9.3.jar \
    "https://repo1.maven.org/maven2/org/jasypt/jasypt/1.9.3/jasypt-1.9.3.jar"
  echo "[+] jasypt-1.9.3.jar"
fi

if [[ ! -x jdk-17/bin/java ]]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    arm64|aarch64) A=aarch64 ;;
    *) A=x64 ;;
  esac
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$OS" in
    darwin) PLAT=mac ;;
    linux) PLAT=linux ;;
    *) echo "unsupported OS: $OS"; exit 1 ;;
  esac
  URL="https://api.adoptium.net/v3/binary/latest/17/ga/${PLAT}/${A}/jre/hotspot/normal/eclipse?project=jdk"
  echo "[*] downloading Temurin 17 JRE ($PLAT/$A) ..."
  curl -fL -o temurin17.tar.gz "$URL"
  rm -rf jdk-17
  mkdir -p jdk-17
  tar -xzf temurin17.tar.gz -C jdk-17 --strip-components=1
  rm -f temurin17.tar.gz
  # macOS tarball keeps Contents/Home; expose flat bin/ for scripts
  if [[ -x jdk-17/Contents/Home/bin/java && ! -x jdk-17/bin/java ]]; then
    ln -sfn Contents/Home/bin jdk-17/bin
  fi
  ./jdk-17/bin/java -version || ./jdk-17/Contents/Home/bin/java -version
fi

# ensure flat java path after prior mac installs
if [[ -x jdk-17/Contents/Home/bin/java && ! -x jdk-17/bin/java ]]; then
  ln -sfn Contents/Home/bin jdk-17/bin
fi

echo "[+] vendor ready: $VENDOR"
JAVA="$VENDOR/jdk-17/bin/java"
[[ -x "$JAVA" ]] || JAVA="$VENDOR/jdk-17/Contents/Home/bin/java"
"$JAVA" -version


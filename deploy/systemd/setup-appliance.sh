#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

if [[ ! -f "${REPO_ROOT}/go.mod" || ! -f "${REPO_ROOT}/ui/package.json" ]]; then
  echo "Repository root not detected at: ${REPO_ROOT}" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This setup helper currently supports Debian/Ubuntu systems (apt-get)." >&2
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

version_ge() {
  local a b
  a="$1"
  b="$2"
  if [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | tail -n1)" == "$a" ]]; then
    return 0
  fi
  return 1
}

parse_go_req() {
  awk '/^go[[:space:]]+[0-9]+\.[0-9]+(\.[0-9]+)?/{print $2; exit}' "${REPO_ROOT}/go.mod"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

install_base_packages() {
  echo "[1/8] Installing base packages"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl git build-essential unzip tar xz-utils gnupg lsb-release
}

install_node() {
  local node_major
  if need_cmd node; then
    node_major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
    if [[ "${node_major}" -ge 18 ]]; then
      echo "[2/8] Node.js already present: $(node -v)"
      if ! need_cmd npm; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y npm
      fi
      return
    fi
  fi
  echo "[2/8] Installing Node.js 20.x + npm"
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
}

install_go() {
  local required current arch tarball url tmpdir
  required="$(parse_go_req)"
  if [[ -z "${required}" ]]; then
    echo "Unable to parse required Go version from go.mod" >&2
    exit 1
  fi
  if need_cmd go; then
    current="$(go version | awk '{print $3}' | sed 's/^go//')"
    if version_ge "${current}" "${required}"; then
      echo "[3/8] Go already present: ${current} (required: ${required})"
      return
    fi
  fi
  arch="$(detect_arch)"
  tarball="go${required}.linux-${arch}.tar.gz"
  url="https://go.dev/dl/${tarball}"
  echo "[3/8] Installing Go ${required} (${arch})"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT
  curl -fsSL "${url}" -o "${tmpdir}/${tarball}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${tmpdir}/${tarball}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  rm -rf "${tmpdir}"
  trap - EXIT
}

build_project() {
  echo "[4/8] Installing UI dependencies"
  (cd "${REPO_ROOT}" && npm --prefix ui install)
  echo "[5/8] Building UI"
  (cd "${REPO_ROOT}" && npm --prefix ui run build)
  echo "[6/8] Building DomNexDomain binary"
  (cd "${REPO_ROOT}" && go build -o build/domnexdomain ./cmd/domnexdomain)
}

install_service() {
  echo "[7/8] Installing systemd service"
  "${REPO_ROOT}/deploy/systemd/install-baremetal.sh" "${REPO_ROOT}/build/domnexdomain"
}

final_hint() {
  echo "[8/8] Done"
  echo "Open: https://<server-ip>:8443"
  echo "If setup is locked, use the OTS from:"
  echo "journalctl -u domnexdomain -n 200 --no-pager | grep 'initial setup locked'"
}

install_base_packages
install_node
install_go
build_project
install_service
final_hint


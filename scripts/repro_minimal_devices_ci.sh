#!/usr/bin/env bash

set -euo pipefail

IMAGE="${FENCE_REPRO_IMAGE:-golang:1.25-bookworm}"

echo "=== Host diagnostics ==="
echo "pwd: $PWD"
echo "kernel: $(uname -r)"
docker version --format 'docker server={{.Server.Version}} client={{.Client.Version}}'
docker info --format 'docker os={{.OperatingSystem}} kernel={{.KernelVersion}} cgroup={{.CgroupVersion}}'

docker run --rm \
  --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v "$PWD":/src \
  -w /src \
  "$IMAGE" \
  sh -c '
    set -eu

    echo "=== Container diagnostics ==="
    echo "kernel: $(uname -r)"
    echo "user: $(id)"

    apt-get update
    apt-get install -y bubblewrap socat
    if ! command -v python3 >/dev/null 2>&1; then
      apt-get install -y python3
    fi

    VENV_PROBE_DIR="$(mktemp -d /tmp/fence-venv-probe.XXXXXX)"
    if ! python3 -m venv "${VENV_PROBE_DIR}" >/tmp/fence-venv-probe.log 2>&1; then
      PYTHON_VENV_PACKAGE="$(python3 - <<'"'"'PY'"'"'
import sys
print(f"python{sys.version_info.major}.{sys.version_info.minor}-venv")
PY
)"
      if ! apt-get install -y "${PYTHON_VENV_PACKAGE}" python3-venv; then
        apt-get install -y "${PYTHON_VENV_PACKAGE}" || apt-get install -y python3-venv
      fi
      rm -rf "${VENV_PROBE_DIR}"
      python3 -m venv "${VENV_PROBE_DIR}"
    fi
    rm -rf "${VENV_PROBE_DIR}" /tmp/fence-venv-probe.log

    if [ -x /src/fence-repro-bin ] && /src/fence-repro-bin --version >/dev/null 2>&1; then
      install -m 0755 /src/fence-repro-bin /usr/local/bin/fence
    elif command -v go >/dev/null 2>&1; then
      go build -buildvcs=false -o /usr/local/bin/fence ./cmd/fence
    else
      echo "No usable Linux fence binary found at /src/fence-repro-bin and Go is unavailable in the container" >&2
      exit 1
    fi
    VENV_DIR="$(mktemp -d /src/.fence-repro-venv.XXXXXX)"
    trap "rm -rf \"${VENV_DIR}\"" EXIT
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/python" -m pip install -q grpcio
    PYTHON_BIN="${VENV_DIR}/bin/python"

    cat >/tmp/fence.json <<'"'"'EOF'"'"'
{"devices":{"mode":"minimal"}}
EOF

    cat >/tmp/fence-replay-like.json <<'"'"'EOF'"'"'
{
  "devices": { "mode": "minimal" },
  "network": {
    "allowedDomains": ["localhost", "127.0.0.1"],
    "allowLocalBinding": true,
    "allowLocalOutbound": false,
    "allowAllUnixSockets": true
  },
  "filesystem": {
    "allowWrite": ["/src", "/tmp"]
  }
}
EOF

    echo "=== Device probe under fence (baseline) ==="
    device_status=0
    /usr/local/bin/fence --settings /tmp/fence.json -- "${PYTHON_BIN}" - <<'"'"'PY'"'"' || device_status=$?
import os
import stat
import sys

failures = 0

print(f"uid={os.getuid()} euid={os.geteuid()} cwd={os.getcwd()}")
print("/dev entries:", ", ".join(sorted(os.listdir("/dev"))))

for path in ("/dev/null", "/dev/random", "/dev/urandom"):
    st = os.stat(path)
    kind = "char" if stat.S_ISCHR(st.st_mode) else "other"
    device_id = "-"
    if stat.S_ISCHR(st.st_mode):
        device_id = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
    print(f"{path} mode={oct(stat.S_IMODE(st.st_mode))} kind={kind} rdev={device_id}")
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
        print(path, "ok")
    except OSError as exc:
        print(path, f"errno={exc.errno} strerror={exc.strerror}")
        failures += 1

print("getrandom:", len(os.getrandom(1)))
sys.exit(1 if failures else 0)
PY
    echo "device_status(baseline)=${device_status}"

    replay_device_status=0
    echo "=== Device probe under fence (replay-like) ==="
    /usr/local/bin/fence -p 8000 --settings /tmp/fence-replay-like.json -- "${PYTHON_BIN}" - <<'"'"'PY'"'"' || replay_device_status=$?
import os
import stat
import sys

failures = 0

print(f"uid={os.getuid()} euid={os.geteuid()} cwd={os.getcwd()}")
print("/dev entries:", ", ".join(sorted(os.listdir("/dev"))))

for path in ("/dev/null", "/dev/random", "/dev/urandom"):
    st = os.stat(path)
    kind = "char" if stat.S_ISCHR(st.st_mode) else "other"
    device_id = "-"
    if stat.S_ISCHR(st.st_mode):
        device_id = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
    print(f"{path} mode={oct(stat.S_IMODE(st.st_mode))} kind={kind} rdev={device_id}")
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
        print(path, "ok")
    except OSError as exc:
        print(path, f"errno={exc.errno} strerror={exc.strerror}")
        failures += 1

print("getrandom:", len(os.getrandom(1)))
sys.exit(1 if failures else 0)
PY
    echo "device_status(replay-like)=${replay_device_status}"

    echo "=== gRPC startup probe under fence (baseline) ==="
    grpc_status=0
    /usr/local/bin/fence --settings /tmp/fence.json -- "${PYTHON_BIN}" - <<'"'"'PY'"'"' || grpc_status=$?
from concurrent import futures

import grpc

print("before grpc.server()", flush=True)
server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
print("after grpc.server()", flush=True)
port = server.add_insecure_port("[::]:50051")
print(f"add_insecure_port={port}", flush=True)
server.start()
print("after server.start()", flush=True)
server.stop(0)
print("after server.stop()", flush=True)
PY
    echo "grpc_status(baseline)=${grpc_status}"

    replay_grpc_status=0
    echo "=== gRPC startup probe under fence (replay-like) ==="
    /usr/local/bin/fence -p 8000 --settings /tmp/fence-replay-like.json -- "${PYTHON_BIN}" - <<'"'"'PY'"'"' || replay_grpc_status=$?
from concurrent import futures

import grpc

print("before grpc.server()", flush=True)
server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
print("after grpc.server()", flush=True)
port = server.add_insecure_port("[::]:50051")
print(f"add_insecure_port={port}", flush=True)
server.start()
print("after server.start()", flush=True)
server.stop(0)
print("after server.stop()", flush=True)
PY
    echo "grpc_status(replay-like)=${replay_grpc_status}"

    if [ "${device_status}" -ne 0 ] || \
       [ "${replay_device_status}" -ne 0 ] || \
       [ "${grpc_status}" -ne 0 ] || \
       [ "${replay_grpc_status}" -ne 0 ]; then
      echo "=== Reproducer detected a failure ==="
      exit 1
    fi

    echo "=== Reproducer did not detect the issue ==="
  '

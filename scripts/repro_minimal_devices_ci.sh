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
  bash -c '
    set -euo pipefail

    echo "=== Container diagnostics ==="
    echo "kernel: $(uname -r)"
    echo "user: $(id)"

    apt-get update
    apt-get install -y bubblewrap socat python3 python3-pip

    go build -o /usr/local/bin/fence ./cmd/fence
    python3 -m pip install -q grpcio

    cat >/tmp/fence.json <<'"'"'EOF'"'"'
{"devices":{"mode":"minimal"}}
EOF

    echo "=== Device probe under fence ==="
    device_status=0
    /usr/local/bin/fence --settings /tmp/fence.json -- python3 - <<'"'"'PY'"'"' || device_status=$?
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
    echo "device_status=${device_status}"

    echo "=== gRPC startup probe under fence ==="
    grpc_status=0
    /usr/local/bin/fence --settings /tmp/fence.json -- python3 - <<'"'"'PY'"'"' || grpc_status=$?
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
    echo "grpc_status=${grpc_status}"

    if [ "${device_status}" -ne 0 ] || [ "${grpc_status}" -ne 0 ]; then
      echo "=== Reproducer detected a failure ==="
      exit 1
    fi

    echo "=== Reproducer did not detect the issue ==="
  '

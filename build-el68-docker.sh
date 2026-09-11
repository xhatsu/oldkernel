#!/bin/sh
# build-el68-docker.sh — Build native CentOS 6.8 x86_64 binaries in Docker
# and assemble the self-contained installer bundle.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"

echo "=== 1. Ensuring CentOS 6.8 builder Docker image ==="
docker build --platform linux/amd64 -t centos68-builder:latest -f Dockerfile.el68 .

echo "=== 2. Compiling native C++03 binaries inside CentOS 6.8 container ==="
mkdir -p bin/el68-x86_64
docker run --platform linux/amd64 --rm -v "$HERE:/build" centos68-builder:latest sh -c "
set -eu
echo 'Compiling nt-sniff-cpp...'
g++ -O2 -Wall -Wextra -std=gnu++98 -pthread nt-sniff-cpp.cpp -lrt -o bin/el68-x86_64/nt-sniff-cpp
echo 'Compiling nt-ship-cpp...'
g++ -O2 -Wall -Wextra -std=gnu++98 -pthread nt-ship-cpp.cpp -lrt -o bin/el68-x86_64/nt-ship-cpp
strip bin/el68-x86_64/nt-sniff-cpp bin/el68-x86_64/nt-ship-cpp
"

echo "=== 3. Verifying binaries against stock minimal CentOS 6.8 image ==="
docker run --platform linux/amd64 --rm -v "$HERE:/build" centos:6.8 sh -c "
set -eu
/build/bin/el68-x86_64/nt-sniff-cpp --help >/dev/null 2>&1 || exit 1
/build/bin/el68-x86_64/nt-ship-cpp --help >/dev/null 2>&1 || exit 1
echo 'Stock CentOS 6.8 execution verified successfully.'
"

echo "=== 4. Packaging self-contained first-run installer bundle ==="
sh build-firstrun.sh

if [ -f "ansible/stage-bundle.sh" ]; then
    echo "=== 5. Refreshing Ansible staged bundle ==="
    sh ansible/stage-bundle.sh
fi

echo "=== Build & Package Complete ==="
ls -lh bin/el68-x86_64/
ls -lh install-firstrun-el68.sh

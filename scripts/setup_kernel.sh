#!/bin/bash
# Setup eBPF/BCC environment on Linux (Ubuntu 20.04+ / Debian 11+)
set -e

echo "🔧 Setting up eBPF/BCC kernel monitoring environment..."

# Check if running on Linux
if [[ ! "$OSTYPE" =~ linux ]]; then
    echo "❌ This setup script is Linux-only (eBPF requirement)."
    exit 1
fi

# Check kernel version (5.4+ required)
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
REQUIRED_VERSION="5.4"
if ! awk "BEGIN {exit !($KERNEL_VERSION >= $REQUIRED_VERSION)}"; then
    echo "⚠️  Kernel version $KERNEL_VERSION detected. Recommended: 5.4+"
fi

echo "📦 Installing dependencies..."
sudo apt-get update

# Install build essentials
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libz-dev \
    pkg-config

# Install Linux headers.
# On WSL2, exact kernel header packages are usually unavailable in apt repos.
KERNEL_RELEASE=$(uname -r)
if echo "$KERNEL_RELEASE" | grep -qi "microsoft"; then
    echo "⚠️  WSL2 kernel detected: $KERNEL_RELEASE"
    echo "   Skipping linux-headers-$KERNEL_RELEASE (not available in standard apt repos)."
    echo "   Installing fallback headers/tooling for userspace BCC development..."
    sudo apt-get install -y \
        linux-headers-generic \
        linux-libc-dev
else
    # Install exact headers on standard Linux distributions
    sudo apt-get install -y \
        linux-headers-$(uname -r)
fi

# Install BCC (eBPF toolchain)
sudo apt-get install -y \
    bpftrace \
    linux-headers-generic

# Install BCC development headers (name differs by distro release)
if apt-cache show libbcc-dev >/dev/null 2>&1; then
    sudo apt-get install -y libbcc-dev
elif apt-cache show libbpfcc-dev >/dev/null 2>&1; then
    sudo apt-get install -y libbpfcc-dev
else
    echo "❌ Could not find BCC dev package (libbcc-dev or libbpfcc-dev)."
    echo "   Enable universe repo or install BCC from source for this distro."
    exit 1
fi

# Install BCC Python bindings
echo "📦 Installing BCC Python bindings..."
if apt-cache show python3-bcc >/dev/null 2>&1; then
    sudo apt-get install -y python3-bcc
elif apt-cache show python3-bpfcc >/dev/null 2>&1; then
    sudo apt-get install -y python3-bpfcc
else
    echo "❌ Could not find Python BCC bindings (python3-bcc or python3-bpfcc)."
    echo "   Check distro repositories or install BCC Python bindings manually."
    exit 1
fi

echo "✅ eBPF/BCC setup complete!"
echo "   - clang, llvm, kernel headers installed"
echo "   - BCC Python bindings ready"
echo ""
echo "⚡ Verify setup:"
echo "   $ clang --version"
echo "   $ python3 -c 'from bcc import BPF'"
echo ""
echo "🔨 Compiling eBPF program..."
cd "$(dirname "$0")/../kernel"
if make check; then
    echo "✅ All eBPF build tools verified"
    make clean
    make all
    echo "✅ eBPF program compiled: $(pwd)/.output/execve_hook.o"
else
    echo "⚠️  eBPF build check failed - see above for details"
    exit 1
fi
echo ""
echo "🎉 Kernel Guard Phase 2 setup complete!"
echo "   Ready to monitor execve syscalls with eBPF"

#!/bin/bash
# Development setup script for Ouroboros
# This script sets up the development environment for the Bitcoin node

set -e  # Exit on error

echo "🚀 Setting up Ouroboros development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if running on Linux, macOS, or Windows (WSL)
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)

# 1. Install Rust toolchain
echo ""
echo "📦 Step 1: Installing Rust toolchain..."

if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version)
    print_status "Rust is already installed: $RUST_VERSION"

    # Check if rustup is installed
    if command -v rustup &> /dev/null; then
        echo "  Updating Rust toolchain (this may fail, but existing version should work)..."
        if rustup update stable 2>/dev/null; then
            print_status "Rust toolchain updated"
        else
            print_warning "Rust update failed, but existing version should work fine"
        fi
        
        # Add components (ignore errors if already installed)
        rustup component add rustfmt clippy 2>/dev/null || true
    fi
else
    print_warning "Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    rustup component add rustfmt clippy
    print_status "Rust installed successfully"
fi

# 2. Install system dependencies
echo ""
echo "📦 Step 2: Installing system dependencies..."

if [ "$OS" == "linux" ]; then
    if command -v apt-get &> /dev/null; then
        print_status "Installing dependencies with apt-get (Ubuntu/Debian)..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            gcc \
            g++ \
            clang \
            libclang-dev \
            libssl-dev \
            pkg-config \
            python3-dev \
            python3-pip \
            python3-venv \
            libsnappy-dev \
            zlib1g-dev \
            libbz2-dev \
            liblz4-dev \
            libzstd-dev
    elif command -v dnf &> /dev/null; then
        print_status "Installing dependencies with dnf (Fedora/RHEL)..."
        sudo dnf install -y \
            gcc \
            gcc-c++ \
            clang \
            glibc-devel \
            openssl-devel \
            pkg-config \
            python3-devel \
            python3-pip \
            snappy-devel \
            zlib-devel \
            bzip2-devel \
            lz4-devel \
            libzstd-devel
    elif command -v yum &> /dev/null; then
        print_status "Installing dependencies with yum (RHEL/CentOS)..."
        sudo yum install -y \
            gcc \
            gcc-c++ \
            clang \
            glibc-devel \
            openssl-devel \
            pkg-config \
            python3-devel \
            python3-pip \
            snappy-devel \
            zlib-devel \
            bzip2-devel \
            lz4-devel \
            zstd-devel
    else
        print_warning "Package manager not recognized. Please install dependencies manually:"
        echo "  - build-essential / gcc, g++, clang"
        echo "  - libclang-dev"
        echo "  - libssl-dev"
        echo "  - pkg-config"
        echo "  - python3-dev, python3-pip"
        echo "  - Compression libraries: snappy, zlib, bzip2, lz4, zstd"
    fi
elif [ "$OS" == "macos" ]; then
    if command -v brew &> /dev/null; then
        print_status "Installing dependencies with Homebrew (macOS)..."
        brew install snappy zstd lz4 openssl pkg-config
    else
        print_warning "Homebrew not found. Please install dependencies manually:"
        echo "  brew install snappy zstd lz4 openssl pkg-config"
    fi
else
    print_warning "OS not recognized. Please install dependencies manually."
fi

# 3. Check Python version
echo ""
echo "📦 Step 3: Checking Python installation..."

if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_status "Python found: $PYTHON_VERSION"

    # Check if Python version is >= 3.10
    PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
        print_error "Python 3.10+ is required. Found Python $PYTHON_MAJOR.$PYTHON_MINOR"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.10 or later."
    exit 1
fi

# 4. Create virtual environment (optional, but recommended)
echo ""
echo "📦 Step 4: Setting up Python virtual environment..."

if [ -d ".venv" ]; then
    print_status "Virtual environment already exists"
else
    print_status "Creating virtual environment..."
    python3 -m venv .venv
    print_status "Virtual environment created"
fi

# Activate virtual environment
source .venv/bin/activate
print_status "Virtual environment activated"

# 5. Upgrade pip and install build tools
echo ""
echo "📦 Step 5: Installing Python build tools..."

pip install --upgrade pip setuptools wheel
# patchelf silences maturin's rpath warning on Linux; harmless on macOS.
pip install maturin patchelf
print_status "Python build tools installed"

# 6. Build the Rust extension module first (installs `sync` as its own package)
#
# IMPORTANT: Order matters here. The `sync` extension MUST be installed before
# the `ouroboros` Python package, because both are editable and maturin uses
# ferrous-utils/sync/pyproject.toml (which declares name="sync") to keep the
# two distributions independent. If we install ouroboros first and then run
# maturin, maturin-generated editable metadata can overwrite or interact with
# pip's editable registration in confusing ways. Installing sync first, then
# pip-installing ouroboros last, gives the clean final state:
#   - sync.so       — editable from ferrous-utils/sync/ (maturin)
#   - ouroboros/    — editable from src/ouroboros/    (pip setuptools)
echo ""
echo "📦 Step 6: Building Rust extension module with maturin..."

# Verify Rust workspace compiles
print_status "Verifying Rust workspace..."
cargo check --workspace

# maturin develop needs to be run from the subdirectory that owns the
# pyproject.toml describing the sync package.
print_status "Building Rust extension module with maturin..."
(
    cd ferrous-utils/sync
    maturin develop --release
)

print_status "Rust extension module built successfully"

# 7. Install Python dependencies (AFTER the Rust extension is in place)
echo ""
echo "📦 Step 7: Installing Python dependencies..."

pip install -e ".[dev]"
print_status "Python dependencies installed"

# Verify Rust module can be imported
if python3 -c "from sync import SyncEngine; print('✓ Rust module imports successfully')" 2>/dev/null; then
    print_status "Rust extension module verified"
else
    print_warning "Rust module import check failed - this may be normal if not yet built"
fi

# 8. Verify installation
echo ""
echo "📦 Step 8: Verifying installation..."

if python3 -c "import ouroboros; print(f'✓ Package version: {ouroboros.__version__}')" 2>/dev/null; then
    print_status "Package imports successfully"
else
    print_warning "Package import check failed (this may be normal if Rust module needs to be imported differently)"
fi

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✓ Development environment setup complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Activate the virtual environment:"
echo "     source .venv/bin/activate"
echo ""
echo "  2. Run tests:"
echo "     cargo test --workspace"
echo "     pytest"
echo ""
echo "  3. Start development:"
echo "     ouroboros --help"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

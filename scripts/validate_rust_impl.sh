#!/bin/bash
# Script to validate Rust implementation before Python integration

set -e

echo "=========================================="
echo "Rust Implementation Validation"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

# Function to check command result
check_result() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1"
        ERRORS=$((ERRORS + 1))
    fi
}

# Function to check warning
check_warning() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${YELLOW}⚠${NC} $1"
        WARNINGS=$((WARNINGS + 1))
    fi
}

echo "1. Checking code format..."
cargo fmt -- --check 2>&1 | grep -q "Diff" && {
    echo -e "${RED}✗${NC} Code formatting issues found"
    echo "   Run: cargo fmt"
    ERRORS=$((ERRORS + 1))
} || check_result "Code formatting OK"

echo ""
echo "2. Running clippy..."
cargo clippy --workspace -- -D warnings 2>&1 | tee /tmp/clippy_output.txt
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    check_result "Clippy checks passed"
else
    echo -e "${RED}✗${NC} Clippy found issues"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "3. Running unit tests..."
cargo test --workspace --lib 2>&1 | tee /tmp/test_output.txt
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    check_result "Unit tests passed"
else
    echo -e "${RED}✗${NC} Some unit tests failed"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "4. Running integration tests..."
if cargo test --test '*' 2>&1 | tee /tmp/integration_output.txt; then
    check_result "Integration tests passed"
else
    echo -e "${RED}✗${NC} Some integration tests failed"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "5. Checking benchmarks compile..."
if cargo bench --no-run 2>&1 | tee /tmp/bench_output.txt; then
    check_result "Benchmarks compile"
else
    check_warning "Benchmarks have issues (non-critical)"
fi

echo ""
echo "6. Building release version..."
if cargo build --workspace --release 2>&1 | tee /tmp/build_output.txt; then
    check_result "Release build successful"
else
    echo -e "${RED}✗${NC} Release build failed"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "=========================================="
echo "Validation Summary"
echo "=========================================="

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Run benchmarks: cargo bench"
    echo "2. Generate coverage: cargo tarpaulin --workspace"
    echo "3. Test Bitcoin Core compatibility"
    echo "4. Proceed to Python integration"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Checks passed with warnings${NC}"
    echo "Warnings: $WARNINGS"
    echo ""
    echo "Review warnings above and fix if needed."
    exit 0
else
    echo -e "${RED}✗ Validation failed${NC}"
    echo "Errors: $ERRORS"
    echo "Warnings: $WARNINGS"
    echo ""
    echo "Please fix the errors above before proceeding."
    exit 1
fi


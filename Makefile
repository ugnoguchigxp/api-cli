.PHONY: help setup build test lint fmt fmt-check check check-all clean release

help:
	@echo "Available commands:"
	@echo "  setup   - Install required rust components (clippy, rustfmt)"
	@echo "  build   - Build the project (debug)"
	@echo "  test    - Run all tests"
	@echo "  lint    - Run clippy for static analysis"
	@echo "  fmt     - Format code using rustfmt"
	@echo "  fmt-check - Check formatting without modifying files"
	@echo "  check   - Run fmt, lint, and test sequentially"
	@echo "  check-all - Verify both Rust and TypeScript packages"
	@echo "  clean   - Clean build artifacts"
	@echo "  release - Build the project for release"

setup:
	rustup component add clippy rustfmt

build:
	cargo build --locked

test:
	cargo test --all-targets --locked

lint:
	cargo clippy --all-targets --all-features --locked -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --all -- --check

check: fmt-check lint test

check-all: check
	cd server && npm run verify

clean:
	cargo clean

release:
	cargo build --release --locked

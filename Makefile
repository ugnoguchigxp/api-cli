.PHONY: help setup build test lint fmt check clean release

help:
	@echo "Available commands:"
	@echo "  setup   - Install required rust components (clippy, rustfmt)"
	@echo "  build   - Build the project (debug)"
	@echo "  test    - Run all tests"
	@echo "  lint    - Run clippy for static analysis"
	@echo "  fmt     - Format code using rustfmt"
	@echo "  check   - Run fmt, lint, and test sequentially"
	@echo "  clean   - Clean build artifacts"
	@echo "  release - Build the project for release"

setup:
	rustup component add clippy rustfmt

build:
	cargo build

test:
	cargo test

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

check: fmt lint test

clean:
	cargo clean

release:
	cargo build --release

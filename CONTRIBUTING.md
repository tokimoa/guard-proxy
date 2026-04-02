# Contributing to Guard Proxy

Thank you for your interest in contributing to Guard Proxy!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/tokimoa/guard-proxy.git
cd guard-proxy

# Install dependencies
uv sync

# Run tests
uv run pytest

# Run linter
uv run ruff check .
uv run ruff format .
```

## Making Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `uv run pytest`
6. Ensure code is clean: `uv run ruff check . && uv run ruff format --check .`
7. Commit your changes
8. Push to your fork and submit a Pull Request

## Code Style

- Python 3.12+
- Formatted with [ruff](https://docs.astral.sh/ruff/)
- Line length: 120 characters
- Async/await for all I/O operations
- Pydantic v2 for data validation
- Type hints encouraged

## Adding New Detection Patterns

1. Add a test case to `tests/test_benchmark/test_incident_tracking.py`
2. Run the test — it should fail (the pattern isn't detected yet)
3. Add the pattern to the appropriate scanner in `app/scanners/patterns/`
4. Run the test again — it should pass
5. Run the full benchmark suite: `uv run pytest tests/test_benchmark/`
6. Verify zero false positives: `uv run pytest tests/test_benchmark/test_false_positives.py`

## Adding New YARA Rules

1. Add rules to `data/yara_rules/supply_chain.yar`
2. Add a test case to `tests/test_scanners/test_yara_scanner.py`
3. Ensure rules follow the existing naming convention

## Reporting Issues

- **Bugs**: Open a [GitHub issue](https://github.com/tokimoa/guard-proxy/issues)
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md)
- **Feature requests**: Open a GitHub issue with the `enhancement` label

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

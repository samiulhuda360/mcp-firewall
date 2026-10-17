# One command to set up, one to run the demo.
PY ?= python

setup:
	$(PY) -m pip install -e ".[dev]"

demo:
	mcp-firewall demo

check:
	ruff check .
	ruff format --check .
	mypy .
	pytest
	MCP_FIREWALL_OFFLINE=1 mcp-firewall eval
	git diff --exit-code eval/results.md eval/results.json

.PHONY: setup demo check

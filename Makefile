# Local dev convenience: full gate, matching what CI runs.
.PHONY: install lint typecheck test tdd bdd docker-build run

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

lint:
	.venv/bin/ruff check cloudflare_os tests features

typecheck:
	.venv/bin/mypy cloudflare_os

# TDD unit tests
test:
	.venv/bin/pytest -q

# BDD feature tests
bdd:
	.venv/bin/behave features

# Everything CI runs, locally
check: lint typecheck test bdd

docker-build:
	docker build -t mini-cloudflare-os .

run:
	.venv/bin/uvicorn cloudflare_os.main:app --reload

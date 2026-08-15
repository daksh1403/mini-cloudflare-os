# Local dev convenience: full gate, matching what CI runs.
# Deploy to Cloudflare Workers needs CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID.
.PHONY: install lint typecheck test tdd bdd docker-build run deploy worker-install

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

worker-install:
	.venv/bin/pip install -e ".[dev,workers]"

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

# Deploy to Cloudflare Workers (requires wrangler + CF credentials)
deploy: worker-install
	npx wrangler deploy

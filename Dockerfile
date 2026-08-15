# Mini Cloudflare OS — Docker image (deployment target for CI/CD).
# Multi-stage: build stage runs the full TDD+BDD gate; final stage is slim.

FROM python:3.12-slim AS builder
WORKDIR /app

COPY pyproject.toml ./
COPY cloudflare_os ./cloudflare_os
COPY tests ./tests
COPY features ./features

RUN pip install --no-cache-dir .[dev]

# Gate: fail the build if any test, BDD feature, or lint check fails.
RUN ruff check cloudflare_os tests features
RUN mypy cloudflare_os
RUN pytest -q --cov=cloudflare_os --cov-fail-under=80
RUN behave features

FROM python:3.12-slim
WORKDIR /app

COPY pyproject.toml ./
COPY cloudflare_os ./cloudflare_os
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "cloudflare_os.main:app", "--host", "0.0.0.0", "--port", "8000"]

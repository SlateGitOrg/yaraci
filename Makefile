# yaraci developer entry points. `make check` is the single CI gate.
UV ?= uv
RUN := $(UV) run --frozen
SRC := src tests scripts

.PHONY: help sync fmt format-check lint typecheck test coverage examples-check check demo goodware bench clean

help:
	@echo "make check     - format-check + lint + typecheck + tests (coverage >= 80%) + fixture freshness"
	@echo "make demo      - offline end-to-end demo against the bundled example packs"
	@echo "make goodware  - download the pinned OSS goodware corpus into .cache/goodware (network)"
	@echo "make bench     - regenerate the committed profiling benchmark in bench/"

sync:
	$(UV) sync --frozen

fmt:
	$(RUN) ruff format $(SRC)
	$(RUN) ruff check --fix $(SRC)

format-check: sync
	$(RUN) ruff format --check $(SRC)

lint: sync
	$(RUN) ruff check $(SRC)

typecheck: sync
	$(RUN) mypy

test: sync
	$(RUN) pytest --cov=yaraci --cov-report=term-missing --cov-fail-under=80

coverage: test

examples-check: sync
	$(RUN) python scripts/make_examples.py --check
	$(RUN) python scripts/gen_checks_doc.py --check

check: format-check lint typecheck examples-check test

demo: sync
	$(RUN) python -u scripts/demo.py

goodware: sync
	$(RUN) yaraci fetch-goodware --manifest goodware/oss-manifest.toml --dest .cache/goodware

bench: sync
	$(RUN) python -u scripts/bench.py --out bench

clean:
	rm -rf out .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov

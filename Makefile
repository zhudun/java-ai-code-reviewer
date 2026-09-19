.PHONY: install test scan

install:
	python3 -m pip install -e ".[dev]"

test:
	pytest

scan:
	jacr scan examples/vulnerable-shop --fail-on NONE

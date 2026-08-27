PYTHON ?= python3
VENV := .venv
PY := $(VENV)/bin/python

.PHONY: setup test validate evidence status distribution-check clean

setup: $(VENV)/.stamp

$(VENV)/.stamp: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt
	@touch $@

test: $(VENV)/.stamp
	PYTHONDONTWRITEBYTECODE=1 $(PY) -m unittest discover -s tests/github_automation -p 'test_*.py' -v

validate: $(VENV)/.stamp
	PYTHONDONTWRITEBYTECODE=1 $(PY) scripts/validate-github-automation.py

evidence: $(VENV)/.stamp
	PYTHONDONTWRITEBYTECODE=1 $(PY) scripts/build-github-automation-evidence.py --capture-gates

status: $(VENV)/.stamp
	PYTHONDONTWRITEBYTECODE=1 $(PY) scripts/github-automation-status.py

distribution-check:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/check-public-distribution.py
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/check-local-only.py
	PYTHONPYCACHEPREFIX=$(VENV)/pycache $(PYTHON) -m compileall -q actions scripts

clean:
	rm -rf .venv
	find actions github_automation scripts tests -type d -name __pycache__ -prune -exec rm -rf {} +
	find actions github_automation scripts tests -type f -name '*.pyc' -delete

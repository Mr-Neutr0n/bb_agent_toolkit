.PHONY: init validate test lint clean audit secrets release-check doctor help

init:
	@echo "Usage: bin/bb-init <target> [--program NAME] [--scope-file FILE]"
	@echo "Creates .bb/context.env and .bb/context.json for the engagement."

validate:
	python3 tools/validate_skills.py

test:
	@status=0; \
	for skill in $$(ls .claude/skills/); do \
		echo "--- Testing $$skill ---"; \
		python3 -c "import yaml; yaml.safe_load(open('.claude/skills/$$skill/skill.yaml'))" 2>/dev/null && echo "  skill.yaml OK" || { echo "  skill.yaml FAIL"; status=1; }; \
		for script in .claude/skills/$$skill/scripts/*.py; do \
			[ -f "$$script" ] && python3 -m py_compile "$$script" 2>/dev/null && echo "  $$script OK" || { echo "  $$script FAIL"; status=1; }; \
		done; \
	done; \
	exit $$status

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check tools/ bin/bb-tools-doctor.py --quiet || echo "ruff not installed; skipping (pip install ruff)"
	@command -v shellcheck >/dev/null 2>&1 && shellcheck bin/bb-run bin/bb-init bin/bb-validate bin/bb-hunt || echo "shellcheck not installed; skipping (brew install shellcheck)"

clean:
	rm -rf output/test-* output/quality_report.json

audit:
	python3 tools/validate_skills.py audit-workflows
	python3 tools/validate_skills.py audit-security

secrets:
	gitleaks detect --source . --no-git -v

release-check: test validate secrets
	python3 tools/validate_skills.py audit-release
	@echo "=== Release gate passed ==="

doctor:
	bin/bb-tools doctor

help:
	@echo "make test           - parse + compile every skill"
	@echo "make lint           - ruff (python) + shellcheck (bash) if installed"
	@echo "make validate       - skill quality validator"
	@echo "make audit          - workflow + security audits"
	@echo "make secrets        - gitleaks scan"
	@echo "make release-check  - full release gate"
	@echo "make doctor         - external tool health checks"

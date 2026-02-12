SCENARIOS=benchmark/scenarios/scenarios.yaml
RUNS=5

.PHONY: opa-up opa-down eval ablations report report-plots thesis-bundle sbom baseline-pre-upgrade

opa-up:
	docker compose up -d

opa-down:
	docker compose down -v

eval: opa-up
	./scripts/run_eval_matrix.sh $(SCENARIOS) $(RUNS)

ablations: opa-up
	./scripts/run_ablations.sh $(SCENARIOS) $(RUNS)

report:
	python scripts/report_results.py --results-dir results --scenarios $(SCENARIOS)

report-plots:
	pip install -e ".[report]"
	python scripts/report_results.py --results-dir results --scenarios $(SCENARIOS) --make-plots

sbom:
	@[ -d .venv ] || python3 -m venv .venv
	. .venv/bin/activate && python scripts/generate_sbom.py artifacts/sbom.json
	@echo "SBOM written to artifacts/sbom.json"

baseline-pre-upgrade: opa-up
	@[ -d .venv ] || python3 -m venv .venv
	. .venv/bin/activate && pip install -e .
	. .venv/bin/activate && python -m benchmark.runner --scenarios benchmark/scenarios/scenarios.yaml --baseline all --runs 5 --compare --out results/baseline_pre_upgrade/run.json --summary results/baseline_pre_upgrade/summary.json
	. .venv/bin/activate && python scripts/report_results.py --results-dir results/baseline_pre_upgrade --scenarios benchmark/scenarios/scenarios.yaml --make-plots --out-dir results/baseline_pre_upgrade/report
	@echo "Baseline pre-upgrade artifacts in results/baseline_pre_upgrade"

thesis-bundle: opa-up
	@[ -d .venv ] || python3 -m venv .venv
	. .venv/bin/activate && pip install -e '.[report]'
	. .venv/bin/activate && python -m benchmark.runner --scenarios $(SCENARIOS) --baseline all --runs $(RUNS) --compare --out results/run.json --summary results/summary.json
	. .venv/bin/activate && python scripts/report_results.py --results-dir results --scenarios $(SCENARIOS) --make-plots
	. .venv/bin/activate && python scripts/generate_sbom.py artifacts/sbom.json
	@mkdir -p artifacts
	@zip -r artifacts/thesis.zip results docs requirements-lock.txt artifacts/sbom.json -x "*.DS_Store" >/dev/null
	@echo "thesis bundle ready: artifacts/thesis.zip"

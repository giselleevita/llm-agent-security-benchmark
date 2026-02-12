SCENARIOS=benchmark/scenarios/scenarios.yaml
RUNS?=5
OPA_URL?=http://localhost:8181

.PHONY: setup lint test policy-test bench report demo ci opa-up opa-down eval ablations

setup:
	@[ -d .venv ] || python3 -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip
	. .venv/bin/activate && pip install -e '.[dev,report]'

lint:
	. .venv/bin/activate && ruff check .

test:
	. .venv/bin/activate && pytest -q

policy-test:
	@if command -v opa >/dev/null 2>&1; then \
		opa test ./policies -v ; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "opa binary not found; running policy tests via docker" ; \
		docker run --rm -v "$$(pwd)/policies:/policies" openpolicyagent/opa:latest test /policies -v ; \
	else \
		mkdir -p .tools ; \
		if [ ! -x .tools/opa ]; then \
			echo "opa and docker not found; downloading temporary opa binary" ; \
			ARCH=$$(uname -m) ; \
			if [ "$$ARCH" = "x86_64" ]; then ARCH=amd64 ; fi ; \
			curl -sSL -o .tools/opa https://openpolicyagent.org/downloads/latest/opa_$$(uname -s | tr '[:upper:]' '[:lower:]')_$${ARCH}_static ; \
			chmod +x .tools/opa ; \
		fi ; \
		.tools/opa test ./policies -v ; \
	fi

opa-up:
	docker compose up -d

opa-down:
	docker compose down -v

bench:
	@set -e ; \
	if command -v docker >/dev/null 2>&1; then \
		docker compose up -d ; \
		sleep 2 ; \
		. .venv/bin/activate && python -m benchmark.runner --scenarios $(SCENARIOS) --baseline all --runs $(RUNS) --compare --seed 1 --opa-url $(OPA_URL) --out results/run.json --summary results/summary.json ; \
		docker compose down -v ; \
	else \
		if [ ! -x .tools/opa ]; then \
			mkdir -p .tools ; \
			ARCH=$$(uname -m) ; \
			if [ "$$ARCH" = "x86_64" ]; then ARCH=amd64 ; fi ; \
			curl -sSL -o .tools/opa https://openpolicyagent.org/downloads/latest/opa_$$(uname -s | tr '[:upper:]' '[:lower:]')_$${ARCH}_static ; \
			chmod +x .tools/opa ; \
		fi ; \
		.tools/opa run --server --addr=127.0.0.1:8181 --log-format=json policies >/tmp/opa_bench.log 2>&1 & \
		OPA_PID=$$! ; \
		sleep 1 ; \
		. .venv/bin/activate && python -m benchmark.runner --scenarios $(SCENARIOS) --baseline all --runs $(RUNS) --compare --seed 1 --opa-url http://127.0.0.1:8181 --out results/run.json --summary results/summary.json ; \
		kill $$OPA_PID ; \
	fi

report:
	. .venv/bin/activate && python scripts/report_results.py --results-dir results --scenarios $(SCENARIOS) --run-id latest --make-plots

demo:
	@$(MAKE) bench RUNS=1 >/tmp/demo_bench.log 2>&1 || { cat /tmp/demo_bench.log; exit 1; }
	@$(MAKE) report >/tmp/demo_report.log 2>&1 || { cat /tmp/demo_report.log; exit 1; }
	@echo "Demo report: results/latest/report/index.html"

ci: lint test policy-test
	@set -e ; \
	if command -v docker >/dev/null 2>&1; then \
		docker compose up -d ; \
		sleep 2 ; \
		. .venv/bin/activate && python -m benchmark.runner --scenarios $(SCENARIOS) --baseline B3 --runs 1 --seed 1 --opa-url $(OPA_URL) --out results/ci_run.json --summary results/ci_summary.json ; \
		docker compose down -v ; \
	else \
		if [ ! -x .tools/opa ]; then \
			mkdir -p .tools ; \
			ARCH=$$(uname -m) ; \
			if [ "$$ARCH" = "x86_64" ]; then ARCH=amd64 ; fi ; \
			curl -sSL -o .tools/opa https://openpolicyagent.org/downloads/latest/opa_$$(uname -s | tr '[:upper:]' '[:lower:]')_$${ARCH}_static ; \
			chmod +x .tools/opa ; \
		fi ; \
		.tools/opa run --server --addr=127.0.0.1:8181 --log-format=json policies >/tmp/opa_ci.log 2>&1 & \
		OPA_PID=$$! ; \
		sleep 1 ; \
		. .venv/bin/activate && python -m benchmark.runner --scenarios $(SCENARIOS) --baseline B3 --runs 1 --seed 1 --opa-url http://127.0.0.1:8181 --out results/ci_run.json --summary results/ci_summary.json ; \
		kill $$OPA_PID ; \
	fi

eval: opa-up
	./scripts/run_eval_matrix.sh $(SCENARIOS) $(RUNS)

ablations: opa-up
	./scripts/run_ablations.sh $(SCENARIOS) $(RUNS)

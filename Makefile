PY    ?= python3
SRC   := src
PKG   := barecode
DIST  := dist
PYZ   := $(DIST)/$(PKG).pyz
PYSRC := $(shell find $(SRC) tools tests -name '*.py' 2>/dev/null)

.DEFAULT_GOAL := help
.PHONY: help build run test prove deps-proof clean install all check

help:
	@printf '\nBareCode — offline supply-chain X-ray for Python environments\n\n'
	@printf '  make build       build dist/barecode.pyz (stdlib zipapp, one step)\n'
	@printf '  make run         build, then run it against this repo\n'
	@printf '  make test        stdlib unittest suite (no pytest)\n'
	@printf '  make prove       machine-check that every import is stdlib\n'
	@printf '  make deps-proof  regenerate deps-proof.txt\n'
	@printf '  make check       prove + test  (what CI runs)\n'
	@printf '  make all         prove + test + build\n'
	@printf '  make install     copy the artifact to ~/.local/bin/barecode\n'
	@printf '  make clean       remove build output and caches\n\n'
	@printf 'Zero dependencies. No pip install is required for any target.\n\n'

# ── build ────────────────────────────────────────────────────────────────────
# One command, one artifact. `zipapp` is stdlib, so there is no build backend
# and no third-party packaging tool anywhere in this pipeline.
build: $(PYZ)

$(PYZ): $(PYSRC)
	@mkdir -p $(DIST)
	$(PY) -m zipapp $(SRC) -o $(PYZ) -p '/usr/bin/env python3' -m '$(PKG).cli:run'
	@chmod +x $(PYZ)
	@printf '\n  built %s (%s bytes)\n  run it: ./%s audit\n\n' \
	  "$(PYZ)" "$$(wc -c < $(PYZ) | tr -d ' ')" "$(PYZ)"

run: build
	@./$(PYZ) audit

# ── verification ─────────────────────────────────────────────────────────────
test:
	$(PY) -m unittest discover -s tests -t . -v

prove:
	@$(PY) tools/prove_zero_deps.py

deps-proof:
	@$(PY) tools/prove_zero_deps.py --write deps-proof.txt
	@printf '  wrote deps-proof.txt\n'

check: prove test

all: prove test build

# ── housekeeping ─────────────────────────────────────────────────────────────
install: build
	@mkdir -p $(HOME)/.local/bin
	@cp $(PYZ) $(HOME)/.local/bin/$(PKG)
	@chmod +x $(HOME)/.local/bin/$(PKG)
	@printf '  installed to %s/.local/bin/%s\n' "$(HOME)" "$(PKG)"

clean:
	@rm -rf $(DIST) .barecode
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@printf '  cleaned\n'

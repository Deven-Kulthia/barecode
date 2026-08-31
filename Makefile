PY    ?= python3
SRC   := src
PKG   := barecode
DIST  := dist
PYZ   := $(DIST)/$(PKG).pyz
PYSRC := $(shell find $(SRC) tools tests -name '*.py' 2>/dev/null)

.DEFAULT_GOAL := help
.PHONY: help build run test prove deps-proof clean install all check repro

help:
	@printf '\nBareCode — offline supply-chain X-ray for Python environments\n\n'
	@printf '  make build       build dist/barecode.pyz (stdlib zipapp, one step)\n'
	@printf '  make run         build, then run it against this repo\n'
	@printf '  make test        stdlib unittest suite (no pytest)\n'
	@printf '  make prove       machine-check that every import is stdlib\n'
	@printf '  make deps-proof  regenerate deps-proof.txt\n'
	@printf '  make check       prove + test  (what CI runs)\n'
	@printf '  make repro       build twice, assert byte-identical, print both hashes\n'
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
	@# Running the tests imports from src/, which leaves __pycache__ behind.
	@# zipapp would silently bundle those .pyc files: a 6x larger artifact whose
	@# size depends on whether you ran the tests first. Strip them so the build
	@# depends only on the source.
	@find $(SRC) -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
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

# ── reproducible build ───────────────────────────────────────────────────────
# Builds the artifact twice from scratch and asserts the two are byte-identical,
# printing both hashes. Scope, per the hackathon FAQ: same machine, same
# toolchain. Cross-environment reproducibility is explicitly not required, and
# we do not claim it -- a fresh `git clone` sets new file mtimes, which zipapp
# stores in the archive.
repro:
	@# Start from a genuinely clean tree. Deleting a leftover __pycache__ during
	@# the first build would bump src/barecode/'s directory mtime, and zipapp
	@# stores directory mtimes -- so build 1 and build 2 would legitimately differ
	@# through no fault of the source.
	@$(MAKE) --no-print-directory clean >/dev/null
	@$(MAKE) --no-print-directory build >/dev/null
	@mv $(PYZ) $(DIST)/build-1.pyz
	@$(MAKE) --no-print-directory build >/dev/null
	@mv $(PYZ) $(DIST)/build-2.pyz
	@printf '\n  build 1: %s\n' "$$(shasum -a 256 $(DIST)/build-1.pyz | cut -d' ' -f1)"
	@printf '  build 2: %s\n\n' "$$(shasum -a 256 $(DIST)/build-2.pyz | cut -d' ' -f1)"
	@if cmp -s $(DIST)/build-1.pyz $(DIST)/build-2.pyz; then \
	  printf '  BYTE-IDENTICAL — reproducible build verified\n\n'; \
	else \
	  printf '  DIFFER — not reproducible\n\n'; exit 1; \
	fi
	@rm -f $(DIST)/build-1.pyz $(DIST)/build-2.pyz
	@$(MAKE) --no-print-directory build >/dev/null

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

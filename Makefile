PYTHON ?= python3

BASE_CFLAGS := -std=c11 -O2 -fPIC -fvisibility=hidden -Wall -Wextra -Wpedantic
DEV_CFLAGS := $(BASE_CFLAGS) -Werror

NATIVE_DIR := src/ah_netbridge/_native
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
NATIVE_LIB := $(NATIVE_DIR)/libtaixinnet.dylib
SHARED_FLAG := -dynamiclib
else
NATIVE_LIB := $(NATIVE_DIR)/libtaixinnet.so
SHARED_FLAG := -shared
endif

UV := $(shell command -v uv 2>/dev/null)

PATH_HINT = bin="$$($(BIN_DIR_CMD))"; \
	echo "ahnb and ah-netbridge-config were installed to $$bin"; \
	case ":$$PATH:" in *":$$bin:"*) ;; *) \
	echo "$$bin is not on your PATH. Add this line to your shell profile (~/.zshrc or ~/.bashrc), then open a new terminal:"; \
	echo "  export PATH=\"$$bin:\$$PATH\"";; esac

.PHONY: run native lock clean fclean install re

native: $(NATIVE_LIB)

$(NATIVE_LIB): native/taixinnet.c include/taixinnet.h
	mkdir -p $(NATIVE_DIR)
	$(CC) $(DEV_CFLAGS) -Iinclude $(SHARED_FLAG) -o $@ native/taixinnet.c

ifneq ($(UV),)
BIN_DIR_CMD := uv tool dir --bin

run: DEV_CFLAGS := $(BASE_CFLAGS)
run: native
	uv sync --locked
	uv run ah-netbridge-config

install:
	uv tool install --force .
	@$(PATH_HINT)

lock:
	uv lock
	uv export --format requirements-txt --no-dev --no-emit-project > requirements.lock
else
BIN_DIR_CMD := $(PYTHON) -c "import sysconfig; print(sysconfig.get_path('scripts', sysconfig.get_preferred_scheme('user')))"

run:
	test -x .venv/bin/python || $(PYTHON) -m venv .venv
	.venv/bin/python -m pip install .
	.venv/bin/ah-netbridge-config

install:
	@$(PYTHON) -m pip install --user . || { \
		echo "User-local pip installation was rejected. Install uv and run: uv tool install --force ." >&2; \
		echo "Or use a venv: python3 -m venv .venv && .venv/bin/pip install ." >&2; \
		exit 1; \
	}
	@$(PATH_HINT)

lock:
	@echo "uv is required to regenerate lockfiles" >&2
	@exit 1
endif

clean:
	rm -rf $(NATIVE_DIR)
	find src -type d -name __pycache__ -prune -exec rm -rf {} +

fclean: clean
	rm -rf .venv build dist .pytest_cache .mypy_cache .ruff_cache
	find . -maxdepth 2 -type d -name '*.egg-info' -prune -exec rm -rf {} +

re: fclean
	$(MAKE) --no-print-directory install

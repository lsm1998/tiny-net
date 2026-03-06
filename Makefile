SHELL := /bin/bash

PROJECT := tiny-net
BUILD_DIR ?= build
BUILD_TYPE ?= Debug
DBUG_BUILD_DIR ?= build-dbug
DBUG_BUILD_TYPE ?= Debug
CMAKE ?= cmake
PYTHON ?= python3
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)

EXAMPLE_SRCS := $(wildcard src/app/examples/*.c)
TEST_SRCS := $(wildcard src/app/tests/*.c)
EXAMPLE_TARGETS := $(basename $(notdir $(EXAMPLE_SRCS)))
TEST_TARGETS := $(basename $(notdir $(TEST_SRCS)))
TARGETS := $(PROJECT) $(EXAMPLE_TARGETS) $(TEST_TARGETS)

.DEFAULT_GOAL := help

.PHONY: all help configure configure-dbug build build-dbug dbug rebuild clean clean-dbug distclean distclean-dbug test test-dbug check test-tcp run run-dbug ping-verify $(TARGETS)

all: build

help:
	@printf "Tiny-Net Makefile\n\n"
	@printf "Usage:\n"
	@printf "  make configure               Configure CMake in %s\n" "$(BUILD_DIR)"
	@printf "  make build                   Build all targets\n"
	@printf "  make build-dbug              Build all targets in dbug mode (%s)\n" "$(DBUG_BUILD_DIR)"
	@printf "  make test                    Build and run core TCP tests\n"
	@printf "  make test-dbug               Run core TCP tests from dbug mode\n"
	@printf "  make <target>                Build one target\n"
	@printf "  make run TARGET=ping ARGS='127.0.0.1'\n"
	@printf "  make run-dbug TARGET=ping ARGS='127.0.0.1'\n"
	@printf "  make clean                   Clean build outputs inside %s\n" "$(BUILD_DIR)"
	@printf "  make clean-dbug              Clean build outputs inside %s\n" "$(DBUG_BUILD_DIR)"
	@printf "  make distclean               Remove %s entirely\n\n" "$(BUILD_DIR)"
	@printf "  make distclean-dbug          Remove %s entirely\n\n" "$(DBUG_BUILD_DIR)"
	@printf "Main targets:\n"
	@printf "  %s\n\n" "$(PROJECT)"
	@printf "Example targets:\n"
	@printf "  %s\n\n" "$(EXAMPLE_TARGETS)"
	@printf "Test targets:\n"
	@printf "  %s\n" "$(TEST_TARGETS)"

configure:
	$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build: configure
	$(CMAKE) --build $(BUILD_DIR) -j$(JOBS)

configure-dbug:
	$(CMAKE) -B $(DBUG_BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=$(DBUG_BUILD_TYPE) -DTINY_NET_DBUG=ON

build-dbug: configure-dbug
	$(CMAKE) --build $(DBUG_BUILD_DIR) -j$(JOBS)

dbug: build-dbug

rebuild: distclean build

clean:
	@if [ -d "$(BUILD_DIR)" ]; then \
		$(CMAKE) --build $(BUILD_DIR) --target clean; \
	else \
		printf "Nothing to clean in %s\n" "$(BUILD_DIR)"; \
	fi

clean-dbug:
	@if [ -d "$(DBUG_BUILD_DIR)" ]; then \
		$(CMAKE) --build $(DBUG_BUILD_DIR) --target clean; \
	else \
		printf "Nothing to clean in %s\n" "$(DBUG_BUILD_DIR)"; \
	fi

distclean:
	@if [ -d "$(BUILD_DIR)" ]; then \
		rm -rf "$(BUILD_DIR)"; \
	else \
		printf "Nothing to remove in %s\n" "$(BUILD_DIR)"; \
	fi

distclean-dbug:
	@if [ -d "$(DBUG_BUILD_DIR)" ]; then \
		rm -rf "$(DBUG_BUILD_DIR)"; \
	else \
		printf "Nothing to remove in %s\n" "$(DBUG_BUILD_DIR)"; \
	fi

test: tcp_mock_test tcp_passive_open_test
	./$(BUILD_DIR)/tcp_mock_test
	./$(BUILD_DIR)/tcp_passive_open_test

test-dbug: configure-dbug
	$(CMAKE) --build $(DBUG_BUILD_DIR) --target tcp_mock_test tcp_passive_open_test -j$(JOBS)
	./$(DBUG_BUILD_DIR)/tcp_mock_test
	./$(DBUG_BUILD_DIR)/tcp_passive_open_test

check: test

test-tcp: test

run:
	@if [ -z "$(TARGET)" ]; then \
		printf "Usage: make run TARGET=<target> [ARGS='...']\n" >&2; \
		exit 1; \
	fi
	@if ! printf '%s\n' "$(TARGETS)" | tr ' ' '\n' | grep -qx "$(TARGET)"; then \
		printf "Unknown target: %s\n" "$(TARGET)" >&2; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory $(TARGET)
	./$(BUILD_DIR)/$(TARGET) $(ARGS)

run-dbug:
	@if [ -z "$(TARGET)" ]; then \
		printf "Usage: make run-dbug TARGET=<target> [ARGS='...']\n" >&2; \
		exit 1; \
	fi
	@if ! printf '%s\n' "$(TARGETS)" | tr ' ' '\n' | grep -qx "$(TARGET)"; then \
		printf "Unknown target: %s\n" "$(TARGET)" >&2; \
		exit 1; \
	fi
	@$(CMAKE) -B $(DBUG_BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=$(DBUG_BUILD_TYPE) -DTINY_NET_DBUG=ON
	@$(CMAKE) --build $(DBUG_BUILD_DIR) --target $(TARGET) -j$(JOBS)
	./$(DBUG_BUILD_DIR)/$(TARGET) $(ARGS)

ping-verify: ping
	$(PYTHON) scripts/ping_verify.py

$(TARGETS): configure
	$(CMAKE) --build $(BUILD_DIR) --target $@ -j$(JOBS)

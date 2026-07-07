# Copyright 2023 VMware, Inc.
#
# This product is licensed to you under the BSD-2 license (the "License").
# You may not use this product except in compliance with the BSD-2 License.
# This product may include a number of subcomponents with separate copyright
# notices and license terms. Your use of these subcomponents is subject to
# the terms and conditions of the subcomponent's license, as noted in the
# LICENSE file.
# 
# SPDX-License-Identifier: BSD-2-Clause

FAKETIME := $(shell command -v faketime 2> /dev/null)

faketime:
ifndef FAKETIME
	$(error "Program 'faketime' was not found. Please install it")
endif

DUMP_DIR = /tmp/tuf-conformance-dump

.PHONY: dev test-all test-python-tuf test-go-tuf build-go-tuf

#########################
# tuf-conformance section
#########################

dev: faketime

test-all: test-python-tuf test-go-tuf

lint_dirs = tuf_conformance clients/python-tuf .github/scripts
lint:
	uv run ruff format --diff $(lint_dirs)
	uv run ruff check $(lint_dirs)
	uv run mypy $(lint_dirs)

fix:
	uv run ruff format $(lint_dirs)
	uv run ruff check --fix $(lint_dirs)

#########################
# python-tuf section
#########################

test-python-tuf: dev
	uv run pytest -v tuf_conformance \
		--entrypoint "./clients/python-tuf/python_tuf.py" \
		--repository-dump-dir $(DUMP_DIR)
	@echo Repository dump in $(DUMP_DIR)

#########################
# go-tuf section
#########################

test-go-tuf: dev build-go-tuf
	uv run pytest -v tuf_conformance \
		--entrypoint "./clients/go-tuf/go-tuf" \
		--repository-dump-dir $(DUMP_DIR)
	@echo Repository dump in $(DUMP_DIR)
build-go-tuf:
	cd ./clients/go-tuf && go build .

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


#########################
# tuf-conformance section
#########################

env/pyvenv.cfg: pyproject.toml
	python3 -m venv env
	./env/bin/python -m pip install --upgrade pip
	./env/bin/python -m pip install -e .[lint]

.PHONY: dev
dev: env/pyvenv.cfg

.PHONY: test-all
test-all: test-python-tuf test-go-tuf

lint_dirs = tuf_conformance clients/python-tuf
lint: dev
	./env/bin/ruff format --diff $(lint_dirs)
	./env/bin/ruff check $(lint_dirs)
	./env/bin/mypy $(lint_dirs)

fix: dev
	./env/bin/ruff format $(lint_dirs)
	./env/bin/ruff check --fix $(lint_dirs)

#########################
# python-tuf section
#########################

PHONY: test-python-tuf
test-python-tuf: dev faketime
	./env/bin/pytest tuf_conformance --entrypoint "./env/bin/python ./clients/python-tuf/python_tuf.py" -vv

#########################
# go-tuf section
#########################

PHONY: test-go-tuf
test-go-tuf: dev build-go-tuf faketime
	./env/bin/pytest tuf_conformance --entrypoint "./clients/go-tuf/go-tuf"

PHONY: build-go-tuf
build-go-tuf:
	cd ./clients/go-tuf && go build .


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

#########################
# tuf-conformance section
#########################

env/pyvenv.cfg: pyproject.toml
	python3 -m venv env
	./env/bin/python -m pip install --upgrade pip
	./env/bin/python -m pip install -e .

.PHONY: dev
dev: env/pyvenv.cfg

.PHONY: test-all
test-all: test-python-tuf test-go-tuf

#########################
# python-tuf section
#########################

PHONY: test-python-tuf
test-python-tuf: dev
	./env/bin/pytest tuf_conformance --entrypoint "./env/bin/python ./clients/python-tuf/python_tuf.py" -vv

#########################
# go-tuf section
#########################

PHONY: test-go-tuf
test-go-tuf: dev build-go-tuf
	./env/bin/pytest tuf_conformance --entrypoint "./clients/go-tuf/go-tuf"

PHONY: build-go-tuf
build-go-tuf:
	cd ./clients/go-tuf && go build .

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
test-all: test-python-tuf test-go-tuf-metadata

#########################
# python-tuf section
#########################

PHONY: test-python-tuf
test-python-tuf: dev
	./env/bin/tuf-conformance "./env/bin/python ./clients/python-tuf/python_tuf.py"

#########################
# go-tuf-metadata section
#########################

PHONY: test-go-tuf-metadata
test-go-tuf-metadata: dev build-go-tuf-metadata
	./env/bin/tuf-conformance "./clients/go-tuf-metadata/go-tuf-metadata"

PHONY: build-go-tuf-metadata
build-go-tuf-metadata:
	cd ./clients/go-tuf-metadata && go build .

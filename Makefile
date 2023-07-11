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

.PHONY: install
install:
	pip install -e .

.PHONY: test-all
test-all: test-python-tuf test-go-tuf-metadata

#########################
# python-tuf section
#########################

PHONY: test-python-tuf
test-python-tuf:
	tuf-conformance "python ./clients/python-tuf/python_tuf.py"

#########################
# go-tuf-metadata section
#########################

PHONY: test-go-tuf-metadata
test-go-tuf-metadata: build-go-tuf-metadata
	tuf-conformance "./clients/go-tuf-metadata/go-tuf-metadata"

PHONY: build-go-tuf-metadata
build-go-tuf-metadata:
	cd ./clients/go-tuf-metadata && go build .

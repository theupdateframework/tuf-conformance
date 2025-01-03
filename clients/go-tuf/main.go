// Copyright 2023 VMware, Inc.
//
// This product is licensed to you under the BSD-2 license (the "License").
// You may not use this product except in compliance with the BSD-2 License.
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to
// the terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"os"

	tufclient "github.com/theupdateframework/tuf-conformance/clients/go-tuf/cmd"
)

func main() {
	fmt.Println(len(os.Args), os.Args)
	tufclient.Execute()
}

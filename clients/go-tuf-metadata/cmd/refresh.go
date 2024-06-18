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

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Performs a refresh of the metadata",
	Args:  cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		if FlagMetadataURL == "" || FlagMetadataDir == "" {
			fmt.Println("Error: required flag(s): \"metadata-url\" or \"metadata-dir\" not set")
			os.Exit(1)
		}
		daysInFuture, err := cmd.Flags().GetString("days-in-future")
		if err != nil {
			os.Exit(1)
		}
		// do a refresh only
		return RefreshAndDownloadCmd("", "", "", daysInFuture, true)
	},
}

func init() {
	rootCmd.AddCommand(refreshCmd)
}

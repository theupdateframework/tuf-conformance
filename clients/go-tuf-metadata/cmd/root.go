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
	"os"

	"github.com/spf13/cobra"
)

var FlagVerbosity bool
var FlagMetadataURL string
var FlagMetadataDir string
var FlagTargetDir string

var rootCmd = &cobra.Command{
	Use:   "tuf-client",
	Short: "tuf-client - a client CLI tool used for TUF conformance testing",
	Run: func(cmd *cobra.Command, args []string) {
		// show the help message if no command has been used
		if len(args) == 0 {
			_ = cmd.Help()
			os.Exit(0)
		}
	},
}

func Execute() {
	rootCmd.PersistentFlags().BoolVar(&FlagVerbosity, "verbose", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&FlagMetadataURL, "metadata-url", "", "URL of the TUF repository")
	rootCmd.PersistentFlags().StringVar(&FlagMetadataDir, "metadata-dir", "", "directory to save metadata")
	rootCmd.PersistentFlags().StringVar(&FlagTargetDir, "target-dir", "", "directory to save target files")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

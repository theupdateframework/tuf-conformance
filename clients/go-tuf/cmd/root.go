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

var FlagVerbosity bool
var FlagMetadataURL string
var FlagMetadataDir string
var FlagTargetDir string
var FlagTargetPath string
var FlagTargetUrl string
var FlagTargetBaseUrl string
var FlagDaysInFuture string
var MaxRootRotations int
var FlagMaxDelegations int

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
	rootCmd.PersistentFlags().StringVar(&FlagTargetPath, "target-path", "", "reference when invoking get-targetinfo")
	rootCmd.PersistentFlags().IntVar(&FlagMaxDelegations, "max-delegations", 10, "the max number of delegations the client will process")
	rootCmd.PersistentFlags().StringVar(&FlagTargetUrl, "target-name", "", "name of target file from the targets.json metadata")
	rootCmd.PersistentFlags().StringVar(&FlagTargetBaseUrl, "target-base-url", "", "base url for target file")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
}

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
var FlagTargetUrl string
var FlagTargetBaseUrl string
var FlagDaysInFuture string
var MaxRootRotations int

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
	rootCmd.PersistentFlags().StringVar(&FlagTargetUrl, "target-url", "", "url for target file")
	rootCmd.PersistentFlags().StringVar(&FlagTargetBaseUrl, "target-base-url", "", "base url for target file")
	rootCmd.PersistentFlags().StringVar(&FlagDaysInFuture, "days-in-future", "0", "for refresh only. For setting the time.Now() at a time in the future")
	rootCmd.PersistentFlags().IntVar(&MaxRootRotations, "max-root-rotations", 32, "number of max allowed root rotations")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("ERRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR", err)
		os.Exit(1)
	}
}

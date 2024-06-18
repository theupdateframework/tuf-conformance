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
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the client with trusted root.json metadata",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if FlagMetadataURL == "" || FlagMetadataDir == "" {
			fmt.Println("Error: required flag(s): \"metadata-url\" or \"metadata-dir\" not set")
			os.Exit(1)
		}
		// first arg means the path to trusted root.json
		return InitializeCmd(args[0])
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func InitializeCmd(trustedRoot string) error {
	// handle verbosity level
	if FlagVerbosity {
		log.SetLevel(log.DebugLevel)
	}

	// read the content of the provided trusted root
	rootBytes, err := os.ReadFile(trustedRoot)
	if err != nil {
		return err
	}

	// save it to the desired metadata directory
	err = os.WriteFile(filepath.Join(FlagMetadataDir, "root.json"), rootBytes, 0644)
	if err != nil {
		return err
	}

	fmt.Println("go-tuf-metadata test client: Initialized repository in", FlagMetadataDir)

	return nil
}

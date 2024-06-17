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

	"github.com/rdimitrov/go-tuf-metadata/metadata/config"
	"github.com/rdimitrov/go-tuf-metadata/metadata/updater"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Downloads a target file",
	//Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if FlagMetadataURL == "" || FlagMetadataDir == "" || FlagTargetUrl == "" {
			fmt.Println("Error: required flag(s): \"metadata-url\" or \"metadata-dir\" not set")
			os.Exit(1)
		}
		targetInfoName, err := cmd.Flags().GetString("target-url")
		if err != nil {
			os.Exit(1)
		}
		targetBaseUrl, err := cmd.Flags().GetString("target-base-url")
		if err != nil {
			os.Exit(1)
		}
		targetDownloadDir, err := cmd.Flags().GetString("target-dir")
		if err != nil {
			os.Exit(1)
		}
		// refresh metadata and try to download the desired target
		// first arg means the name of the target file to download
		return RefreshAndDownloadCmd(targetInfoName, targetBaseUrl, targetDownloadDir, false)
	},
}

func init() {
	rootCmd.AddCommand(downloadCmd)
}

func RefreshAndDownloadCmd(targetName, targetBaseUrl, targetDownloadDir string, refreshOnly bool) error {
	// handle verbosity level
	if FlagVerbosity {
		log.SetLevel(log.DebugLevel)
	}

	// read the trusted root metadata
	rootBytes, err := os.ReadFile(filepath.Join(FlagMetadataDir, "root.json"))
	if err != nil {
		return err
	}

	// create an Updater configuration
	cfg, err := config.New(FlagMetadataURL, rootBytes) // default config
	if err != nil {
		return err
	}
	cfg.LocalMetadataDir = FlagMetadataDir
	cfg.LocalTargetsDir = FlagMetadataDir // TODO: perhaps fix that once we progress
	cfg.RemoteTargetsURL = targetBaseUrl
	cfg.PrefixTargetsWithHash = false // change if needed to be compliant with python-tuf

	// create an Updater instance
	up, err := updater.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Updater instance: %w", err)
	}

	// try to build the top-level metadata
	err = up.Refresh()
	if err != nil {
		return fmt.Errorf("failed to refresh trusted metadata: %w", err)
	}

	// exit early if it's a refresh only command or there's no targetName provided
	if refreshOnly || targetName == "" {
		fmt.Println("go-tuf-metadata test client: Refreshed metadata in", FlagMetadataDir)
		return nil
	}

	// search if the desired target is available
	targetInfo, err := up.GetTargetInfo(targetName)
	if err != nil {
		return fmt.Errorf("target %s not found: %w", targetName, err)
	}

	// target is available, so let's see if the target is already present locally
	path, _, err := up.FindCachedTarget(targetInfo, "")
	if err != nil {
		return fmt.Errorf("failed while finding a cached target: %w", err)
	}

	if path != "" {
		fmt.Printf("Target %s is already present at - %s\n", targetName, path)
		return nil
	}

	// target is not present locally, so let's try to download it
	path, _, err = up.DownloadTarget(targetInfo, filepath.Join(targetDownloadDir, targetName), targetBaseUrl)
	if err != nil {
		return fmt.Errorf("failed to download target file %s - %w", targetName, err)
	}

	fmt.Printf("go-tuf-metadata test client: downloaded target %s in %s\n", targetName, path)

	return nil
}

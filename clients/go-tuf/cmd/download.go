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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
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
		targetInfoName, err := cmd.Flags().GetString("target-name")
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

func RefreshAndDownloadCmd(targetName string,
	targetBaseUrl string,
	targetDownloadDir string,
	refreshOnly bool) error {
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

	// create an Updater instance
	up, err := updater.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Updater instance: %w", err)
	}

	// Test suite uses faketime to set the time client should consider "current".
	// Golang does not use libc and bypasses the tricks faketime uses.
	// use "date" command to get current time as this is affected by faketime
	out, err := exec.Command("date", "+%s").Output()
	if err != nil {
		return fmt.Errorf("calling 'date' failed: %w", err)
	}
	timestamp_str := string(out[:len(out)-1])
	timestamp, err := strconv.ParseInt(timestamp_str, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse date output: %w", err)
	}
	ref_time := time.Unix(timestamp, 0)
	up.UnsafeSetRefTime(ref_time)

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
	localPath := filepath.Join(targetDownloadDir, url.QueryEscape(targetName))
	path, _, err := up.FindCachedTarget(targetInfo, localPath)
	if err != nil {
		return fmt.Errorf("failed while finding a cached target: %w", err)
	}

	if path != "" {
		fmt.Printf("Target %s is already present at - %s\n", targetName, path)
		return nil
	}

	// target is not present locally, so let's try to download it
	//
	path, _, err = up.DownloadTarget(targetInfo, localPath, targetBaseUrl)
	if err != nil {
		return fmt.Errorf("failed to download target file %s - %w", targetName, err)
	}

	fmt.Printf("go-tuf-metadata test client: downloaded target %s in %s\n", targetName, path)

	return nil
}

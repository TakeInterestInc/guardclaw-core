// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
//go:build !darwin && !linux

package receipts

import (
	"errors"
	"os"
)

func openJournal(string) (*os.File, error) {
	return nil, errors.New("receipt persistence supports macOS and Linux only")
}
func lockJournal(*os.File) error { return errors.New("unsupported platform") }
func unlockJournal(*os.File)     {}

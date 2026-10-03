// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
//go:build darwin || linux

package receipts

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func openJournal(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
}
func lockJournal(f *os.File) error {
	for attempt := 0; attempt < 100; attempt++ {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("receipt journal busy; refusing to proceed")
}
func unlockJournal(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

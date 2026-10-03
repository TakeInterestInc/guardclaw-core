// SPDX-License-Identifier: Apache-2.0
package main

import (
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TakeInterestInc/guardclaw-core/internal/report"
)

func main() { os.Exit(runCLI(10*time.Second, os.Args[1:])) }

func runCLI(deadline time.Duration, args []string) int {
	return runCLIReady(deadline, args, nil)
}

// ready is an optional in-process test synchronization callback. Production
// passes nil; no environment flag, output protocol or execution path is added.
func runCLIReady(deadline time.Duration, args []string, ready func()) int {
	// Independent termination must not wait for a blocked stdin/stdout writer.
	watchdog := time.AfterFunc(deadline, func() { os.Exit(2) })
	defer watchdog.Stop()
	// Local to this short-lived process. Never forward parser/engine log values.
	log.SetOutput(io.Discard)
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	defer signal.Stop(signals)
	defer close(done)
	go func() {
		select {
		case <-signals:
			os.Exit(2)
		case <-done:
		}
	}()
	if ready != nil {
		ready()
	}
	return report.Run(args, os.Stdin, os.Stdout)
}

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
	return report.Run(args, os.Stdin, os.Stdout)
}

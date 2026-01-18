//go:build !debug

package main

import "log"

// initProfiling is a no-op in release builds.
// Profiling is only available when building with -tags debug.
func initProfiling(_ *log.Logger) {}

// finishProfiling is a no-op in release builds.
// Profiling is only available when building with -tags debug.
func finishProfiling() {}

//go:build debug

package main

import (
	"flag"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
)

var (
	flagCPUProfile = flag.String("cpuprofile", "", "write cpu profile to file")
	flagMemProfile = flag.String("memprofile", "", "write memory profile to file")

	profilingCleanupOnce sync.Once
	cpuProfileFile       *os.File
	profilingLogger      *log.Logger
)

// initProfiling starts CPU profiling if enabled. Must be called after flag.Parse().
// The provided logger is used for profiling messages.
func initProfiling(l *log.Logger) {
	profilingLogger = l

	if *flagCPUProfile == "" {
		return
	}

	f, err := os.Create(*flagCPUProfile)
	if err != nil {
		profilingLogger.Printf("could not create CPU profile: %v", err)
		return
	}
	cpuProfileFile = f

	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		profilingLogger.Printf("could not start CPU profile: %v", err)
		return
	}

	profilingLogger.Printf("CPU profiling enabled, writing to: %s", *flagCPUProfile)
}

// finishProfiling writes memory profile and stops CPU profiling.
// Safe to call multiple times - only runs once.
func finishProfiling() {
	profilingCleanupOnce.Do(func() {
		// Write memory profile
		if *flagMemProfile != "" {
			f, err := os.Create(*flagMemProfile)
			if err != nil {
				profilingLogger.Printf("could not create memory profile: %v", err)
			} else {
				runtime.GC() // get up-to-date statistics
				if err := pprof.WriteHeapProfile(f); err != nil {
					profilingLogger.Printf("could not write memory profile: %v", err)
				} else {
					profilingLogger.Printf("Memory profile written to: %s", *flagMemProfile)
				}
				f.Close()
			}
		}

		// Stop CPU profiling
		if cpuProfileFile != nil {
			pprof.StopCPUProfile()
			cpuProfileFile.Close()
			profilingLogger.Printf("CPU profile written to: %s", *flagCPUProfile)
		}
	})
}

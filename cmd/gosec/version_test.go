package main

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("prepareVersionInfo", func() {
	Context("when Version is empty", func() {
		It("should set Version to 'dev'", func() {
			// Save original value
			originalVersion := Version

			// Set to empty to test
			Version = ""

			// Call function
			prepareVersionInfo()

			// Verify Version was set
			Expect(Version).To(Equal("dev"))

			// Restore original value
			Version = originalVersion
		})
	})

	Context("when Version is already set", func() {
		It("should not change the Version", func() {
			// Save original value
			originalVersion := Version

			// Set a specific version
			Version = "1.2.3"

			// Call function
			prepareVersionInfo()

			// Verify Version was not changed
			Expect(Version).To(Equal("1.2.3"))

			// Restore original value
			Version = originalVersion
		})
	})

	Context("with GitTag and BuildDate", func() {
		It("should not affect GitTag or BuildDate", func() {
			// Save original values
			originalVersion := Version
			originalGitTag := GitTag
			originalBuildDate := BuildDate

			// Set test values
			Version = ""
			GitTag = "v1.0.0"
			BuildDate = "2024-01-01"

			// Call function
			prepareVersionInfo()

			// Verify Version was set but others unchanged
			Expect(Version).To(Equal("dev"))
			Expect(GitTag).To(Equal("v1.0.0"))
			Expect(BuildDate).To(Equal("2024-01-01"))

			// Restore original values
			Version = originalVersion
			GitTag = originalGitTag
			BuildDate = originalBuildDate
		})
	})
})

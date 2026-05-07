package gosec_test

import (
	"bytes"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
)

var _ = Describe("Configuration", func() {
	var configuration gosec.Config
	BeforeEach(func() {
		configuration = gosec.NewConfig()
	})

	Context("when loading from disk", func() {
		It("should be possible to load configuration from a file", func() {
			json := `{"G101": {}}`
			buffer := bytes.NewBufferString(json)
			nread, err := configuration.ReadFrom(buffer)
			Expect(nread).Should(Equal(int64(len(json))))
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return an error if configuration file is invalid", func() {
			var err error
			invalidBuffer := bytes.NewBuffer([]byte{0xc0, 0xff, 0xee})
			_, err = configuration.ReadFrom(invalidBuffer)
			Expect(err).Should(HaveOccurred())

			emptyBuffer := bytes.NewBuffer([]byte{})
			_, err = configuration.ReadFrom(emptyBuffer)
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("when saving to disk", func() {
		It("should be possible to save an empty configuration to file", func() {
			expected := `{"global":{}}`
			buffer := bytes.NewBuffer([]byte{})
			nbytes, err := configuration.WriteTo(buffer)
			Expect(int(nbytes)).Should(Equal(len(expected)))
			Expect(err).ShouldNot(HaveOccurred())
			Expect(buffer.String()).Should(Equal(expected))
		})

		It("should be possible to save configuration to file", func() {
			configuration.Set("G101", map[string]string{
				"mode": "strict",
			})

			buffer := bytes.NewBuffer([]byte{})
			nbytes, err := configuration.WriteTo(buffer)
			Expect(int(nbytes)).ShouldNot(BeZero())
			Expect(err).ShouldNot(HaveOccurred())
			Expect(buffer.String()).Should(Equal(`{"G101":{"mode":"strict"},"global":{}}`))
		})
	})

	Context("when configuring rules", func() {
		It("should be possible to get configuration for a rule", func() {
			settings := map[string]string{
				"ciphers": "AES256-GCM",
			}
			configuration.Set("G101", settings)

			retrieved, err := configuration.Get("G101")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(retrieved).Should(HaveKeyWithValue("ciphers", "AES256-GCM"))
			Expect(retrieved).ShouldNot(HaveKey("foobar"))
		})
	})

	Context("when using global configuration options", func() {
		It("should have a default global section", func() {
			settings, err := configuration.Get("global")
			Expect(err).ShouldNot(HaveOccurred())
			expectedType := make(map[gosec.GlobalOption]string)
			Expect(settings).Should(BeAssignableToTypeOf(expectedType))
		})

		It("should save global settings to correct section", func() {
			configuration.SetGlobal(gosec.Nosec, "enabled")
			settings, err := configuration.Get("global")
			Expect(err).ShouldNot(HaveOccurred())
			if globals, ok := settings.(map[gosec.GlobalOption]string); ok {
				Expect(globals["nosec"]).Should(MatchRegexp("enabled"))
			} else {
				Fail("globals are not defined as map")
			}

			setValue, err := configuration.GetGlobal(gosec.Nosec)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(setValue).Should(MatchRegexp("enabled"))
		})

		It("should find global settings which are enabled", func() {
			configuration.SetGlobal(gosec.Nosec, "enabled")
			enabled, err := configuration.IsGlobalEnabled(gosec.Nosec)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(enabled).Should(BeTrue())
		})

		It("should parse the global settings of type string from file", func() {
			config := `
			{
				"global": {
					"nosec": "enabled"
				}
			}`
			cfg := gosec.NewConfig()
			_, err := cfg.ReadFrom(strings.NewReader(config))
			Expect(err).ShouldNot(HaveOccurred())

			value, err := cfg.GetGlobal(gosec.Nosec)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(value).Should(Equal("enabled"))
		})
		It("should parse the global settings of other types from file", func() {
			config := `
			{
				"global": {
					"nosec": true
				}
			}`
			cfg := gosec.NewConfig()
			_, err := cfg.ReadFrom(strings.NewReader(config))
			Expect(err).ShouldNot(HaveOccurred())

			value, err := cfg.GetGlobal(gosec.Nosec)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(value).Should(Equal("true"))
		})
	})

	Context("when managing exclude rules", func() {
		It("should set and get exclude rules", func() {
			rules := []gosec.PathExcludeRule{
				{Path: ".*test\\.go$", Rules: []string{"G101", "G102"}},
				{Path: ".*_gen\\.go$", Rules: []string{"*"}},
			}
			configuration.SetExcludeRules(rules)

			excludedRules, err := configuration.GetExcludeRules()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(excludedRules).Should(HaveLen(2))
			Expect(excludedRules[0].Path).Should(Equal(".*test\\.go$"))
			Expect(excludedRules[0].Rules).Should(ConsistOf("G101", "G102"))
			Expect(excludedRules[1].Path).Should(Equal(".*_gen\\.go$"))
			Expect(excludedRules[1].Rules).Should(ConsistOf("*"))
		})

		It("should handle empty exclude rules", func() {
			configuration.SetExcludeRules([]gosec.PathExcludeRule{})

			excludedRules, err := configuration.GetExcludeRules()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(excludedRules).Should(BeEmpty())
		})

		It("should overwrite previous exclude rules", func() {
			configuration.SetExcludeRules([]gosec.PathExcludeRule{
				{Path: ".*old\\.go$", Rules: []string{"G101"}},
			})

			configuration.SetExcludeRules([]gosec.PathExcludeRule{
				{Path: ".*new\\.go$", Rules: []string{"G201"}},
			})

			excludedRules, err := configuration.GetExcludeRules()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(excludedRules).Should(HaveLen(1))
			Expect(excludedRules[0].Path).Should(Equal(".*new\\.go$"))
		})

		It("should persist exclude rules in configuration", func() {
			rules := []gosec.PathExcludeRule{
				{Path: ".*vendor/.*", Rules: []string{"G301", "G302"}},
			}
			configuration.SetExcludeRules(rules)

			buffer := bytes.NewBuffer([]byte{})
			_, err := configuration.WriteTo(buffer)
			Expect(err).ShouldNot(HaveOccurred())

			newConfig := gosec.NewConfig()
			_, err = newConfig.ReadFrom(buffer)
			Expect(err).ShouldNot(HaveOccurred())

			excludedRules, err := newConfig.GetExcludeRules()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(excludedRules).Should(HaveLen(1))
			Expect(excludedRules[0].Path).Should(Equal(".*vendor/.*"))
			Expect(excludedRules[0].Rules).Should(ConsistOf("G301", "G302"))
		})

		It("should handle nil configuration gracefully", func() {
			var nilConfig gosec.Config
			nilConfig.SetExcludeRules([]gosec.PathExcludeRule{{Path: ".*", Rules: []string{"*"}}})

			rules, err := nilConfig.GetExcludeRules()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(rules).Should(BeNil())
		})
	})
})

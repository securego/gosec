package cwe_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2/cwe"
)

var _ = Describe("CWE Types", func() {
	BeforeEach(func() {
	})
	Context("when consulting cwe types", func() {
		It("it should retrieves the information and download URIs", func() {
			Expect(cwe.InformationURI).To(Equal("https://cwe.mitre.org/data/published/cwe_v4.4.pdf/"))
			Expect(cwe.DownloadURI).To(Equal("https://cwe.mitre.org/data/xml/cwec_v4.4.xml.zip"))
		})

		It("it should retrieves the weakness ID and URL", func() {
			weakness := &cwe.Weakness{ID: "798"}
			Expect(weakness).ShouldNot(BeNil())
			Expect(weakness.SprintID()).To(Equal("CWE-798"))
			Expect(weakness.SprintURL()).To(Equal("https://cwe.mitre.org/data/definitions/798.html"))
		})

		It("should handle nil weakness when formatting ID", func() {
			var weakness *cwe.Weakness
			Expect(weakness.SprintID()).To(Equal("CWE-0000"))
		})

		It("should marshal weakness to JSON correctly", func() {
			weakness := &cwe.Weakness{
				ID:          "89",
				Name:        "SQL Injection",
				Description: "Improper Neutralization of Special Elements used in an SQL Command",
			}

			jsonData, err := json.Marshal(weakness)
			Expect(err).ToNot(HaveOccurred())

			var result map[string]string
			err = json.Unmarshal(jsonData, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result["id"]).To(Equal("89"))
			Expect(result["url"]).To(Equal("https://cwe.mitre.org/data/definitions/89.html"))
			// Name and Description should not be in JSON
			_, hasName := result["name"]
			Expect(hasName).To(BeFalse())
			_, hasDescription := result["description"]
			Expect(hasDescription).To(BeFalse())
		})

		It("should handle weakness with different ID formats", func() {
			weakness1 := &cwe.Weakness{ID: "1"}
			Expect(weakness1.SprintID()).To(Equal("CWE-1"))
			Expect(weakness1.SprintURL()).To(Equal("https://cwe.mitre.org/data/definitions/1.html"))

			weakness2 := &cwe.Weakness{ID: "1234"}
			Expect(weakness2.SprintID()).To(Equal("CWE-1234"))
			Expect(weakness2.SprintURL()).To(Equal("https://cwe.mitre.org/data/definitions/1234.html"))
		})

		It("should handle empty weakness ID", func() {
			weakness := &cwe.Weakness{ID: ""}
			Expect(weakness.SprintID()).To(Equal("CWE-"))
			Expect(weakness.SprintURL()).To(Equal("https://cwe.mitre.org/data/definitions/.html"))
		})

		It("should marshal weakness with special characters in description", func() {
			weakness := &cwe.Weakness{
				ID:          "79",
				Name:        "XSS",
				Description: "Cross-site Scripting (XSS) \"quoted\" & <special>",
			}

			jsonData, err := json.Marshal(weakness)
			Expect(err).ToNot(HaveOccurred())
			Expect(jsonData).To(ContainSubstring("79"))
			Expect(jsonData).To(ContainSubstring("https://cwe.mitre.org/data/definitions/79.html"))
		})
	})
})

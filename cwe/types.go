// This types are based on http://cwe.mitre.org/data/xsd/cwe_schema_v6.4.xsd
package cwe

// Weakness defines a CWE weakness
type Weakness struct {
	ID          string
	Name        string
	Description string
}

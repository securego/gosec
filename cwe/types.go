package cwe

import (
	"fmt"
)

// Weakness defines a CWE weakness based on http://cwe.mitre.org/data/xsd/cwe_schema_v6.4.xsd
type Weakness struct {
	ID          string
	Name        string
	Description string
}

//URL Expose the CWE URL
func (w *Weakness) URL() string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", w.ID)
}

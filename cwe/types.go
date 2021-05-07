package cwe

import (
	"encoding/json"
	"fmt"
)

const (
	//URL is the base URL for CWE definitions
	URL = "https://cwe.mitre.org/data/definitions/"
	//Acronym is the acronym of CWE
	Acronym = "CWE"
	//Version the CWE version
	Version = "4.4"
	//ReleaseDateUtc the release Date of CWE Version
	ReleaseDateUtc = "2021-03-15"
	//Organisation MITRE
	Organization = "MITRE"
	//Description the description of CWE
	Description = "The MITRE Common Weakness Enumeration"
)

// Weakness defines a CWE weakness based on http://cwe.mitre.org/data/xsd/cwe_schema_v6.4.xsd
type Weakness struct {
	ID          string
	Name        string
	Description string
}

//SprintURL format the CWE URL
func (w *Weakness) SprintURL() string {
	return fmt.Sprintf("%s%s.html", URL, w.ID)
}

//SprintID format the CWE ID
func (w *Weakness) SprintID() string {
	return fmt.Sprintf("%s-%s", Acronym, w.ID)
}

//MarshalJSON print only id and URL
func (w *Weakness) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}{
		ID:  w.ID,
		URL: w.SprintURL(),
	})
}

func InformationURI() string {
	return fmt.Sprintf("https://cwe.mitre.org/data/published/cwe_v%s.pdf/", Version)
}

func DownloadURI() string {
	return fmt.Sprintf("https://cwe.mitre.org/data/xml/cwec_v%s.xml.zip", Version)
}

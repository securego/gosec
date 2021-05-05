package junit

import (
	"encoding/xml"
)

type JunitXMLReport struct {
	XMLName    xml.Name     `xml:"testsuites"`
	Testsuites []*Testsuite `xml:"testsuite"`
}

type Testsuite struct {
	XMLName   xml.Name    `xml:"testsuite"`
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Testcases []*Testcase `xml:"testcase"`
}

type Testcase struct {
	XMLName xml.Name `xml:"testcase"`
	Name    string   `xml:"name,attr"`
	Failure *Failure `xml:"failure"`
}

type Failure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Text    string   `xml:",innerxml"`
}

package gas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
)

// Config is used to provide configuration and customization to each of the rules.
type Config map[string]interface{}

// NewConfig initializes a new configuration instance. The configuration data then
// needs to be loaded via c.ReadFrom(strings.NewReader("config data"))
// or from a *os.File.
func NewConfig() Config {
	return make(Config)
}

// ReadFrom implements the io.ReaderFrom interface. This
// should be used with io.Reader to load configuration from
//file or from string etc.
func (c Config) ReadFrom(r io.Reader) (int64, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return int64(len(data)), err
	}
	if err = json.Unmarshal(data, c); err != nil {
		return int64(len(data)), err
	}
	return int64(len(data)), nil
}

// WriteTo implements the io.WriteTo interface. This should
// be used to save or print out the configuration information.
func (c Config) WriteTo(w io.Writer) (int64, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return int64(len(data)), err
	}
	return io.Copy(w, bytes.NewReader(data))
}

// EnableRule will change the rule to the specified enabled state
func (c Config) EnableRule(ruleID string, enabled bool) {
	if data, found := c["rules"]; found {
		if rules, ok := data.(map[string]bool); ok {
			rules[ruleID] = enabled
		}
	}
}

// Enabled returns a list of rules that are enabled
func (c Config) Enabled() []string {
	if data, found := c["rules"]; found {
		if rules, ok := data.(map[string]bool); ok {
			enabled := make([]string, len(rules))
			for ruleID := range rules {
				enabled = append(enabled, ruleID)
			}
			return enabled
		}
	}
	return nil
}

// Get returns the configuration section for a given rule
func (c Config) Get(ruleID string) (interface{}, error) {
	section, found := c[ruleID]
	if !found {
		return nil, fmt.Errorf("Rule %s not in configuration", ruleID)
	}
	return section, nil
}

// Set section for a given rule
func (c Config) Set(ruleID string, val interface{}) {
	c[ruleID] = val
}

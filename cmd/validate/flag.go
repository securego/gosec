package validate

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateFlag used for flag cli string type
type ValidatedFlag string

func (f *ValidatedFlag) String() string {
	return fmt.Sprint(*f)
}

// Set will be called for flag that is of validateFlag type
func (f *ValidatedFlag) Set(value string) error {
	if strings.Contains(value, "-") {
		return errors.New("")
	}
	return nil
}


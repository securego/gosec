package vflag

import (
	"errors"
	"fmt"
	"strings"
)

//ValidateFlag cli string type
type ValidateFlag string

func (f *ValidateFlag) String() string {
	return fmt.Sprint(*f)
}

// Set will be called for flag that is of validateFlag type
func (f *ValidateFlag) Set(value string) error {
	if strings.Contains(value, "-") {
		return errors.New("")
	}
	return nil
}


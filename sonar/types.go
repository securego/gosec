package sonar

type TextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EtartColumn int `json:"endColumn,omitempty"`
}
type Location struct {
	Message   string     `json:"message"`
	FilePath  string     `json:"filePath"`
	TextRange *TextRange `json:"textRange,omitempty"`
}

type Issue struct {
	EngineID           string      `json:"engineId"`
	RuleID             string      `json:"ruleId"`
	PrimaryLocation    *Location   `json:"primaryLocation"`
	Type               string      `json:"type"`
	Severity           string      `json:"severity"`
	EffortMinutes      int         `json:"effortMinutes"`
	SecondaryLocations []*Location `json:"secondaryLocations,omitempty"`
}

type Report struct {
	Issues []*Issue `json:"issues"`
}

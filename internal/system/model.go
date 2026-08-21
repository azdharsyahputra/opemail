package system

type CategoryReport struct {
	Name   string            `json:"name"`
	Checks map[string]string `json:"checks"`
	Passed bool              `json:"passed"`
}

type FullSystemReport struct {
	Healthy    bool                      `json:"healthy"`
	Categories map[string]CategoryReport `json:"categories"`
}

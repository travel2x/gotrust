package api

type WeakPasswordError struct {
	Message string   `json:"message,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

func (e *WeakPasswordError) Error() string {
	return e.Message
}

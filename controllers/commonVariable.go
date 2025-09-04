package controllers

type User struct {
	Email    string `json:"email" binding:"required,email"` // binding tag is used to validate the input data
	Password string `json:"password" binding:"required,min=6"`
}

type LoginPayload struct {
	Email           string         `json:"email" binding:"required,email"`
	Password        string         `json:"password"`
	TempCode        string         `json:"temp_code"`
	ApplicationName string         `json:"application_name" binding:"required"`
	AccessPayload   map[string]any `json:"access_payload" binding:"required"`
	RefreshPayload  map[string]any `json:"refresh_payload" binding:"required"`
}

// NOTES
// map[string]any is a map (like an object in JavaScript). before it was map[string]interface{}
// The keys are strings.
// The values are of type interface{}, which means they can be anything—string, int, bool, another map, a slice, etc.

package model

import (
	"time"
)

// Role represents a user's permission level
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// User represents an authenticated dashboard user
type User struct {
	ID           string    `json:"id"`            // UUID
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`             // Never serialize the password hash
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuthTokens holds the JWT pair returned upon login
type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"-"` // Passed via HTTP-only cookie, not JSON body
}

package errors

import (
	"fmt"
	"net/http"
)

// AppError represents an application-specific error
type AppError struct {
	Code       int    `json:"-"`          // HTTP status code
	Message    string `json:"message"`    // User-facing error message
	Detail     string `json:"detail"`     // Detailed error description
	Internal   error  `json:"-"`          // Internal error details (not exposed)
	StatusText string `json:"status"`     // Status text (e.g., "error", "fail")
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Internal)
	}
	return e.Message
}

// NewAppError creates a new AppError
func NewAppError(code int, message string, err error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Internal:   err,
		StatusText: "error",
	}
}

// Common application errors
var (
	ErrInvalidRequest = func(err error) *AppError {
		return NewAppError(http.StatusBadRequest, "Invalid request", err)
	}

	ErrUnauthorized = func(err error) *AppError {
		return NewAppError(http.StatusUnauthorized, "Unauthorized access", err)
	}

	ErrRateLimitExceeded = func() *AppError {
		return NewAppError(http.StatusTooManyRequests, "Rate limit exceeded", nil)
	}

	ErrInternalServer = func(err error) *AppError {
		return NewAppError(http.StatusInternalServerError, "Internal server error", err)
	}
)

// ErrorResponse writes an error response to the client
func ErrorResponse(w http.ResponseWriter, err error) {
	appErr, ok := err.(*AppError)
	if !ok {
		appErr = ErrInternalServer(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.Code)

	// Hide internal error details in production
	response := struct {
		Message string `json:"message"`
		Status  string `json:"status"`
	}{
		Message: appErr.Message,
		Status:  appErr.StatusText,
	}

	json.NewEncoder(w).Encode(response)
}
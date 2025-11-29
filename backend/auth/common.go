package auth

// isTokenExpired checks if the error is due to token expiration
func isTokenExpired(err error) bool {
	// Check for specific Clerk token expiration errors
	if err == nil {
		return false
	}
	
	// Clerk typically returns specific error messages for expired tokens
	errMsg := err.Error()
	return contains(errMsg, "expired") || 
	       contains(errMsg, "invalid") || 
	       contains(errMsg, "exp") ||
	       contains(errMsg, "token")
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
	       (s == substr || 
	        (len(s) > len(substr) && 
	         (s[:len(substr)] == substr || 
	          s[len(s)-len(substr):] == substr ||
	          containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
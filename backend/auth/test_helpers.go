package auth

// MockEmailService is a shared mock email service for testing
type MockEmailService struct{}

func (m *MockEmailService) SendPasswordResetEmail(toEmail string, resetToken string, ipAddress string) error {
	return nil
}

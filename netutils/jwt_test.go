package netutils_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/whoseyourdd/utilities/netutils"
)

func TestTryEncrypt(t *testing.T) {
	tests := []struct {
		name            string
		payload         map[string]interface{}
		expectedError   bool
		expectedPayload map[string]interface{}
	}{
		{
			name: "success",
			payload: map[string]interface{}{
				"payload1":   "test1",
				"payload2":   "test2",
				"payloadint": float64(1),
			},
			expectedError: false,
			expectedPayload: map[string]interface{}{
				"payload1":   "test1",
				"payload2":   "test2",
				"payloadint": int32(1),
			},
		},
		{
			name:            "empty payload",
			payload:         map[string]interface{}{},
			expectedError:   false,
			expectedPayload: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretKey := "secretKey"

			// Generate JWT token
			jwt, err := netutils.GenerateJWTToken(tt.payload, secretKey)
			if tt.expectedError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Decrypt JWT token
			encryptedPayload, err := netutils.GetEncryptedClaims(*jwt)
			if err != nil {
				t.Fatalf("Error while decrypting JWT: %v\n", err)
			}
			fmt.Printf("Decoded payload: %+v\n", encryptedPayload)

			decryptedPayload, err := netutils.GetDecryptedPayload(*jwt, secretKey)
			if err != nil {
				t.Fatalf("Error while decrypting JWT: %v\n", err)
			}

			// Print debug information
			fmt.Printf("Input: %+v\n", tt.payload)
			fmt.Printf("Got: %+v\n", decryptedPayload)
			fmt.Printf("Expected: %+v\n", tt.expectedPayload)

			// Assertions to ensure payload is correctly encrypted and decrypted
			assert.Equal(t, tt.expectedPayload, decryptedPayload, "Decoded payload does not match the original")
		})
	}
}

package main

import (
	"fmt"

	"github.com/whoseyourdd/utilities/netutils"
)

func tryEncrypt() error {

	payload := map[string]interface{}{
		"payload1":   "test1",
		"payload2":   "test2",
		"payloadint": 1,
	}

	jwt, err := netutils.GenerateJWTToken(payload, "secretKey")
	if err != nil {
		return fmt.Errorf("Error while generating JWT: %v\n", err)
	}

	decodedPayload, err := netutils.DecryptJWTToken(*jwt)

	decryptedPayload, err := decodedPayload.GetPayload("secretKey")
	if err != nil {
		return fmt.Errorf("failed to decode JWT: %v", err)
	}
	fmt.Printf("Decoded Payload: %v\n", decryptedPayload)
	return nil
}

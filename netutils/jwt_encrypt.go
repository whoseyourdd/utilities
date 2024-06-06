package netutils

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/whoseyourdd/utilities"
)

func EncryptPayload(payload map[string]interface{}, key string) (map[string]interface{}, error) {
	encryptedPayload := make(map[string]interface{})
	for key, value := range payload {
		switch v := value.(type) {
		case string:
			encryptedValue, err := utilities.Encrypt([]byte(v), key)
			if err != nil {
				return nil, err
			}
			encryptedPayload[key] = string(encryptedValue)
		case int, int8, int16, int32, int64, float32, float64, bool:
			encryptedValue, err := utilities.Encrypt([]byte(fmt.Sprintf("%v", v)), key)
			if err != nil {
				return nil, err
			}
			encryptedPayload[key] = string(encryptedValue)
		default:
			jsonValue, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			encryptedValue, err := utilities.Encrypt(jsonValue, key)
			if err != nil {
				return nil, err
			}
			encryptedPayload[key] = string(encryptedValue)
		}
	}
	return encryptedPayload, nil
}

func DecryptPayload(encryptedPayload map[string]interface{}, key string) (map[string]interface{}, error) {
	decryptedPayload := make(map[string]interface{})
	for key, value := range encryptedPayload {
		switch v := value.(type) {
		case string:
			decryptedValue, err := utilities.Decrypt(v, key)
			if err != nil {
				return nil, err
			}
			var jsonValue interface{}
			if err := json.Unmarshal(decryptedValue, &jsonValue); err != nil {
				decryptedPayload[key] = string(decryptedValue)
			} else {
				switch jsonValue.(type) {
				case float64:
					decryptedPayload[key] = int32(jsonValue.(float64))
				case string:
					decryptedPayload[key] = jsonValue
				default:
					decryptedPayload[key] = jsonValue
				}
			}
		default:
			return nil, errors.New("unsupported encrypted value type")
		}
	}
	return decryptedPayload, nil
}

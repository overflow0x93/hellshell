package io

import (
	"bytes"
	"os"
)

// ReadPayloadFile reads a file from disk and returns the data and size.
func ReadPayloadFile(fileInput string) ([]byte, error) {
	data, err := os.ReadFile(fileInput)
	if err != nil {
		return nil, err //, errors.Wrap(err, "failed to read file")
	}
	return data, nil
}

// WritePayloadFile writes data to a file.
func WritePayloadFile(filePath string, payloadSize int, payloadData []byte) error {
	err := os.WriteFile(filePath, payloadData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func AppendInputPayload(multipleOf int, payload []byte) ([]byte, error) {
	appendSize := len(payload) + multipleOf - (len(payload) % multipleOf)
	appendedPayload := bytes.Repeat([]byte{0x90}, appendSize)
	copy(appendedPayload, payload)
	return appendedPayload, nil
}

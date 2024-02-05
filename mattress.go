// Package mattress provides a secure way to handle sensitive data within Go applications.
// It uses the memguard library to create encrypted enclaves for sensitive information,
// ensuring that data is protected both in memory and during runtime. The package is designed
// to help prevent accidental leaks of sensitive data through improper memory handling or
// exposure via runtime panics.
//
// Note: While this package provides a higher degree of security for sensitive data, it's
// important to understand that no method is foolproof. Users should combine this with other
// security best practices to ensure comprehensive protection.
//
// Warning: This package uses runtime finalizers to ensure cleanup of sensitive data. Because
// Go's runtime does not guarantee when finalizers will run, it's possible for sensitive data
// to remain in memory longer than intended. Use with caution and ensure you understand the
// implications.
package mattress

import (
	"bytes"
	"encoding/gob"
	"runtime"

	"github.com/awnumar/memguard"
)

func init() {
	// CatchInterrupt ensures that if the application is interrupted, any sensitive data
	// handled by memguard will be securely wiped from memory before exit.
	memguard.CatchInterrupt()
}

// Secret holds a reference to a securely stored piece of data of any type.
// The data is stored within a memguard.LockedBuffer, providing encryption at rest
// and secure memory handling.
type Secret[T any] struct {
	buffer *memguard.LockedBuffer
}

// NewSecret initializes a new Secret with the provided data. It serializes the data using
// encoding/gob and stores it securely using memguard. This function returns an error if
// encoding the data fails or if there is an issue securing the data in memory.
func NewSecret[T any](data T) (*Secret[T], error) {
	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)

	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}

	bytes := buf.Bytes()

	enclave := memguard.NewEnclave(bytes)

	buffer, err := enclave.Open()
	if err != nil {
		return nil, err
	}

	// WipeBytes securely erases the original byte slice to minimize the risk of data leakage.
	memguard.WipeBytes(bytes)

	// Assign a runtime finalizer to ensure the secure buffer is wiped when the Secret is
	// garbage collected.
	secret := &Secret[T]{buffer: buffer}
	runtime.SetFinalizer(secret, func(s *Secret[T]) {
		s.zero()
	})

	return secret, nil
}

// zero securely wipes the memory area holding the sensitive data, ensuring it cannot
// be accessed once the Secret is no longer needed.
func (s *Secret[T]) zero() {
	s.buffer.Destroy()
}

// Expose decrypts and returns the stored data. Note that this operation potentially
// exposes sensitive data in memory. Ensure that the returned data is handled securely
// and is wiped from memory when no longer needed.
func (s *Secret[T]) Expose() T {
	var data T

	gob.NewDecoder(bytes.NewReader(s.buffer.Bytes())).Decode(&data)

	return data
}

// String provides a safe string representation of the Secret, ensuring that sensitive
// data is not accidentally exposed via logging or other string handling mechanisms.
func (s *Secret[T]) String() string {
	return "[SECRET]"
}

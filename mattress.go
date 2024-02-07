// mattress provides a secure way to handle sensitive data within Go applications.
// It leverages the memguard library to create encrypted enclaves for sensitive information,
// ensuring that data is protected both in memory and during runtime. This package is designed
// to mitigate accidental leaks of sensitive data through improper memory handling or
// exposure via runtime panics.
//
// Note: While this package offers enhanced security for sensitive data, it is important to
// acknowledge that no method is entirely foolproof. Users are encouraged to employ this
// package in conjunction with other security best practices for more comprehensive protection.
//
// Warning: This package utilizes runtime finalizers to ensure cleanup of sensitive data. Due
// to the nature of Go's runtime, which does not guarantee immediate execution of finalizers,
// sensitive data may reside in memory longer than anticipated. Users should proceed with
// caution and ensure they fully comprehend the potential implications.
//
// Example Usage:
//
//	import m "github.com/garrettladley/mattress"
//
//	type User struct {
//	  Username string
//	  Password *m.Secret[string]
//	}
//
//	func main() {
//	  password, err := m.NewSecret("password")
//	  if err != nil {
//	    // handle error
//	  }
//
//	  user := User{
//	    Username: "username",
//	    Password: password,
//	  }
//
//	  fmt.Println(user.Password) // Output: memory address
//	  fmt.Println(user.Password.String()) // Output: "[SECRET]"
//	  fmt.Println(user.Password.Expose()) // Output: "password"
//	}
package mattress

import (
	"bytes"
	"encoding/gob"
	"runtime"
	"sync"

	"github.com/awnumar/memguard"
)

// init is called on package load and sets up a signal handler to catch interrupts.
// This ensures that sensitive data is securely wiped from memory if the application
// is interrupted.
func init() {
	// CatchInterrupt ensures that if the application is interrupted, any sensitive data
	// handled by memguard will be securely wiped from memory before exit.
	memguard.CatchInterrupt()
}

// Secret holds a reference to a securely stored piece of data of any type.
// The data is stored within a memguard.LockedBuffer, providing encryption at rest
// and secure memory handling.
type Secret[T any] struct {
	buffer *memguard.LockedBuffer // buffer holds the encrypted data
	mutex  sync.Mutex             // synchronize access to the buffer
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
	s.mutex.Lock()         // Lock before accessing the buffer
	defer s.mutex.Unlock() // Ensure the mutex is unlocked when the method returns

	var data T

	gob.NewDecoder(bytes.NewReader(s.buffer.Bytes())).Decode(&data)

	return data
}

// String provides a safe string representation of the Secret, ensuring that sensitive
// data is not accidentally exposed via logging or other string handling mechanisms.
func (s *Secret[T]) String() string {
	return "[SECRET]"
}

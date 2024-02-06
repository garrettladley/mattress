<h1 align="center">mattress</h1>

<div align="center">
    <img src="./mattress.png" alt="Mattress Logo" width="25%">
</div>

<h2 align="center">Like storing your secrets under your mattress, but better</h2>

<div align="center">
  <a href="https://goreportcard.com/report/github.com/garrettladley/mattress">
    <img src="https://goreportcard.com/badge/github.com/garrettladley/mattress"
      alt="Mattress Go Report" />
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0">
    <img src="https://img.shields.io/badge/License-GPLv3-blue.svg"
      alt="GNU GPL v3.0 License" />
  </a>
  <a href="https://pkg.go.dev/github.com/garrettladley/mattress#section-documentation">
    <img src="https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white"
      alt="Go.Dev Reference" />
  </a>
</div>

A Go port of Rust's [secrecy](https://github.com/iqlusioninc/crates/tree/main/secrecy) crate.

> [!NOTE]
> Disclaimer:
>
> While this package offers enhanced security for sensitive data, it is important to acknowledge that no method is entirely foolproof. Users are encouraged to employ this package in conjunction with other security best practices for more comprehensive protection.
>
> Warning:
>
> This package utilizes runtime finalizers to ensure cleanup of sensitive data. Due to the nature of Go's runtime, which does not guarantee immediate execution of finalizers, sensitive data may reside in memory longer than anticipated. Users should proceed with caution and ensure they fully comprehend the potential implications.

# Example

```go
import m "github.com/garrettladley/mattress"

type User struct {
  Username string
  Password *m.Secret[string]
}

func main() {
  password, err := m.NewSecret("password")
  if err != nil {
    // handle error
  }

  user := User{
    Username: "username",
    Password: password,
  }

  fmt.Println(user.Password) // Output: memory address
  fmt.Println(user.Password.String()) // Output: "[SECRET]"
  fmt.Println(user.Password.Expose()) // Output: "password"
}
```

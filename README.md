<h1 align="center">mattress</h1>

<div align="center">
    <img src="./mattress.png" alt="Mattress Logo" width="25%">
</div>

<h2 align="center">Like storing your secrets under your mattress, but better</h2>

A Go port of Rust's [secrecy](https://github.com/iqlusioninc/crates/tree/main/secrecy) crate.

> [!NOTE]
> Disclaimer:
> 
> While this package provides a higher degree of security for sensitive data, it's important to understand that no method is foolproof. Users should combine this with other security best practices to ensure comprehensive protection.
>
> Warning:
> 
> This package uses runtime finalizers to ensure cleanup of sensitive data. Because Go's runtime does not guarantee when finalizers will run, it's possible for sensitive data to remain in memory longer than intended. Use with caution and ensure you understand the implications.

# Example

```go

import m "github.com/garrettladley/mattress"

type User struct {
    Username string
    Password Secret[string]
}

password, err := m.New("password")

// handle err

user := User{
    Username: "username",
    Password: *password,
}

fmt.Println(user.Password.Expose())
```

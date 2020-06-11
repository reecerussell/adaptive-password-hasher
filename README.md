[![Go Report Card](https://goreportcard.com/badge/github.com/reecerussell/adaptive-password-hasher)](https://goreportcard.com/badge/github.com/reecerussell/adaptive-password-hasher)
[![CircleCI](https://circleci.com/gh/reecerussell/adaptive-password-hasher/tree/master.png?style=shield)](https://circleci.com/gh/reecerussell/adaptive-password-hasher/tree/master.png?style=shield)
[![codecov](https://codecov.io/gh/reecerussell/adaptive-password-hasher/branch/master/graph/badge.svg)](https://codecov.io/gh/reecerussell/adaptive-password-hasher)
[![Go Docs](https://godoc.org/github.com/reecerussell/adaptive-password-hasher?status.svg)](https://godoc.org/github.com/reecerussell/adaptive-password-hasher)

# Adaptive Password Hasher

<img src="https://media.giphy.com/media/loXfQtPqLxGmbLs9h2/giphy.gif" align="right" width="40%" alt="A super cool gif" />

A simple, adaptive, password hashing module for Go!

Using the pbkdf2 key derivation algorithm, the module has functionality to hash and verify hashes, for a number of different hash algorithms, key and salt sizes. Currently, only the SHA256 and SHA512 hashing functions are supported - more are to come if needed, but feel free to open a PR for another.

## Contents

- [Installation](#installation)
- [Get Started](#get-started)
  - [Defaults](#defaults)
- [Advanced](#advanced)

## <span id="installation">Installation</span>

Installation is very simple. By using the Go CLI and `go get` installation can be achieved by running:

    go get -u github.com/reecerussell/adaptive-password-hasher
    
## <span id="get-started">Get Started</span>

To get started, you must first install the package, which you can do [here](#installation).

First of all, add the module import:

```go
import (
    hasher "github.com/reecerussell/adaptive-password-hasher"
)
```
    
Then, you can use the exported functions `Hash` and `Verify`. Hashing a password can be done as follows:

```go
pwd := []byte("MySuperSecurePassword")
hash := hasher.hash(pwd)
    
// encode & print
fmt.Printf("My Hashed Password: %s\n", base64.StdEncoding.EncodeToString(hash))
```    
So what if you need to verify it? Easy!

    ok := hasher.Verify(pwd, hash)
    fmt.Printf("Verified: %v\n", ok)
    
And that's it!

### <span id="defaults">Defaults</span>

These exported functions all use the default hasher interface, meaning they use the default hashing values.

| Default          | Value   | Property             |
|------------------|---------|----------------------|
|Iteration Count   | 1000    |DefaultIterationCount |
|Salt Size         | 128-bit |DefaultSaltSize       |
|Key Size          | 256-bit |DefaultKeySize        |
|Hashing Algorithm | SHA256  |DefaultHashKey        |

## <span id="advanced">Advanced</span>

So you'd like to change the hashing algorithm or maybe even key size. It's just as simple as using the default functions. By using the `New()` function, you can pass in your own settings. The `New()` function requires 4 parameters: iteration count, salt size, key size and a hashing algorithm key.

### <span id="hash-keys">Hash Keys</span>

Currently, both SHA256 and SHA512 are supported, which means you can use them in your password hasher. Stored as constants, each supported algorithm has a "hash key", which make it easy to switch to different hashes and are used to distinguise what hash functions were used for a specific hash.

| Constant   | Algorithm | Value |
|------------|-----------|-------|
| HashSHA256 | SHA256    | 1     |
| HashSHA512 | SHA512    | 2     |

### <span id="setup">Setup</span>

Using this module with the `New()` function allows a lot more versability by enabling you to customise the hasher to your needs.

Here is an example on how to set it up:

```go
myIterationCount := 15000
mySaltSize := 128
myKeySize := 256
myHashKey := hasher.HashSHA512

myHasher, err := hasher.New(myIterationCount, mySaltSize, myKeySize, myHashKey)
if err != nil {
    panic(err)
}

// hash a password
pwd := []byte("MySecurePassword")
hash := myHasher.Hash([]byte(pwd))

// encode and print
fmt.Printf("Hash: %s\n", base64.StdEncoding.EncodeToString(hash))

// verify
ok := myHasher.Verify(pwd, hash)
fmt.Printf("Verified: %v\n", ok)
```

Using the "advanced" method of setting up the hasher, you get the same API and functions as the default method of using it. It's worth noting you can pass in the default constants as arguments to the `New()` function.

## Info

Updated on 11/06/2020 - Reece

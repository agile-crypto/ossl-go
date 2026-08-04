// Package ossl is a Go binding for OpenSSL 3.x libcrypto.
//
// All cgo and unsafe usage in a program should be confined to this package.
// Callers see ordinary Go types: []byte, string, error, io.Writer.
//
// Every type that owns C memory has a Close method. Use defer.
package ossl

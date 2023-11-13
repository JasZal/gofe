# GoFE - Functional Encryption library

This is a forked instance of the [gofe library](https://github.com/fentec-project/gofe). GoFE is a cryptographic library offering different state-of-the-art implementations of functional encryption schemes, specifically FE
schemes for _linear_ (e.g. _inner products_) and _quadratic polynomials_.
For details on how to use and which schemes are implemented, please check out the original github project. 


We added two schemes, that are secure noisy FE schemes. 


### Before using the library
Please note that the library is a work in progress and has not yet
reached a stable release. Code organization and APIs are **not stable**.
You can expect them to change at any point.

The purpose of GoFE is to support research and proof-of-concept
implementations. It **should not be used in production**.

## Installing GoFE
First, clone the repository via git clone and build the library by running either
`go install github.com/JasZal/gofe/...` or
 `go get -u -t github.com/JasZal/gofe/...` from the terminal (note that this also
 downloads and builds all the dependencies of the library).
 Please note that from Go version 1.18 on, `go get` will [no longer build packages](https://golang.org/doc/go-get-install-deprecation),
 and `go install` should be used instead.
 

# Fastly Edge Computing

This project is part of the _22. Innovation and Hacking Days_ and tries to explore what we can do with serverless computing on Fastly's edge nodes.
Fastly provides some kind of web IDE that makes it pretty easy to deploy code to their edge nodes, the project is called [terrarium][2]
It uses [lucet][3] as a compiler backend that translates the code, be it in Rust, Javascript or C to webassembly (WASM) which is then executed on their edge nodes.

## Task

What we want to achieve today is to validate JWT tokens using Fastly's Terrarium platform and to rate-limit on a per IP basis.

## Setup

The following instructions are explained thoroughly on in this [blog post][4].

- install a Rust distribution through [rustup](https://rustup.rs)
- install the compiler toolchain that supports wasm targets: `rustup toolchain add nightly`
- install what is required to compile to wasm: `rustup target add wasm32-unknown-unknown --toolchain nightly`

This does not need to be done, but here's how to create a sample project:

- this creates a project scaffold `cargo new --lib jwt-edge-validation`
- configure the project to be a dynamic library by adding this to `jwt-edge-validation/Cargo.toml`:

```toml
[lib]
crate-type=["cdylib"]
```

- cd into `jwt-edge-validation` and run `rustup override set nightly` to set the nightly toolchain as default

## Build

Debug build: `cargo build --target wasm32-unknown-unknown`, the binary can then be found in `target/wasm32-unknown-unknown/debug/`
Release build: `cargo build --release --target wasm32-unknown-unknown`, the path is then `target/wasm32-unknown-unknown/release/`

## Deployment

To access Fastly's Terrarium API we use [terrctl][5], it can be installed either via `go get -u github.com/fastly/terrctl/terrctl` or by using the [prebuilt binaries](https://github.com/fastly/terrctl/releases/latest).

```
$ terrctl src/lib.rs
```

## Usage

At first generate a JWT with arbitrary payload and sign it with HMAC256, e.g. using [jwt.io](https://jwt.io), using this secret `ZPM//uZwrUN85ogHI0JAb8K1SFtNw270W6wdU4Op1Wk=`.

```
$ curl --header "Authorization: Bearer <Token>" "https://<deployment-domain>.com/some/path?param=value"
```

Example: `curl --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.nJkjEH_2wFclNpjG4mem7xShvYDS9UB3zfHmQ93CNiQ' https://captured-crew-prove-meant.fastly-terrarium.com/get`

[2]: https://wasm.fastlylabs.com/
[3]: https://github.com/fastly/lucet/
[4]: https://www.fastly.com/blog/edge-programming-rust-web-assembly
[5]: https://github.com/fastly/terrctl

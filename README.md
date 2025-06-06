# rdf-proofs

**WORK IN PROGRESS**

This library is designed to facilitate the attachment of BBS+ signatures to RDF graphs, enabling the issuance of Verifiable Credentials.
It also supports the aggregation of multiple Verifiable Credentials and allows for selective disclosure of their components.
This results in the creation of Verifiable Presentations in the form of RDF datasets.
The library utilizes the BBS+ signature scheme and proof-system library from [docknetwork/crypto](https://github.com/docknetwork/crypto).

**⚠️ Experimental Phase**: This library is currently in an experimental phase and is not recommended for use in production environments.

## Using the Library

Ensure that Rust is installed on your system.
**Note**: Starting with version 0.11.0, this crate requires **Rust 1.81 or later** due to updates in its dependencies, including Wasmer.

Add this crate to your project by running the following command:

```shell
cargo add rdf-proofs
```

## Build

```shell
cargo build
```

or

```shell
cargo build --release
```

## Test

```shell
cargo test
```

or
```shell
cargo test --release
```

## Examples

TBD

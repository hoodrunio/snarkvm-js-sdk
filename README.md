# snarkvm-js-sdk

A TypeScript SDK for interacting with Aleo's snarkVM, providing cryptographic primitives and account management utilities. This library implements Aleo's account model, including private keys, view keys, and address generation, along with core cryptographic operations using the Ed25519 curve.

## Key Features

- Account Management (Private Keys, View Keys, Addresses)
- Ed25519 Curve Operations
- Schnorr Signature Implementation
- Bech32m Address Encoding/Decoding
- Cryptographic Primitives (Hash Functions, Scalar Operations)
- Network-specific Parameters Support

## Core Components

- Account Management: Private/View Key Generation, Address Derivation
- Cryptographic Operations: Group Operations, Scalar Math, Hash Functions
- Encoding Utilities: Bech32m, Base58
- Error Handling: Specialized Error Types

Built for developers integrating with Aleo Network, this SDK provides a type-safe interface for client-side cryptographic operations.
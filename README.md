# cc7

`cc7` is a support library used in [PowerAuth Mobile SDK](https://github.com/wultra/powerauth-mobile-sdk) and other Wultra projects. It provides multiplatform C++ interfaces that unify native code across iOS and Android, along with build scripts for OpenSSL bundled with the library.

## Namespaces

| Namespace | Description |
|-----------|-------------|
| `cc` | General utilities: Base64 encoding/decoding and foundational support objects |
| `cc7::crypto` | Cryptographic library built on top of OpenSSL, providing the subset of functions required by Wultra projects |
| `cc7::json` | JSON parser and writer designed to minimise sensitive data leaking in memory |
| `cc7::jwt` | Simple JWT / JWS signer and verifier |
| `cc7::objc` | Apple-platform bridge: converts key objects between C++ and Objective-C |
| `cc7::jni` | Android bridge: converts key objects between C++ and Java via JNI |
| `cc7::utils` | Miscellaneous utility objects |

## Essential objects

| Class | Description |
|-------|-------------|
| `cc7::ByteArray` | Safe memory container that zeroes and cleans up its bytes upon destruction |
| `cc7::ByteRange` | Lightweight, non-owning view over a region of memory — typically used as function input |
| `cc7::crypto::Key` | Interface for a generic cryptographic key |
| `cc7::crypto::SymmetricKey` | Key for symmetric encryption algorithms and MACs |
| `cc7::crypto::PublicKey` | Public key |
| `cc7::crypto::PrivateKey` | Private key |
| `cc7::crypto::KeyPair` | Public and private key pair |

## Supported algorithms

| Class | Description |
|-------|-------------|
| `cc7::crypto::Cipher` | Interface for symmetric encryption, such as AES |
| `cc7::crypto::MAC` | Interface for computing and verifying MAC, such as KMAC |
| `cc7::crypto::MessageDigest` | Interface for computing message digest, such as SHA3 |
| `cc7::crypto::KeyAgreement` | Interface for key agreement, such as ECDH |
| `cc7::crypto::KeyEncapsulation` | Interface for key encapsulation, such as ML-KEM |
| `cc7::crypto::Signature` | Interface for calculating and verifying digital signatures, such as ECDSA, ML-DSA |
| `cc7::crypto::Random` | Random data generator |
| `cc7::crypto::AEAD` | Interface for AEAD algorithms, such as AES-GCM |

## Platform support

- **iOS / macOS** — Xcode project in [proj-xcode/](proj-xcode/), Swift Package Manager support via [Package.swift](Package.swift)
- **Android** — Android project in [proj-android/](proj-android/)

## OpenSSL

Pre-built OpenSSL libraries are located in [openssl-lib/](openssl-lib/). Build scripts used to produce them are in [openssl-build/](openssl-build/).

## License

See [LICENSE](LICENSE).

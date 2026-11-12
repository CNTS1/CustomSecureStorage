# 🔐 CustomSecureStorage

### A C++ Secure Storage and Cryptography Library









---

## 📖 Overview

**CustomSecureStorage** is a C++ cryptography and secure-storage library designed to provide developers with a set of reusable components for protecting sensitive application data.

The project combines modern cryptographic primitives with Windows Data Protection API (DPAPI) and SQLite-based persistence to provide a foundation for applications that need encrypted data storage and local cryptographic key management.

Rather than relying on a single encryption function, the library separates its responsibilities into dedicated components:

- Symmetric authenticated encryption.
- Cryptographic key generation and protection.
- Elliptic-curve key exchange.
- Cryptographic key derivation.
- Persistent storage for protected keys and encrypted records.

The library is currently under active development. Its APIs, internal implementation, and feature set may evolve as the project progresses.

> **Development note:** This project is being developed incrementally. Some components are implemented and available, while additional functionality, testing, documentation, and integration improvements are planned.

---

## ✨ Current Features

### 🔒 1. AES-256-GCM Encryption

The `CryptoEngine` component provides symmetric encryption and decryption using **AES-256-GCM** through OpenSSL's EVP interface.

Implemented capabilities:

- 256-bit encryption keys.
- 96-bit nonce generation using OpenSSL's cryptographic random generator.
- 128-bit authentication tags.
- Authenticated encryption and decryption.
- Authentication-tag verification during decryption.
- Rejection of modified ciphertext or invalid authentication tags.
- RAII-managed OpenSSL cipher contexts.
- Temporary plaintext-buffer cleansing with `OPENSSL_cleanse`.

Encrypted output is represented by the `EncryptedData` structure:

```cpp
struct EncryptedData
{
    Nonce nonce{};
    Data cipherText;
    Tag tag{};
};
```

The nonce, ciphertext, and authentication tag are kept together so they can be stored and retrieved as a single encrypted record.

### 🔑 2. Cryptographic Key Management

The `KeyManger` component provides utilities for generating and managing AES-256 keys.

Implemented capabilities:

- Cryptographically secure key generation using `RAND_bytes`.
- Windows DPAPI-based key protection.
- Key restoration through `CryptUnprotectData`.
- Constant-time key comparison using `CRYPTO_memcmp`.
- Sensitive temporary-buffer cleansing.
- RAII management of DPAPI-allocated memory.

The library uses Windows DPAPI to protect keys under the current user's Windows security context.

**Important:** DPAPI protection is tied to the relevant Windows security context. It is not a portable key-storage format that can automatically be restored on another operating system or user account.

### 🔄 3. X25519 Key Exchange

The `KeyExchange` component implements elliptic-curve Diffie–Hellman key exchange using **X25519**.

Implemented capabilities:

- X25519 key-pair generation.
- Raw 32-byte public and private key representation.
- Shared-secret derivation.
- OpenSSL EVP-based implementation.
- Validation of the derived shared secret.
- Rejection of an all-zero shared-secret result.
- Sensitive output cleansing on failure.

The component exposes:

```cpp
KeyExchange::GenerateKeyPair();
KeyExchange::DeriveSharedSecret();
```

X25519 allows two parties to derive a common secret using their own private key and the other party's public key.

The resulting shared secret should not be used directly as an AES encryption key. A key-derivation function should be applied first.

### 🧬 4. HKDF-SHA256 Key Derivation

The `KeyDerivation` component provides key derivation using **HKDF with SHA-256**.

Implemented capabilities:

- HKDF-based key derivation.
- X25519 shared-secret input.
- Optional salt input.
- Optional context-specific `info` input.
- 32-byte derived AES-256 key output.
- OpenSSL 3 EVP_KDF interface.
- Sensitive output cleansing on failure.
- RAII management of OpenSSL KDF resources.

Main interface:

```cpp
KeyDerivation::DeriveAESKey(
    sharedSecret,
    salt,
    info,
    derivedKey
);
```

The `salt` and `info` parameters allow the derivation process to be configured for a particular cryptographic context.

### 🗄️ 5. SQLite Secure Storage

The `Storage` component provides a C++ interface for persisting protected keys and encrypted records using SQLite.

Implemented capabilities:

- SQLite database creation and opening.
- Database schema initialization.
- Persistent storage of DPAPI-protected keys.
- Persistent storage of AES-GCM encrypted records.
- Separate key and record tables.
- Key identifiers and record identifiers.
- Active and retired key states.
- A database constraint that allows only one active key.
- Foreign-key relationships between records and keys.
- Prepared SQL statements and bound parameters.
- Explicit database transactions.
- SQLite extended result codes.
- Database busy timeout configuration.
- RAII management of prepared statements.
- Database handle cleanup through the `Storage` destructor.
- File-permission restriction attempts.

The database stores encrypted record components separately:

| Field        | Purpose                   |
| ------------ | ------------------------- |
| `record_id`  | Unique record identifier  |
| `key_id`     | Associated encryption key |
| `nonce`      | AES-GCM nonce             |
| `ciphertext` | Encrypted data            |
| `tag`        | Authentication tag        |
| `created_at` | Record creation timestamp |

The key table stores protected key blobs rather than raw AES key values.

---

## 🧩 Architecture

The library is organized into independent components, each responsible for a specific part of the cryptographic and storage workflow.

```text
CustomSecureStorage
│
├── CryptoEngine
│   ├── AES-256-GCM Encryption
│   ├── AES-256-GCM Decryption
│   ├── Nonce Generation
│   └── Authentication Tag Verification
│
├── KeyManger
│   ├── Secure Key Generation
│   ├── DPAPI Protection
│   ├── DPAPI Restoration
│   └── Constant-Time Key Comparison
│
├── KeyExchange
│   ├── X25519 Key Generation
│   └── Shared Secret Derivation
│
├── KeyDerivation
│   └── HKDF-SHA256
│
└── Storage
    ├── SQLite Database
    ├── Protected Key Persistence
    ├── Encrypted Record Persistence
    └── Active / Retired Key Management
```

### 🔐 Example Cryptographic Workflow

A typical application can use the available components in the following sequence:

```text
              Generate AES Key
                     |
                     v
              Protect Key (DPAPI)
                     |
                     v
              Store Protected Key
                     |
                     v
                Plaintext Data
                     |
                     v
              AES-256-GCM Encrypt
                     |
                     v
             Nonce + Ciphertext + Tag
                     |
                     v
             Store Encrypted Record
                     |
                     v
               Retrieve Record
                     |
                     v
              Restore Protected Key
                     |
                     v
              AES-256-GCM Decrypt
                     |
                     v
              Authenticated Plaintext
```

X25519 and HKDF are also available as separate components for applications that need to establish and derive cryptographic keys between parties.

**Note:** This workflow illustrates how the components can be combined by an application. The library does not currently provide a single high-level API that automatically performs every step.

---

## 📁 Project Structure

```text
CustomSecureStorage/
│
├── SecureStorage - V1/
│   │
│   ├── include/
│   │   ├── CryptoEngine.h
│   │   ├── KeyDerivation.h
│   │   ├── KeyExchange.h
│   │   ├── KeyManger.h
│   │   └── Storage.h
│   │
│   ├── src/
│   │   ├── CryptoEngine.cpp
│   │   ├── KeyDerivation.cpp
│   │   ├── KeyExchange.cpp
│   │   ├── KeyManger.cpp
│   │   └── Storage.cpp
│   │
│   └── lib/
│       └── libSecureStorage.a
│
└── README.md
```

---

## ⚙️ Dependencies

The current implementation relies on the following external libraries and platform APIs:

| Dependency    | Purpose                                                                      |
| ------------- | ---------------------------------------------------------------------------- |
| C++           | Core implementation                                                          |
| OpenSSL 3.x   | AES-GCM, X25519, HKDF, secure random generation, and cryptographic utilities |
| SQLite3       | Persistent storage                                                           |
| Windows DPAPI | Local cryptographic key protection                                           |
| Windows SDK   | Windows platform APIs                                                        |

### Platform Notes

- The key-management implementation currently uses Windows DPAPI and Windows headers.
- The project is therefore Windows-oriented in its current form.
- SQLite and OpenSSL must be available to the application during compilation and linking.
- The presence of a POSIX permission-handling branch in the storage implementation does not mean that the complete library is currently portable to Linux or macOS.

---

## 🚀 Basic Usage

The following example demonstrates how the implemented components can be combined to generate a key, protect it, encrypt data, and save the resulting encrypted record.

```cpp
#include "CryptoEngine.h"
#include "KeyManger.h"
#include "Storage.h"

#include <iostream>
#include <string>

int main()
{
    CryptoEngine::Key encryptionKey{};
    KeyManger::ProtectedKey protectedKey;

    CryptoEngine::EncryptedData encryptedData;

    Storage storage;

    // Generate an AES-256 key.
    if (!KeyManger::GenerateKey(encryptionKey))
        return 1;

    // Protect the key using Windows DPAPI.
    if (!KeyManger::ProtectKey(encryptionKey, protectedKey))
        return 1;

    // Open and initialize the database.
    if (!storage.Open("secure_storage.db"))
        return 1;

    if (!storage.Initialize())
        return 1;

    // Save the protected key as the active key.
    Storage::KeyId keyId = 0;

    if (!storage.SaveProtectedKey(protectedKey, keyId, true))
        return 1;

    // Encrypt application data.
    const std::string message = "Sensitive application data";

    if (!CryptoEngine::Encrypt(encryptionKey, message, encryptedData))
        return 1;

    // Persist the encrypted record.
    Storage::RecordId recordId = 0;

    if (!storage.SaveEncryptedRecord(keyId, encryptedData, recordId))
        return 1;

    std::cout << "Encrypted record saved successfully.\n";
    std::cout << "Record ID: " << recordId << '\n';

    storage.Close();

    return 0;
}
```

This is a basic illustration of the current public interfaces, not a complete production-ready application. A complete application should also implement reliable error handling, secure cleanup of sensitive objects, and a carefully defined key lifecycle.

---

## 🛡️ Security Considerations

CustomSecureStorage uses established cryptographic primitives through OpenSSL and Windows platform security facilities.

However, using established algorithms does not automatically make an entire application secure.

Important considerations:

- AES-GCM nonces must never be reused with the same encryption key.
- Private keys and derived secrets must be protected throughout their lifecycle.
- DPAPI protection depends on the Windows security context and the application's deployment model.
- X25519 key exchange alone does not authenticate the identity of the other party.
- Applications using X25519 should implement an appropriate peer-authentication mechanism.
- HKDF should be used to derive purpose-specific keys from shared secrets.
- Authentication failures must be treated as decryption failures.
- Database access permissions and backups must be considered part of the security model.
- Memory cleansing reduces exposure of sensitive buffers but cannot guarantee that every copy of sensitive data has been erased.

**Security status:** This project has not been presented as independently audited, formally verified, or production-certified. Review and test the implementation within your own threat model before using it to protect important data.

---

## 🗺️ Roadmap

The following items represent potential future development directions. They are planned ideas, not currently implemented features.

### 🔑 Cryptographic Improvements

- [ ] A higher-level cryptographic session API combining X25519, HKDF, and AES-GCM.
- [ ] Explicit key lifecycle management.
- [ ] More structured key rotation workflows.
- [ ] Additional key-purpose separation.
- [ ] Optional authenticated additional data (AAD) support for AES-GCM.
- [ ] More comprehensive cryptographic input validation.
- [ ] Secure-memory abstractions for sensitive key material.

### 🗄️ Storage Improvements

- [ ] Database schema versioning and migration support.
- [ ] Record deletion and secure lifecycle management APIs.
- [ ] More comprehensive key-rotation and historical-key workflows.
- [ ] Improved database backup and recovery utilities.
- [ ] Storage integrity and consistency checks.
- [ ] Configurable database security policies.

### 🧱 Architecture and Developer Experience

- [ ] CMake-based build and installation system.
- [ ] Cleaner public API organization.
- [ ] Unified error-handling and diagnostic interfaces.
- [ ] More comprehensive API documentation.
- [ ] Additional usage examples.
- [ ] Automated unit and integration tests.
- [ ] Improved cross-platform architecture.
- [ ] Dedicated secure-storage configuration interface.

### 🧪 Testing and Reliability

- [ ] Cryptographic test vectors.
- [ ] Negative tests for invalid keys and corrupted ciphertext.
- [ ] Database failure and recovery tests.
- [ ] Memory-management testing.
- [ ] Fuzz testing for relevant input-handling interfaces.
- [ ] Continuous integration build and test workflows.

The roadmap may change as the implementation evolves.

---

## 📚 Documentation

Full API documentation will be published separately.

It will cover:

- Class and function references.
- Parameter descriptions.
- Return values and failure conditions.
- Cryptographic workflows.
- Storage architecture.
- Integration examples.
- Dependency and build configuration.

**Full API Documentation:**

🔗 [**Documentation Website — Coming Soon**]([YOUR_DOCUMENTATION_URL](https://kalikali-lgtml.github.io/SecureStorageLib/))

---

## ⚠️ Development Status

CustomSecureStorage is an evolving C++ project.

The current version provides the core cryptographic and storage components described above, but additional development is required to improve integration, testing, portability, documentation, and overall API design.

Interfaces and implementation details may change between versions.

Contributions, technical feedback, and suggestions are welcome.

---

## 📜 License

The repository's licensing and redistribution terms should be reviewed before using or redistributing this project.
---

/**
 * file CryptoEngine.h
 * brief Declares the CryptoEngine class providing symmetric encryption and decryption.
 */

#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <string>
#include <vector>
#include <array>
#include <cstddef>

/**
 * Class CryptoEngine
 * Brief Provides symmetric encryption and decryption using a key, nonce, and tag.
 */
class CryptoEngine
{
public:
    // Size in bytes of the encryption key.
    static constexpr std::size_t KEY_SIZE = 32;

    // Size in bytes of the nonce.
    static constexpr std::size_t NONCE_SIZE = 12;

    // Size in bytes of the authentication tag.
    static constexpr std::size_t TAG_SIZE = 16;

    // Fixed-size array holding the encryption key.
    using Key = std::array<unsigned char, KEY_SIZE>;

    // Fixed-size array holding the nonce.
    using Nonce = std::array<unsigned char, NONCE_SIZE>;

    // Fixed-size array holding the authentication tag.
    using Tag = std::array<unsigned char, TAG_SIZE>;

    // Dynamic buffer holding arbitrary binary data.
    using Data = std::vector<unsigned char>;

    /**
     * Struct: EncryptedData
     * Brief:Bundles the nonce, ciphertext, and tag produced by encryption.
     */
    struct EncryptedData
    {
        // Nonce used during encryption.
        Nonce nonce{};

        // Encrypted payload.
        Data cipherText;

        // Authentication tag for integrity verification.
        Tag tag{};
    };

    // Encrypts plaintext into an EncryptedData bundle.
    static bool Encrypt(const Key& key, const std::string& plainText, EncryptedData& output);

    // Decrypts an EncryptedData bundle back into plaintext.
    static bool Decrypt(const Key& key, const EncryptedData& input, std::string& plainText);
};

#endif
/**
 * file KeyManger.h
 * brief Static utility class for cryptographic key management.
 */

#ifndef KEY_MANGER_H
#define KEY_MANGER_H

#include "CryptoEngine.h"

#include <vector>
#include <cstdint>


/**
 * Class: KeyManger
 * Brief: Provides static routines for generating, protecting,
 *        restoring, and verifying cryptographic keys.
 */
class KeyManger
{
 public:

    // Alias for the underlying cryptographic key type.
    using Key = CryptoEngine::Key;

    // Container holding a protected (encrypted) key blob.
    using ProtectedKey = std::vector<unsigned char>;

    // Generates a new cryptographic key.
    static bool GenerateKey(Key& key);

    // Protects a key by converting it into a protected blob.
    static bool ProtectKey(const Key& key, ProtectedKey& protectedKey);

    // Restores a key from a previously protected blob.
    static bool RestoreKey(const ProtectedKey& protectedKey, Key& resotredkey);

    // Verifies whether two keys match.
    static bool VerifyKeys(const Key& first, Key& second);
};
#endif
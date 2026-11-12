#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include "CryptoEngine.h"
#include "KeyExchange.h"

#include <cstddef>
#include <vector>

class KeyDerivation
{
public:
    using Salt = std::vector<unsigned char>;
    using Info = std::vector<unsigned char>;

    // Derives a secure AES-256 key from an X25519 shared secret using HKDF-SHA256.
    static bool DeriveAESKey(const KeyExchange::SharedSecret& sharedSecret, const Salt& salt, const Info& info, CryptoEngine::Key& derivedKey);
};

#endif
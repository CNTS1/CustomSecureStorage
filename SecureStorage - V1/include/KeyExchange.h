/**
 * file KeyExchange.h
 * brief Declares the KeyExchange class providing X25519 key pair generation and shared secret derivation.
 */

#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include <array>
#include <cstddef>

class KeyExchange
{
  public:
  
 // X25519 Uses 32-Byte (256-bit) Keys And Shared Secrets.
 static constexpr std::size_t KEY_SIZE = 32;
 static constexpr std::size_t SHARED_SECRET_SIZE = 32;

 using PublicKey = std::array<unsigned char, KEY_SIZE>;
 using PrivateKey = std::array<unsigned char, KEY_SIZE>;
 using SharedSecret = std::array<unsigned char, SHARED_SECRET_SIZE>;

 struct KeyPair
 {
   PublicKey publicKey{};
   PrivateKey privateKey{};
 };

 // Generate a Fresh Cryptographic X25519 Key Pair (Public & Private).
 static bool GenerateKeyPair(KeyPair& keyPair);

 // Derives a 32-Byte Shared Secret Using out Private key and the Perr's Public Key.
 static bool DeriveSharedSecret(const PrivateKey& privateKey, const PublicKey& perrPublicKey, SharedSecret& sharedSecret);
};
#endif
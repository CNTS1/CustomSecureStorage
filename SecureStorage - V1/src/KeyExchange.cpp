/*==============================================================================
   KeyExchange.cpp
 ------------------------------------------------------------------------------
   Implementation of the KeyExchange public interface.

   Provides X25519 key pair generation and Diffie-Hellman shared secret
   derivation using OpenSSL's EVP API. All sensitive buffers are wiped
   on failure, and derived secrets are validated against the all-zero
   output that would indicate a small-subgroup public key.

   See KeyExchange.h for the full project description and usage overview.
 ==============================================================================*/

#include "../include/KeyExchange.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <memory>


namespace
{
    //Custom Deleters For OpenSSL Types To Ensure Proper 'RAII' memory Managment
    struct EVP_PKEY_Deleter
    {
     void operator()(EVP_PKEY* pkey) const noexcept
     {
        if(pkey != nullptr)
        {
            EVP_PKEY_free(pkey);
        }
     }
    };

    struct EVP_PKEY_CTX_Deleter
    {
        void operator()(EVP_PKEY_CTX* ctx) const noexcept
        {
         if(ctx != nullptr)
         {
            EVP_PKEY_CTX_free(ctx);
         }
        }
    };

    using PkeyPtr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
    using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;

    //Reject all-zero secrets that indicate a small-subgroup public key
    bool IsAllZero(const unsigned char* data, std::size_t size) noexcept
    {
        unsigned char accumulator = 0;
        for(std::size_t i = 0; i < size; ++i)
        {
            accumulator |= data[i];
        }
        return accumulator == 0;
    }
}


bool KeyExchange::GenerateKeyPair(KeyPair& keyPair)
{
    // Wipe any previous private key so a failed call never leaves stale data
    OPENSSL_cleanse(keyPair.privateKey.data(), keyPair.privateKey.size());
    
    //Create a New Context For 'X25519' Key Generation.
    PkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if(!pctx)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if(EVP_PKEY_keygen_init(pctx.get()) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    EVP_PKEY* rawPKey = nullptr;
    if(EVP_PKEY_keygen(pctx.get(), &rawPKey) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    PkeyPtr pkey(rawPKey);

    std::size_t pubLen = KEY_SIZE;
    std::size_t privLen = KEY_SIZE;

    // Extract Raw Public and Private Keys Into Our Standard Arrays
    if(EVP_PKEY_get_raw_public_key(pkey.get(), keyPair.publicKey.data(), &pubLen) <= 0 || EVP_PKEY_get_raw_private_key(pkey.get(), keyPair.privateKey.data(), &privLen) <= 0)
    {
        OPENSSL_cleanse(keyPair.privateKey.data(), keyPair.privateKey.size());
        ERR_print_errors_fp(stderr);
        return false;
    }

    if(pubLen != KEY_SIZE || privLen != KEY_SIZE)
    {
        OPENSSL_cleanse(keyPair.privateKey.data(), keyPair.privateKey.size());
        return false;
    }

    return true;
}

bool KeyExchange::DeriveSharedSecret(const PrivateKey& privateKey, const PublicKey& perrPublicKey, SharedSecret& sharedSecret)
{
    //Wipe any previous secret so a failed call never leaves stale data
    OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());

    // Import Our Raw Private Key Into OpenSSL EVP_PKEY
    EVP_PKEY* rawPriv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,nullptr,privateKey.data(),privateKey.size());

    PkeyPtr privPkey(rawPriv);
    if(!privPkey)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Import Perr's Raw Public Key into OpenSSL EVP_PKEY
    EVP_PKEY* rawPub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,nullptr,perrPublicKey.data(),perrPublicKey.size());
    PkeyPtr pubPkey(rawPub);

    if(!pubPkey)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Create Derivation Context Using Our Private Key
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(privPkey.get(), nullptr));
    if(!ctx)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if(EVP_PKEY_derive_init(ctx.get()) <= 0)
    {
       ERR_print_errors_fp(stderr);
       return false;
    }

    // Set The Perr's Public Key For The Diffie-Hellman Operation
    if(EVP_PKEY_derive_set_peer(ctx.get(), pubPkey.get()) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::size_t secretLen = SHARED_SECRET_SIZE;

    // Compute The Final Shared Secret
    if(EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &secretLen) <= 0)
    {
        OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());
        ERR_print_errors_fp(stderr);
        return false;
    }

    if(secretLen != SHARED_SECRET_SIZE)
    {
        OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());
        return false;
    }

    //Reject all-zero output that would indicate a small-subgroup peer key
    if(IsAllZero(sharedSecret.data(), sharedSecret.size()))
    {
        OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());
        return false;
    }

    return true;
}
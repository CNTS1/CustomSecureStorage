/*==============================================================================
   KeyDerivation.cpp
 ------------------------------------------------------------------------------
   Implementation of the KeyDerivation public interface.

   Provides HKDF-SHA256 key derivation from an X25519 shared secret, an
   optional salt, and optional context info. The derived output is a
   32-byte AES-256 key suitable for CryptoEngine.

   See KeyDerivation.h for the full project description and usage overview.
 ==============================================================================*/

#include "../include/KeyDerivation.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <memory>

namespace
{
    // Custom deleters for OpenSSL 3.0+ KDF objects ensuring RAII memory safety
    struct EVP_KDF_Deleter
    {
        void operator()(EVP_KDF* kdf) const noexcept
        {
            if (kdf != nullptr)
            {
                EVP_KDF_free(kdf);
            }
        }
    };

    struct EVP_KDF_CTX_Deleter
    {
        void operator()(EVP_KDF_CTX* ctx) const noexcept
        {
            if (ctx != nullptr)
            {
                EVP_KDF_CTX_free(ctx);
            }
        }
    };

    using KDFPtr = std::unique_ptr<EVP_KDF, EVP_KDF_Deleter>;
    using KDF_CtxPtr = std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter>;
}

bool KeyDerivation::DeriveAESKey(
    const KeyExchange::SharedSecret& sharedSecret,
    const Salt& salt,
    const Info& info,
    CryptoEngine::Key& derivedKey
)
{
    // Wipe any previous key so a failed call never leaves stale data
    OPENSSL_cleanse(derivedKey.data(), derivedKey.size());

    // 1. Fetch the HKDF algorithm from OpenSSL
    KDFPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 2. Create the KDF context
    KDF_CtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 3. Prepare parameters for HKDF (Digest type, Secret Key, Salt, and Info)
    char digestName[] = "SHA256";

    OSSL_PARAM params[6];
    std::size_t idx = 0;

    params[idx++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        digestName,
        0
    );

    params[idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        const_cast<unsigned char*>(sharedSecret.data()),
        sharedSecret.size()
    );

    if (!salt.empty())
    {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            const_cast<unsigned char*>(salt.data()),
            salt.size()
        );
    }

    if (!info.empty())
    {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            const_cast<unsigned char*>(info.data()),
            info.size()
        );
    }

    params[idx++] = OSSL_PARAM_construct_end();

    // 4. Derive the final AES-256 key using the configured parameters
    if (EVP_KDF_derive(ctx.get(), derivedKey.data(), derivedKey.size(), params) <= 0)
    {
        ERR_print_errors_fp(stderr);
        OPENSSL_cleanse(derivedKey.data(), derivedKey.size());
        return false;
    }

    return true;
}
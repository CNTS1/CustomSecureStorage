/*==============================================================================
   CryptoEngine.cpp
 ------------------------------------------------------------------------------
   Implementation of the CryptoEngine public interface.

   Provides AES-256-GCM authenticated encryption and decryption using
   OpenSSL's EVP API. The implementation follows the official OpenSSL
   GCM usage sequence and returns false on any failure.

   See CryptoEngine.h for the full project description, security model,
   and usage overview.
 ==============================================================================*/

#include "../include/CryptoEngine.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <memory>
#include <limits>


// Encrypts plainText with AES-256-GCM and fills output with nonce, ciphertext, and tag.
bool CryptoEngine::Encrypt(const Key& key, const std::string& plainText, EncryptedData& output)
{
    // Reject inputs that cannot be represented as an int for OpenSSL.
    if(plainText.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }

    // Generate a fresh 96-bit nonce for this message.
    if(RAND_bytes(output.nonce.data(), static_cast<int>(output.nonce.size())) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Create an RAII-managed cipher context.
    using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if(!ctx)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Initialize the context with AES-256-GCM.
    if(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Set the nonce length explicitly before use.
    if(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(output.nonce.size()), nullptr) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Supply the key and nonce to the context.
    if(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), output.nonce.data()) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Allocate the ciphertext buffer; GCM output length equals input length.
    output.cipherText.resize(plainText.size());

    int cipherTextLength = 0;
    int finalLength = 0;

    // Encrypt the plaintext (skipped for empty input).
    if(!plainText.empty())
    {
        if(EVP_EncryptUpdate(ctx.get(), output.cipherText.data(), &cipherTextLength, reinterpret_cast<const unsigned char*>(plainText.data()), static_cast<int>(plainText.size())) != 1)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
    }

    // Finalize the encryption operation.
    if(EVP_EncryptFinal_ex(ctx.get(), output.cipherText.data() + cipherTextLength, &finalLength) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Adjust the buffer to the actual ciphertext length.
    output.cipherText.resize(cipherTextLength + finalLength);

    // Extract the 128-bit authentication tag.
    if(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(output.tag.size()), output.tag.data()) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}


// Decrypts input with AES-256-GCM and verifies the tag before producing plainText.
bool CryptoEngine::Decrypt(const Key& key, const EncryptedData& input, std::string& plainText)
{
    // Clear the output first so a failed call never leaves stale data behind.
    plainText.clear();

    // Reject inputs that cannot be represented as an int for OpenSSL.
    if(input.cipherText.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }

    using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if(!ctx)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Initialize the context with AES-256-GCM.
    if(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Set the nonce length explicitly before use.
    if(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(input.nonce.size()), nullptr) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Supply the key and nonce to the context.
    if(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), input.nonce.data()) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Allocate the plaintext buffer; GCM output length equals input length.
    Data decrypted(input.cipherText.size());

    int plainTextLength = 0;
    int finalLength = 0;

    // Decrypt the ciphertext (skipped for empty input).
    if(!input.cipherText.empty())
    {
        if(EVP_DecryptUpdate(ctx.get(), decrypted.data(), &plainTextLength, input.cipherText.data(), static_cast<int>(input.cipherText.size())) != 1)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
    }

    // Provide the expected tag; OpenSSL only reads it even though the API takes a non-const pointer.
    if(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(input.tag.size()), const_cast<unsigned char*>(input.tag.data())) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Verify the tag and finalize; a mismatch here means tampering or a wrong key.
    if(EVP_DecryptFinal_ex(ctx.get(), decrypted.data() + plainTextLength, &finalLength) != 1)
    {
        OPENSSL_cleanse(decrypted.data(), decrypted.size());
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Publish the plaintext only after successful authentication.
    plainText.assign(reinterpret_cast<const char*>(decrypted.data()), static_cast<std::size_t>(plainTextLength + finalLength));

    // Wipe the temporary buffer before releasing it.
    OPENSSL_cleanse(decrypted.data(), decrypted.size());

    return true;
}
/*==============================================================================
   KeyManger.cpp
 ------------------------------------------------------------------------------
   Implementation of the KeyManger public interface.

   Provides secure key generation, protection, restoration, and verification
   using OpenSSL's RNG and Windows DPAPI. Keys are protected with the current
   user's credentials by default and are never written to disk in plaintext.

   See KeyManger.h for the full project description and usage overview.
 ==============================================================================*/

#include "../include/KeyManger.h"

#include <windows.h>
#include <dpapi.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <memory>
#include <cstring>
#include <iostream>
#include <limits>

#pragma comment(lib, "Crypt32.lib")

namespace
{
    struct LocalFreeDeleter
    {
    void operator()(BYTE* ptr)const noexcept
    {
        if(ptr != nullptr)
        {
            LocalFree(ptr);
        }
    }
    };
    using DPAPI_Buffer = std::unique_ptr<BYTE,LocalFreeDeleter>;
}


// Fills the supplied key with 32 cryptographically secure random bytes.
bool KeyManger::GenerateKey(Key& key)
{
    // Use OpenSSL's CSPRNG for secure random generation.
    if(RAND_bytes(key.data(),static_cast<int>(key.size())) != 1)
    {
        OPENSSL_cleanse(key.data(), key.size());
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    return true;
}


// Encrypts the key with DPAPI and stores the protected blob in protectedKey.
bool KeyManger::ProtectKey(const Key& key, ProtectedKey& protectedKey)
{
    // Wipe any previous protected key before reuse.
    if(!protectedKey.empty())
    {
        OPENSSL_cleanse(protectedKey.data(), protectedKey.size());
    }
    protectedKey.clear();

    Key temporaryKey = key;

    DATA_BLOB input{};
    DATA_BLOB output{};

    input.cbData = static_cast<DWORD>(temporaryKey.size());
    input.pbData = temporaryKey.data();

    // Protect the key with the current user's credentials.
    BOOL success = CryptProtectData(&input, L"SecureStorage AES-256 Key",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output);

    OPENSSL_cleanse(temporaryKey.data(), temporaryKey.size());

    DPAPI_Buffer outputBuffer(output.pbData);

    if(!success)
    {
        std::cerr << "[-]Crypt Protect Data Failed. ERROR: " << GetLastError() << '\n';
        return false;
    }

    if(output.pbData == nullptr || output.cbData == 0)
    {
        return false;
    }

    // Copy the protected blob into the output vector.
    try
    {
        protectedKey.assign(output.pbData,output.pbData + output.cbData);
    }
    catch(...)
    {
    if(!protectedKey.empty())
    {
     OPENSSL_cleanse(protectedKey.data(), protectedKey.size());
    }
    protectedKey.clear();
    return false;
    }

    return true;
}


// Decrypts a DPAPI-protected blob back into the original 32-byte key.
bool KeyManger::RestoreKey(const ProtectedKey& protectedKey, Key& restoredKey)
{
    // Fail-safe: never leave a stale key in the output.
    OPENSSL_cleanse(restoredKey.data(), restoredKey.size());

    if(protectedKey.empty() || protectedKey.size() > std::numeric_limits<DWORD>::max())
    {
        return false;
    }

    DATA_BLOB input{};
    DATA_BLOB output{};

    input.cbData = static_cast<DWORD>(protectedKey.size());
    input.pbData = const_cast<BYTE*>(protectedKey.data());

    // Unprotect using the current user's credentials.
    BOOL success = CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN, &output);

    DPAPI_Buffer outputBuffer(output.pbData);

    if(!success)
    {
        std::cerr << "[-]Crypt Unprotect Data Failed. Error: " << GetLastError() << '\n';
        return false;
    }

    // Verify the recovered blob matches the expected key size.
    if(output.pbData == nullptr || output.cbData != restoredKey.size())
    {
        if(output.pbData != nullptr && output.cbData > 0)
        {
            OPENSSL_cleanse(output.pbData, output.cbData);
        }
        return false;
    }

    std::memcpy(restoredKey.data(), output.pbData, restoredKey.size());

    OPENSSL_cleanse(output.pbData, output.cbData);

    return true;
}


// Compares two keys in constant time to avoid timing leaks.
bool KeyManger::VerifyKeys(const Key& first, Key& second)
{
    return CRYPTO_memcmp(first.data(),second.data(),first.size()) == 0;
}
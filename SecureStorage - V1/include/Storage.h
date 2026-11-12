/*==============================================================================
   Storage.h
 ------------------------------------------------------------------------------
   Public interface for the Storage module.

   Provides a thin, exception-free C++ wrapper around a SQLite database
   used to persist DPAPI-protected keys and AES-256-GCM encrypted records.
   The class owns a single sqlite3 handle and exposes explicit Open,
   Initialize, and Close operations.

   The Storage object is non-copyable and manages its database handle
   through RAII: the destructor closes the handle if it is still open.

   See Storage.cpp for the implementation details.
 ==============================================================================*/

#ifndef STORAGE_H
#define STORAGE_H

#include "CryptoEngine.h"

#include <string>
#include <vector>
#include <cstdint>

struct sqlite3;

class Storage
{   
 public:
    
    using RecordId = std::int64_t;
    using KeyId = std::int64_t;
    using ProtectedKey = std::vector<unsigned char>;

    Storage() noexcept;
    ~Storage();

    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&)= delete;

    // Opens the SQLite database at the given path.
    bool Open(const std::string& dataBasePath);

    // Creates the required tables if they do not already exist.
    bool Initialize();

    // Closes the database handle if it is open.
    void Close() noexcept;

    // Stores a protected key and optionally marks it as active.
    bool SaveProtectedKey(const ProtectedKey& protectedKey, KeyId& keyId, bool makeActive);

    // Loads a protected key by its identifier.
    bool LoadProtectedKey(KeyId keyId, ProtectedKey& protectedKey) const;

    // Marks the given key as the active one.
    bool SetActiveKey(KeyId KeyId);

    // Retrieves the identifier of the currently active key.
    bool GetActiveKeyId(KeyId& KeyId) const;

    // Stores an encrypted record bound to the given key.
    bool SaveEncryptedRecord(KeyId keyId, const CryptoEngine::EncryptedData& encryptedData, RecordId& recordId);

    // Loads an encrypted record and its associated key identifier.
    bool LoadEncryptedRecord(RecordId recordId, KeyId& KeyId, CryptoEngine::EncryptedData& encryptedData) const;

    private:
    
    sqlite3* db_ = nullptr;
};

#endif
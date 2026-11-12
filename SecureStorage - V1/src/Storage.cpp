/*==============================================================================
   Storage.cpp
 ------------------------------------------------------------------------------
   Implementation of the Storage public interface.

   Provides SQLite-backed persistence for DPAPI-protected keys and
   AES-256-GCM encrypted records. All statements use prepared bindings,
   all multi-step writes run inside explicit transactions, and every
   resource is released through RAII.

   See Storage.h for the full project description and usage overview.
 ==============================================================================*/

#include "../include/Storage.h"

#include <sqlite3.h>

#include <openssl/crypto.h>

#include <memory>
#include <limits>
#include <iostream>
#include <utility>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#else
#include <sys/stat.h>
#endif

namespace
{
    struct StatementDeleter
    {
        void operator()(sqlite3_stmt* statement) const noexcept
        {
            if (statement != nullptr)
            {
                sqlite3_finalize(statement);
            }
        }
    };

    using Statement = std::unique_ptr<
        sqlite3_stmt,
        StatementDeleter
    >;

    void LogDatabaseError(
        sqlite3* db,
        const char* operation
    )
    {
        if (db != nullptr)
        {
            std::cerr << operation
                      << " failed: "
                      << sqlite3_errmsg(db)
                      << '\n';
        }
        else
        {
            std::cerr << operation << " failed.\n";
        }
    }

    Statement Prepare(
        sqlite3* db,
        const char* sql
    )
    {
        sqlite3_stmt* rawStatement = nullptr;

        int result = sqlite3_prepare_v2(
            db,
            sql,
            -1,
            &rawStatement,
            nullptr
        );

        if (result != SQLITE_OK)
        {
            LogDatabaseError(db, "sqlite3_prepare_v2");

            if (rawStatement != nullptr)
            {
                sqlite3_finalize(rawStatement);
            }

            return {};
        }

        return Statement(rawStatement);
    }

    bool ExecuteSQL(
        sqlite3* db,
        const char* sql
    )
    {
        char* errorMessage = nullptr;

        int result = sqlite3_exec(
            db,
            sql,
            nullptr,
            nullptr,
            &errorMessage
        );

        if (result != SQLITE_OK)
        {
            if (errorMessage != nullptr)
            {
                std::cerr << "SQLite error: "
                          << errorMessage
                          << '\n';

                sqlite3_free(errorMessage);
            }
            else
            {
                LogDatabaseError(db, "sqlite3_exec");
            }

            return false;
        }

        return true;
    }

    bool BindBlob(
        sqlite3_stmt* statement,
        int parameterIndex,
        const unsigned char* data,
        std::size_t size
    )
    {
        if (size > static_cast<std::size_t>(
            std::numeric_limits<int>::max()))
        {
            return false;
        }

        if (size == 0)
        {
            return sqlite3_bind_zeroblob(
                statement,
                parameterIndex,
                0
            ) == SQLITE_OK;
        }

        return sqlite3_bind_blob(
            statement,
            parameterIndex,
            data,
            static_cast<int>(size),
            SQLITE_TRANSIENT
        ) == SQLITE_OK;
    }

    bool BeginTransaction(sqlite3* db)
    {
        return ExecuteSQL(db, "BEGIN IMMEDIATE;");
    }

    bool CommitTransaction(sqlite3* db)
    {
        return ExecuteSQL(db, "COMMIT;");
    }

    void RollbackTransaction(sqlite3* db)
    {
        ExecuteSQL(db, "ROLLBACK;");
    }

    bool ValidateDatabasePath(const std::string& path)
    {
        if (path.empty())
        {
            return false;
        }

        if (path.find('\0') != std::string::npos)
        {
            return false;
        }

        if (path.find("..") != std::string::npos)
        {
            return false;
        }

        return true;
    }

    bool RestrictFilePermissions(const std::string& path)
    {
#ifdef _WIN32
        HANDLE fileHandle = CreateFileA(
            path.c_str(),
            WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        PACL acl = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;

        if (GetSecurityInfo(
            fileHandle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &acl,
            nullptr,
            &descriptor
        ) != ERROR_SUCCESS)
        {
            CloseHandle(fileHandle);
            return false;
        }

        EXPLICIT_ACCESS_A access{};
        access.grfAccessPermissions = GENERIC_ALL;
        access.grfAccessMode = SET_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;

        HANDLE tokenHandle = nullptr;
        if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &tokenHandle))
        {
            LocalFree(descriptor);
            CloseHandle(fileHandle);
            return false;
        }

        DWORD tokenSize = 0;
        GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenSize);

        std::unique_ptr<BYTE[]> tokenBuffer(new (std::nothrow) BYTE[tokenSize]);
        if (!tokenBuffer ||
            !GetTokenInformation(
                tokenHandle,
                TokenUser,
                tokenBuffer.get(),
                tokenSize,
                &tokenSize))
        {
            CloseHandle(tokenHandle);
            LocalFree(descriptor);
            CloseHandle(fileHandle);
            return false;
        }

        auto* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenBuffer.get());
        access.Trustee.ptstrName = reinterpret_cast<LPSTR>(tokenUser->User.Sid);

        PACL newAcl = nullptr;
        bool success = SetEntriesInAclA(1, &access, acl, &newAcl) == ERROR_SUCCESS;

        if (success)
        {
            success = SetSecurityInfo(
                fileHandle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                newAcl,
                nullptr
            ) == ERROR_SUCCESS;
        }

        if (newAcl != nullptr)
        {
            LocalFree(newAcl);
        }

        CloseHandle(tokenHandle);
        LocalFree(descriptor);
        CloseHandle(fileHandle);

        return success;
#else
        return chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0;
#endif
    }
}

// ============================================================
// Constructor and Destructor
// ============================================================

Storage::Storage() noexcept = default;

Storage::~Storage()
{
    Close();
}

// ============================================================
// Open
// ============================================================

bool Storage::Open(const std::string& databasePath)
{
    if (db_ != nullptr || !ValidateDatabasePath(databasePath))
    {
        return false;
    }

    sqlite3* temporaryDatabase = nullptr;

    int result = sqlite3_open_v2(
        databasePath.c_str(),
        &temporaryDatabase,
        SQLITE_OPEN_READWRITE |
        SQLITE_OPEN_CREATE |
        SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (result != SQLITE_OK)
    {
        LogDatabaseError(
            temporaryDatabase,
            "sqlite3_open_v2"
        );

        if (temporaryDatabase != nullptr)
        {
            sqlite3_close_v2(temporaryDatabase);
        }

        return false;
    }

    db_ = temporaryDatabase;

    sqlite3_extended_result_codes(db_, 1);

    if (sqlite3_busy_timeout(db_, 1500) != SQLITE_OK)
    {
        LogDatabaseError(db_, "sqlite3_busy_timeout");
        Close();
        return false;
    }

    if (!ExecuteSQL(db_, "PRAGMA foreign_keys = ON;"))
    {
        Close();
        return false;
    }

    RestrictFilePermissions(databasePath);

    return true;
}

// ============================================================
// Initialize
// ============================================================

bool Storage::Initialize()
{
    if (db_ == nullptr)
    {
        return false;
    }

    if (!BeginTransaction(db_))
    {
        return false;
    }

    const char* schema = R"SQL(

        CREATE TABLE IF NOT EXISTS keys
        (
            key_id INTEGER PRIMARY KEY AUTOINCREMENT,

            protected_key BLOB NOT NULL,

            status TEXT NOT NULL
                CHECK(status IN ('active', 'retired')),

            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_key
        ON keys(status)
        WHERE status = 'active';

        CREATE TABLE IF NOT EXISTS records
        (
            record_id INTEGER PRIMARY KEY AUTOINCREMENT,

            key_id INTEGER NOT NULL,

            nonce BLOB NOT NULL,

            ciphertext BLOB NOT NULL,

            tag BLOB NOT NULL,

            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(key_id)
                REFERENCES keys(key_id)
        );

        CREATE INDEX IF NOT EXISTS idx_records_key_id
        ON records(key_id);

    )SQL";

    if (!ExecuteSQL(db_, schema))
    {
        RollbackTransaction(db_);
        return false;
    }

    if (!CommitTransaction(db_))
    {
        RollbackTransaction(db_);
        return false;
    }

    return true;
}

// ============================================================
// Close
// ============================================================

void Storage::Close() noexcept
{
    if (db_ != nullptr)
    {
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
}

// ============================================================
// SaveProtectedKey
// ============================================================

bool Storage::SaveProtectedKey(
    const ProtectedKey& protectedKey,
    KeyId& keyId,
    bool makeActive
)
{
    if (db_ == nullptr ||
        protectedKey.empty() ||
        protectedKey.size() >
            static_cast<std::size_t>(
                std::numeric_limits<int>::max()))
    {
        return false;
    }

    if (!BeginTransaction(db_))
    {
        return false;
    }

    if (makeActive)
    {
        Statement retireStatement = Prepare(
            db_,
            "UPDATE keys SET status = 'retired' "
            "WHERE status = 'active';"
        );

        if (!retireStatement)
        {
            RollbackTransaction(db_);
            return false;
        }

        if (sqlite3_step(retireStatement.get()) != SQLITE_DONE)
        {
            LogDatabaseError(db_, "Retire previous key");
            RollbackTransaction(db_);
            return false;
        }
    }

    const char* insertSQL =
        "INSERT INTO keys (protected_key, status) "
        "VALUES (?, ?);";

    Statement insertStatement = Prepare(
        db_,
        insertSQL
    );

    if (!insertStatement)
    {
        RollbackTransaction(db_);
        return false;
    }

    const char* status = makeActive
        ? "active"
        : "retired";

    if (!BindBlob(
        insertStatement.get(),
        1,
        protectedKey.data(),
        protectedKey.size()
    ))
    {
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_bind_text(
        insertStatement.get(),
        2,
        status,
        -1,
        SQLITE_STATIC
    ) != SQLITE_OK)
    {
        LogDatabaseError(db_, "sqlite3_bind_text");
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_step(insertStatement.get()) != SQLITE_DONE)
    {
        LogDatabaseError(db_, "Insert protected key");
        RollbackTransaction(db_);
        return false;
    }

    KeyId newKeyId = sqlite3_last_insert_rowid(db_);

    if (!CommitTransaction(db_))
    {
        RollbackTransaction(db_);
        return false;
    }

    keyId = newKeyId;

    return true;
}

// ============================================================
// LoadProtectedKey
// ============================================================

bool Storage::LoadProtectedKey(
    KeyId keyId,
    ProtectedKey& protectedKey
) const
{
    if (db_ == nullptr || keyId <= 0)
    {
        return false;
    }

    Statement statement = Prepare(
        db_,
        "SELECT protected_key "
        "FROM keys "
        "WHERE key_id = ?;"
    );

    if (!statement)
    {
        return false;
    }

    if (sqlite3_bind_int64(
        statement.get(),
        1,
        keyId
    ) != SQLITE_OK)
    {
        LogDatabaseError(db_, "sqlite3_bind_int64");
        return false;
    }

    int result = sqlite3_step(statement.get());

    if (result != SQLITE_ROW)
    {
        return false;
    }

    if (sqlite3_column_type(statement.get(), 0) != SQLITE_BLOB)
    {
        return false;
    }

    const void* blob = sqlite3_column_blob(
        statement.get(),
        0
    );

    int blobSize = sqlite3_column_bytes(
        statement.get(),
        0
    );

    if (blobSize < 0)
    {
        return false;
    }

    ProtectedKey temporary;

    try
    {
        if (blobSize > 0)
        {
            if (blob == nullptr)
            {
                return false;
            }

            const auto* bytes =
                static_cast<const unsigned char*>(blob);

            temporary.assign(
                bytes,
                bytes + blobSize
            );
        }
    }
    catch (...)
    {
        if (!temporary.empty())
        {
            OPENSSL_cleanse(temporary.data(), temporary.size());
        }
        return false;
    }

    if (!protectedKey.empty())
    {
        OPENSSL_cleanse(protectedKey.data(), protectedKey.size());
    }

    protectedKey = std::move(temporary);

    return true;
}

// ============================================================
// SetActiveKey
// ============================================================

bool Storage::SetActiveKey(KeyId keyId)
{
    if (db_ == nullptr || keyId <= 0)
    {
        return false;
    }

    if (!BeginTransaction(db_))
    {
        return false;
    }

    Statement retireStatement = Prepare(
        db_,
        "UPDATE keys "
        "SET status = 'retired' "
        "WHERE status = 'active' "
        "AND key_id != ?;"
    );

    if (!retireStatement)
    {
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_bind_int64(
        retireStatement.get(),
        1,
        keyId
    ) != SQLITE_OK)
    {
        LogDatabaseError(db_, "Bind key ID");
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_step(retireStatement.get()) != SQLITE_DONE)
    {
        LogDatabaseError(db_, "Retire active key");
        RollbackTransaction(db_);
        return false;
    }

    Statement activateStatement = Prepare(
        db_,
        "UPDATE keys "
        "SET status = 'active' "
        "WHERE key_id = ?;"
    );

    if (!activateStatement)
    {
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_bind_int64(
        activateStatement.get(),
        1,
        keyId
    ) != SQLITE_OK)
    {
        LogDatabaseError(db_, "Bind key ID");
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_step(activateStatement.get()) != SQLITE_DONE)
    {
        LogDatabaseError(db_, "Activate key");
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_changes(db_) != 1)
    {
        RollbackTransaction(db_);
        return false;
    }

    if (!CommitTransaction(db_))
    {
        RollbackTransaction(db_);
        return false;
    }

    return true;
}

// ============================================================
// GetActiveKeyId
// ============================================================

bool Storage::GetActiveKeyId(KeyId& keyId) const
{
    if (db_ == nullptr)
    {
        return false;
    }

    Statement statement = Prepare(
        db_,
        "SELECT key_id "
        "FROM keys "
        "WHERE status = 'active' "
        "LIMIT 1;"
    );

    if (!statement)
    {
        return false;
    }

    int result = sqlite3_step(statement.get());

    if (result != SQLITE_ROW)
    {
        return false;
    }

    keyId = sqlite3_column_int64(
        statement.get(),
        0
    );

    return true;
}

// ============================================================
// SaveEncryptedRecord
// ============================================================

bool Storage::SaveEncryptedRecord(
    KeyId keyId,
    const CryptoEngine::EncryptedData& encryptedData,
    RecordId& recordId
)
{
    if (db_ == nullptr ||
        keyId <= 0 ||
        encryptedData.cipherText.size() >
            static_cast<std::size_t>(
                std::numeric_limits<int>::max()))
    {
        return false;
    }

    if (!BeginTransaction(db_))
    {
        return false;
    }

    const char* insertSQL = R"SQL(

        INSERT INTO records
        (
            key_id,
            nonce,
            ciphertext,
            tag
        )

        SELECT
            key_id,
            ?,
            ?,
            ?

        FROM keys

        WHERE key_id = ?
        AND status = 'active';

    )SQL";

    Statement statement = Prepare(
        db_,
        insertSQL
    );

    if (!statement)
    {
        RollbackTransaction(db_);
        return false;
    }

    if (!BindBlob(
        statement.get(),
        1,
        encryptedData.nonce.data(),
        encryptedData.nonce.size()
    ))
    {
        RollbackTransaction(db_);
        return false;
    }

    if (!BindBlob(
        statement.get(),
        2,
        encryptedData.cipherText.data(),
        encryptedData.cipherText.size()
    ))
    {
        RollbackTransaction(db_);
        return false;
    }

    if (!BindBlob(
        statement.get(),
        3,
        encryptedData.tag.data(),
        encryptedData.tag.size()
    ))
    {
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_bind_int64(
        statement.get(),
        4,
        keyId
    ) != SQLITE_OK)
    {
        LogDatabaseError(db_, "Bind key ID");
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_step(statement.get()) != SQLITE_DONE)
    {
        LogDatabaseError(db_, "Insert encrypted record");
        RollbackTransaction(db_);
        return false;
    }

    if (sqlite3_changes(db_) != 1)
    {
        RollbackTransaction(db_);
        return false;
    }

    RecordId newRecordId = sqlite3_last_insert_rowid(db_);

    if (!CommitTransaction(db_))
    {
        RollbackTransaction(db_);
        return false;
    }

    recordId = newRecordId;

    return true;
}

// ============================================================
// LoadEncryptedRecord
// ============================================================

bool Storage::LoadEncryptedRecord(
    RecordId recordId,
    KeyId& keyId,
    CryptoEngine::EncryptedData& encryptedData
) const
{
    if (db_ == nullptr || recordId <= 0)
    {
        return false;
    }

    Statement statement = Prepare(
        db_,
        "SELECT key_id, nonce, ciphertext, tag "
        "FROM records "
        "WHERE record_id = ?;"
    );

    if (!statement)
    {
        return false;
    }

    if (sqlite3_bind_int64(
        statement.get(),
        1,
        recordId
    ) != SQLITE_OK)
    {
        LogDatabaseError(db_, "Bind record ID");
        return false;
    }

    int result = sqlite3_step(statement.get());

    if (result != SQLITE_ROW)
    {
        return false;
    }

    if (sqlite3_column_type(statement.get(), 1) != SQLITE_BLOB ||
        sqlite3_column_type(statement.get(), 2) != SQLITE_BLOB ||
        sqlite3_column_type(statement.get(), 3) != SQLITE_BLOB)
    {
        return false;
    }

    int nonceSize = sqlite3_column_bytes(statement.get(), 1);
    int ciphertextSize = sqlite3_column_bytes(statement.get(), 2);
    int tagSize = sqlite3_column_bytes(statement.get(), 3);

    if (nonceSize != static_cast<int>(CryptoEngine::NONCE_SIZE) ||
        tagSize != static_cast<int>(CryptoEngine::TAG_SIZE) ||
        ciphertextSize < 0)
    {
        return false;
    }

    const auto* nonce = static_cast<const unsigned char*>(
        sqlite3_column_blob(statement.get(), 1)
    );

    const auto* ciphertext = static_cast<const unsigned char*>(
        sqlite3_column_blob(statement.get(), 2)
    );

    const auto* tag = static_cast<const unsigned char*>(
        sqlite3_column_blob(statement.get(), 3)
    );

    if (nonce == nullptr || tag == nullptr)
    {
        return false;
    }

    if (ciphertextSize > 0 && ciphertext == nullptr)
    {
        return false;
    }

    CryptoEngine::EncryptedData temporaryData;

    try
    {
        std::copy(
            nonce,
            nonce + CryptoEngine::NONCE_SIZE,
            temporaryData.nonce.begin()
        );

        if (ciphertextSize > 0)
        {
            temporaryData.cipherText.assign(
                ciphertext,
                ciphertext + ciphertextSize
            );
        }

        std::copy(
            tag,
            tag + CryptoEngine::TAG_SIZE,
            temporaryData.tag.begin()
        );
    }
    catch (...)
    {
        if (!temporaryData.cipherText.empty())
        {
            OPENSSL_cleanse(temporaryData.cipherText.data(), temporaryData.cipherText.size());
        }
        return false;
    }

    KeyId temporaryKeyId = sqlite3_column_int64(
        statement.get(),
        0
    );

    if (!encryptedData.cipherText.empty())
    {
        OPENSSL_cleanse(encryptedData.cipherText.data(), encryptedData.cipherText.size());
    }

    encryptedData = std::move(temporaryData);
    keyId = temporaryKeyId;

    return true;
}
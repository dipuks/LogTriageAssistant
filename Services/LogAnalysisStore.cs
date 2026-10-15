using System.Text.Json;
using LogTriageAssistant.Models;
using Microsoft.Data.Sqlite;

namespace LogTriageAssistant.Services;

public class LogAnalysisStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;
    private readonly int _maxSavedAnalyses;

    public LogAnalysisStore(string connectionString, int maxSavedAnalyses = 1000)
    {
        if (maxSavedAnalyses < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxSavedAnalyses), "At least one saved analysis must be retained.");
        }

        _connectionString = connectionString;
        _maxSavedAnalyses = maxSavedAnalyses;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS Analyses (
                Id TEXT PRIMARY KEY,
                OwnerId TEXT NOT NULL DEFAULT 'legacy-admin',
                AnalyzedAt TEXT NOT NULL,
                Severity TEXT NOT NULL,
                FileName TEXT NOT NULL,
                ResultJson TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS Users (
                Id TEXT PRIMARY KEY,
                Username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                PasswordHash TEXT NOT NULL,
                CreatedAt TEXT NOT NULL
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);

        var columnsCommand = connection.CreateCommand();
        columnsCommand.CommandText = "PRAGMA table_info(Analyses);";
        var hasOwnerId = false;
        await using (var reader = await columnsCommand.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                if (reader.GetString(1).Equals("OwnerId", StringComparison.OrdinalIgnoreCase))
                {
                    hasOwnerId = true;
                    break;
                }
            }
        }

        if (!hasOwnerId)
        {
            var migrationCommand = connection.CreateCommand();
            migrationCommand.CommandText =
                "ALTER TABLE Analyses ADD COLUMN OwnerId TEXT NOT NULL DEFAULT 'legacy-admin';";
            await migrationCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        var indexCommand = connection.CreateCommand();
        indexCommand.CommandText = """
            CREATE INDEX IF NOT EXISTS IX_Analyses_Owner_AnalyzedAt
                ON Analyses (OwnerId, AnalyzedAt DESC);
            CREATE INDEX IF NOT EXISTS IX_Analyses_Owner_Severity_AnalyzedAt
                ON Analyses (OwnerId, Severity, AnalyzedAt DESC);
            DELETE FROM Analyses
            WHERE Id IN (
                SELECT Id FROM (
                    SELECT Id, ROW_NUMBER() OVER (
                        PARTITION BY OwnerId ORDER BY AnalyzedAt DESC, rowid DESC
                    ) AS RowNumber
                    FROM Analyses
                )
                WHERE RowNumber > $maxRows
            );
            """;
        indexCommand.Parameters.AddWithValue("$maxRows", _maxSavedAnalyses);
        await indexCommand.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = "SELECT 1;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken)) == 1;
    }

    public async Task<UserAccount?> GetUserByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, Username, PasswordHash
            FROM Users
            WHERE Username = $username COLLATE NOCASE;
            """;
        command.Parameters.AddWithValue("$username", username);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new UserAccount(reader.GetString(0), reader.GetString(1), reader.GetString(2))
            : null;
    }

    public async Task<bool> CreateUserAsync(
        UserAccount user,
        CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Id, Username, PasswordHash, CreatedAt)
            VALUES ($id, $username, $passwordHash, $createdAt);
            """;
        command.Parameters.AddWithValue("$id", user.Id);
        command.Parameters.AddWithValue("$username", user.Username);
        command.Parameters.AddWithValue("$passwordHash", user.PasswordHash);
        command.Parameters.AddWithValue("$createdAt", DateTimeOffset.UtcNow.ToString("O"));
        try
        {
            return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            return false;
        }
    }

    public async Task AddAsync(
        LogAnalysisResult item,
        string ownerId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = """
            INSERT INTO Analyses (Id, OwnerId, AnalyzedAt, Severity, FileName, ResultJson)
            VALUES ($id, $ownerId, $analyzedAt, $severity, $fileName, $resultJson);
            """;
        command.Parameters.AddWithValue("$id", item.Id);
        command.Parameters.AddWithValue("$ownerId", ownerId);
        command.Parameters.AddWithValue("$analyzedAt", item.AnalyzedAt.ToString("O"));
        command.Parameters.AddWithValue("$severity", item.Severity);
        command.Parameters.AddWithValue("$fileName", item.FileName ?? string.Empty);
        command.Parameters.AddWithValue("$resultJson", JsonSerializer.Serialize(item, JsonOptions));
        await command.ExecuteNonQueryAsync(cancellationToken);

        var retentionCommand = connection.CreateCommand();
        retentionCommand.Transaction = (SqliteTransaction)transaction;
        retentionCommand.CommandText = """
            DELETE FROM Analyses
            WHERE Id IN (
                SELECT Id FROM (
                    SELECT Id, ROW_NUMBER() OVER (
                        PARTITION BY OwnerId ORDER BY AnalyzedAt DESC, rowid DESC
                    ) AS RowNumber
                    FROM Analyses
                )
                WHERE RowNumber > $maxRows
            );
            """;
        retentionCommand.Parameters.AddWithValue("$maxRows", _maxSavedAnalyses);
        await retentionCommand.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<LogAnalysisResult>> GetRecentAsync(
        string ownerId,
        int limit = 10,
        CancellationToken cancellationToken = default)
    {
        var boundedLimit = Math.Clamp(limit, 1, 100);
        var results = new List<LogAnalysisResult>(boundedLimit);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ResultJson
            FROM Analyses
            WHERE OwnerId = $ownerId
            ORDER BY AnalyzedAt DESC, rowid DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$ownerId", ownerId);
        command.Parameters.AddWithValue("$limit", boundedLimit);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var result = JsonSerializer.Deserialize<LogAnalysisResult>(reader.GetString(0), JsonOptions);
            if (result is not null)
            {
                results.Add(result);
            }
        }

        return results;
    }

    public async Task<LogAnalysisHistoryPage> GetHistoryAsync(
        string ownerId,
        int page = 1,
        int pageSize = 20,
        string? search = null,
        string? severity = null,
        CancellationToken cancellationToken = default)
    {
        var boundedPageSize = Math.Clamp(pageSize, 1, 50);
        var boundedPage = Math.Max(1, page);
        var searchPattern = string.IsNullOrWhiteSpace(search)
            ? null
            : $"%{search.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_")}%";

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: true);

        var countCommand = connection.CreateCommand();
        countCommand.Transaction = transaction;
        countCommand.CommandText = """
            SELECT COUNT(*)
            FROM Analyses
            WHERE OwnerId = $ownerId
              AND ($severity IS NULL OR Severity = $severity)
              AND ($search IS NULL OR ResultJson LIKE $search ESCAPE '\');
            """;
        countCommand.Parameters.AddWithValue("$ownerId", ownerId);
        countCommand.Parameters.AddWithValue("$severity", (object?)severity ?? DBNull.Value);
        countCommand.Parameters.AddWithValue("$search", (object?)searchPattern ?? DBNull.Value);
        var totalCount = Convert.ToInt32(await countCommand.ExecuteScalarAsync(cancellationToken));
        var totalPages = (int)Math.Ceiling(totalCount / (double)boundedPageSize);
        boundedPage = Math.Min(boundedPage, Math.Max(totalPages, 1));
        var offset = (long)(boundedPage - 1) * boundedPageSize;

        var queryCommand = connection.CreateCommand();
        queryCommand.Transaction = transaction;
        queryCommand.CommandText = """
            SELECT ResultJson
            FROM Analyses
            WHERE OwnerId = $ownerId
              AND ($severity IS NULL OR Severity = $severity)
              AND ($search IS NULL OR ResultJson LIKE $search ESCAPE '\')
            ORDER BY AnalyzedAt DESC, rowid DESC
            LIMIT $pageSize OFFSET $offset;
            """;
        queryCommand.Parameters.AddWithValue("$ownerId", ownerId);
        queryCommand.Parameters.AddWithValue("$severity", (object?)severity ?? DBNull.Value);
        queryCommand.Parameters.AddWithValue("$search", (object?)searchPattern ?? DBNull.Value);
        queryCommand.Parameters.AddWithValue("$pageSize", boundedPageSize);
        queryCommand.Parameters.AddWithValue("$offset", offset);

        var items = new List<LogAnalysisHistoryItem>(boundedPageSize);
        await using (var reader = await queryCommand.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var result = JsonSerializer.Deserialize<LogAnalysisResult>(reader.GetString(0), JsonOptions);
                if (result is not null)
                {
                    items.Add(new LogAnalysisHistoryItem(
                        result.Id,
                        result.AnalyzedAt,
                        result.FileName,
                        result.Severity,
                        result.Summary,
                        result.Confidence));
                }
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return new LogAnalysisHistoryPage(items, totalCount, boundedPage, boundedPageSize, totalPages);
    }

    public async Task<LogAnalysisResult?> GetByIdAsync(
        string id,
        string ownerId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = "SELECT ResultJson FROM Analyses WHERE Id = $id AND OwnerId = $ownerId;";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$ownerId", ownerId);
        var resultJson = await command.ExecuteScalarAsync(cancellationToken);
        return resultJson is string json
            ? JsonSerializer.Deserialize<LogAnalysisResult>(json, JsonOptions)
            : null;
    }

    public async Task<bool> DeleteAsync(
        string id,
        string ownerId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM Analyses WHERE Id = $id AND OwnerId = $ownerId;";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$ownerId", ownerId);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }
}

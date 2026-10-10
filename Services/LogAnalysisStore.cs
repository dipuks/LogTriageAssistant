using System.Text.Json;
using LogTriageAssistant.Models;
using Microsoft.Data.Sqlite;

namespace LogTriageAssistant.Services;

public class LogAnalysisStore(string connectionString)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Analyses (
                Id TEXT PRIMARY KEY,
                AnalyzedAt TEXT NOT NULL,
                Severity TEXT NOT NULL,
                FileName TEXT NOT NULL,
                ResultJson TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_Analyses_AnalyzedAt ON Analyses (AnalyzedAt DESC);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task AddAsync(LogAnalysisResult item, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Analyses (Id, AnalyzedAt, Severity, FileName, ResultJson)
            VALUES ($id, $analyzedAt, $severity, $fileName, $resultJson);
            """;
        command.Parameters.AddWithValue("$id", item.Id);
        command.Parameters.AddWithValue("$analyzedAt", item.AnalyzedAt.ToString("O"));
        command.Parameters.AddWithValue("$severity", item.Severity);
        command.Parameters.AddWithValue("$fileName", item.FileName ?? string.Empty);
        command.Parameters.AddWithValue("$resultJson", JsonSerializer.Serialize(item, JsonOptions));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<LogAnalysisResult>> GetRecentAsync(
        int limit = 10,
        CancellationToken cancellationToken = default)
    {
        var boundedLimit = Math.Clamp(limit, 1, 100);
        var results = new List<LogAnalysisResult>(boundedLimit);

        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ResultJson
            FROM Analyses
            ORDER BY AnalyzedAt DESC
            LIMIT $limit;
            """;
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
}

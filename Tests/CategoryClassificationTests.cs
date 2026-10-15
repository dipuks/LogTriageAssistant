using System.Text.Json;
using LogTriageAssistant.Services;
using Xunit;

namespace LogTriageAssistant.Tests;

/// <summary>Token-aware categories: identifiers, numbers and timestamps must not create categories; genuine signals still do.</summary>
public class CategoryClassificationTests
{
    private readonly LogAnalyzerService _service = new();

    [Theory]
    [InlineData("ERROR Test 'Case 1' failed: Simulated Timeout failure. resultId=7f4031aa-0c2b-4e5f-9a1d-503e2a1b4031", "Network")]
    [InlineData("ERROR job failed after 4031 ms", "General")]
    [InlineData("ERROR order 5021 failed", "General")]
    [InlineData("ERROR request 401 of 900 failed", "General")]
    [InlineData("2026-10-14T14:01:40.403Z ERROR worker crashed", "Runtime / Crash")]
    [InlineData("ERROR cleaning room 4 failed", "General")]
    [InlineData("ERROR resetting tenant 42 failed", "General")]
    [InlineData("ERROR build 503.2 artifact upload failed", "Build / Deploy")]
    public void Identifiers_numbers_and_timestamps_do_not_create_categories(string line, string expected)
    {
        Assert.Equal(expected, Assert.Single(_service.Analyze(line).Findings).Category);
    }

    [Theory]
    [InlineData("ERROR HTTP 401 Unauthorized calling /api/orders", "Authentication")]
    [InlineData("ERROR status=403 access denied", "Authentication")]
    [InlineData("ERROR 401 Unauthorized", "Authentication")]
    [InlineData("ERROR upstream returned (503)", "Dependency")]
    [InlineData("""{"level":"Error","message":"call failed","statusCode":502}""", "Dependency")]
    [InlineData("ERROR HTTP 503 upstream service unavailable", "Dependency")]
    [InlineData("FATAL OOMKilled container restarted", "Memory / Resource")]
    [InlineData("ERROR SqlException: deadlock victim", "Database")]
    [InlineData("ERROR SQLite Error 5: database is locked", "Database")]
    [InlineData("ERROR Npgsql.NpgsqlException: connection lost", "Database")]
    [InlineData("ERROR System.NullReferenceException: Object reference not set", "Runtime / Crash")]
    [InlineData("ERROR TLS handshake failed", "Network")]
    [InlineData("ERROR missing settings value for Payments", "Configuration")]
    [InlineData("WARN request timeouts increasing", "Network")]
    public void Genuine_status_codes_and_keywords_still_classify(string line, string expected)
    {
        Assert.Equal(expected, Assert.Single(_service.Analyze(line).Findings).Category);
    }

    [Fact]
    public void Cq_pulse_documents_with_ids_are_classified_without_spurious_categories()
    {
        // The document shape CQ Pulse submits: JSON lines with GUID ids and durations. Before the token-aware rules,
        // digits inside ids made 4–7% of lines "Authentication" or "Dependency".
        var random = new Random(7);
        Guid NextGuid() { var bytes = new byte[16]; random.NextBytes(bytes); return new Guid(bytes); }
        var categories = new[] { "ApiError", "Timeout", "UiElement", "DataValidation", "Environment" };
        var lines = Enumerable.Range(0, 500).Select(i => JsonSerializer.Serialize(new
        {
            timestamp = new DateTimeOffset(2026, 10, 14, 13, 30, 0, TimeSpan.Zero).AddMilliseconds(i * 7),
            level = "ERROR",
            message = $"Test 'Checkout case {i % 40}' failed: Simulated {categories[i % 5]} failure.",
            category = categories[i % 5],
            runId = NextGuid(), resultId = NextGuid(), testCaseId = NextGuid(), durationMs = random.Next(0, 9999)
        })).ToList();

        var result = _service.Analyze(string.Join('\n', lines));

        Assert.Equal(500, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.Equal(
            categories[(f.LineNumber - 1) % 5] == "Timeout" ? "Network" : "General", f.Category));
    }
}

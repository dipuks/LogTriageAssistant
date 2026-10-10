using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace LogTriageAssistant.Tests;

public class LogAnalysisApiTests : IClassFixture<LogAnalysisApiFactory>
{
    private readonly HttpClient _client;

    public LogAnalysisApiTests(LogAnalysisApiFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Health_ReturnsHealthyStatus()
    {
        var response = await _client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonDocument>();
        Assert.NotNull(body);
        Assert.Equal("healthy", body.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Analyze_RejectsEmptyLogText()
    {
        var response = await _client.PostAsJsonAsync("/api/analyze", new { logText = " " });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Analyze_SavesResultAndReturnsItInRecentHistory()
    {
        var response = await _client.PostAsJsonAsync("/api/analyze", new
        {
            logText = "ERROR Failed to connect to database",
            fileName = "integration-test.log"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var analysis = await response.Content.ReadFromJsonAsync<AnalysisResponse>();
        Assert.NotNull(analysis);
        Assert.Equal("Database", analysis.Statistics.TopCategory);

        var recent = await _client.GetFromJsonAsync<List<AnalysisResponse>>("/api/recent?limit=10");

        Assert.NotNull(recent);
        Assert.Contains(recent, item => item.Id == analysis.Id);
    }

    [Fact]
    public async Task AnalyzeFile_AcceptsMultipartUpload()
    {
        using var form = new MultipartFormDataContent();
        using var content = new StringContent("FATAL out of memory");
        form.Add(content, "file", "upload.log");

        var response = await _client.PostAsync("/api/analyze-file", form);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var analysis = await response.Content.ReadFromJsonAsync<AnalysisResponse>();
        Assert.NotNull(analysis);
        Assert.Equal("CRITICAL", analysis.Severity);
        Assert.Equal("upload.log", analysis.FileName);
    }

    private sealed class AnalysisResponse
    {
        public string Id { get; set; } = string.Empty;
        public string? FileName { get; set; }
        public string Severity { get; set; } = string.Empty;
        public AnalysisStatistics Statistics { get; set; } = new();
    }

    private sealed class AnalysisStatistics
    {
        public string TopCategory { get; set; } = string.Empty;
    }
}

public sealed class LogAnalysisApiFactory : WebApplicationFactory<Program>
{
    private readonly string _databasePath = Path.Combine(
        Path.GetTempPath(),
        $"logtriage-tests-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Storage:DatabasePath"] = _databasePath
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing)
        {
            return;
        }

        foreach (var path in new[] { _databasePath, $"{_databasePath}-shm", $"{_databasePath}-wal" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}

using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using LogTriageAssistant.Services;
using Xunit;

namespace LogTriageAssistant.Tests;

public class LogAnalysisApiTests : IClassFixture<LogAnalysisApiFactory>
{
    private readonly HttpClient _client;

    public LogAnalysisApiTests(LogAnalysisApiFactory factory)
    {
        _client = factory.CreateAuthenticatedClient();
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
    public async Task UnauthenticatedRequestsCannotReadSavedAnalysesOrAppShell()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        var apiResponse = await client.GetAsync("/api/history");
        var appResponse = await client.GetAsync("/");
        var loginResponse = await client.GetAsync("/login.html");

        Assert.Equal(HttpStatusCode.Unauthorized, apiResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, appResponse.StatusCode);
        Assert.Equal("/login.html", appResponse.Headers.Location?.OriginalString);
        Assert.True(
            loginResponse.StatusCode == HttpStatusCode.OK,
            $"Login page returned {(int)loginResponse.StatusCode} with redirect {loginResponse.Headers.Location}.");
    }

    [Fact]
    public async Task Login_RejectsInvalidCredentialsWithGenericResponse()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateUnauthenticatedClient();
        await factory.AddCsrfTokenAsync(client);

        var response = await client.PostAsJsonAsync("/api/auth/login", new
        {
            username = LogAnalysisApiFactory.TestUsername,
            password = "incorrect-password"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(LogAnalysisApiFactory.TestUsername, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Login_IssuesHttpOnlySecureStrictSessionCookie()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateUnauthenticatedClient();
        await factory.AddCsrfTokenAsync(client);

        var response = await client.PostAsJsonAsync("/api/auth/login", new
        {
            username = LogAnalysisApiFactory.TestUsername,
            password = LogAnalysisApiFactory.TestPassword
        });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookie = Assert.Single(
            response.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith("__Host-LogTriage.Auth=", StringComparison.Ordinal));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Registration_CreatesAccountAndSignsUserIn()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateUnauthenticatedClient();
        await factory.AddCsrfTokenAsync(client);

        var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            username = "new.user",
            password = "strong-registration-password",
            confirmPassword = "strong-registration-password"
        });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var authCookie = response.Headers.GetValues("Set-Cookie")
            .Single(value => value.StartsWith("__Host-LogTriage.Auth=", StringComparison.Ordinal))
            .Split(';', 2)[0];
        client.DefaultRequestHeaders.Add("Cookie", authCookie);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/status")).StatusCode);
    }

    [Fact]
    public async Task Registration_ValidatesCredentialsAndRejectsDuplicateUsernames()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateUnauthenticatedClient();
        await factory.AddCsrfTokenAsync(client);

        var weakPassword = await client.PostAsJsonAsync("/api/auth/register", new
        {
            username = "new-user",
            password = "short",
            confirmPassword = "short"
        });
        Assert.Equal(HttpStatusCode.BadRequest, weakPassword.StatusCode);

        var mismatch = await client.PostAsJsonAsync("/api/auth/register", new
        {
            username = "new-user",
            password = "strong-registration-password",
            confirmPassword = "different-registration-password"
        });
        Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);

        var created = await client.PostAsJsonAsync("/api/auth/register", new
        {
            username = "new-user",
            password = "strong-registration-password",
            confirmPassword = "strong-registration-password"
        });
        Assert.Equal(HttpStatusCode.NoContent, created.StatusCode);

        using var secondClient = factory.CreateUnauthenticatedClient();
        await factory.AddCsrfTokenAsync(secondClient);
        var duplicate = await secondClient.PostAsJsonAsync("/api/auth/register", new
        {
            username = "NEW-USER",
            password = "strong-registration-password",
            confirmPassword = "strong-registration-password"
        });
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }

    [Fact]
    public async Task Analyses_ArePrivateBetweenRegisteredAccountsAndLegacyAdmin()
    {
        using var factory = new LogAnalysisApiFactory();
        using var adminClient = factory.CreateAuthenticatedClient();
        using var userClient = await factory.CreateRegisteredClientAsync("private-user");

        var adminAnalysis = await CreateAnalysisAsync(adminClient, "ERROR database", "admin-only-marker.log");
        var userAnalysis = await CreateAnalysisAsync(userClient, "ERROR database", "user-only-marker.log");

        var adminHistory = await adminClient.GetStringAsync("/api/history");
        var userHistory = await userClient.GetStringAsync("/api/history");
        Assert.Contains("admin-only-marker", adminHistory, StringComparison.Ordinal);
        Assert.DoesNotContain("user-only-marker", adminHistory, StringComparison.Ordinal);
        Assert.Contains("user-only-marker", userHistory, StringComparison.Ordinal);
        Assert.DoesNotContain("admin-only-marker", userHistory, StringComparison.Ordinal);

        Assert.Equal(
            HttpStatusCode.NotFound,
            (await userClient.GetAsync($"/api/recent/{adminAnalysis.Id}")).StatusCode);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await userClient.DeleteAsync($"/api/recent/{adminAnalysis.Id}")).StatusCode);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await adminClient.GetAsync($"/api/recent/{userAnalysis.Id}")).StatusCode);
    }

    [Fact]
    public async Task ExistingAnalysisDatabase_MigratesOldRecordsToLegacyAdmin()
    {
        using var factory = new LogAnalysisApiFactory();
        await factory.CreateLegacyAnalysisSchemaAsync();
        using var adminClient = factory.CreateAuthenticatedClient();

        var recent = await adminClient.GetFromJsonAsync<List<AnalysisResponse>>("/api/recent?limit=10");

        Assert.NotNull(recent);
        Assert.Contains(recent, analysis => analysis.Id == "existing-legacy-analysis");
    }

    [Fact]
    public async Task ProductionMode_RejectsAuthenticationOverPlainHttp()
    {
        using var factory = new LogAnalysisApiFactory { UseProductionEnvironment = true };
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost"),
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/api/auth/csrf");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AuthenticatedSessionCanAccessApiAndLogout()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateAuthenticatedClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/status")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/history")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/auth/logout", null)).StatusCode);
        client.DefaultRequestHeaders.Remove("Cookie");

        var response = await client.GetAsync("/api/history");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ApiWriteRequiresValidCsrfToken()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateAuthenticatedClient();
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");

        var response = await client.PostAsJsonAsync("/api/analyze", new { logText = "ERROR test" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Readiness_ReturnsReadyWhenDatabaseIsAvailable()
    {
        var response = await _client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task HomePage_IncludesBrowserSecurityHeaders()
    {
        var response = await _client.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            response.Headers.GetValues("Content-Security-Policy"),
            value => value.Contains("default-src 'self'", StringComparison.Ordinal));
        Assert.Contains("nosniff", response.Headers.GetValues("X-Content-Type-Options"));
        Assert.Contains("DENY", response.Headers.GetValues("X-Frame-Options"));
        Assert.Contains("no-referrer", response.Headers.GetValues("Referrer-Policy"));
    }

    [Fact]
    public async Task Analyze_RejectsEmptyLogText()
    {
        var response = await _client.PostAsJsonAsync("/api/analyze", new { logText = " " });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AiAnalysis_RejectsUnsupportedProvider()
    {
        var response = await _client.PostAsJsonAsync("/api/ai/analyze", new
        {
            logText = "ERROR database unavailable",
            provider = "unsupported"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Analyze_RejectsLogContentOverTwoMegabytes()
    {
        var response = await _client.PostAsJsonAsync("/api/analyze", new
        {
            logText = new string('x', 2 * 1024 * 1024 + 1)
        });

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
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
    public async Task History_ReturnsFilteredPaginatedSummariesAndAnalysisCanBeReopened()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateAuthenticatedClient();
        await CreateAnalysisAsync(client, "ERROR database page-marker-one");
        await CreateAnalysisAsync(client, "WARN retrying page-marker-two");
        var third = await CreateAnalysisAsync(client, "ERROR database page-marker-three");

        var page = await client.GetFromJsonAsync<HistoryPageResponse>(
            "/api/history?page=1&pageSize=1&search=page-marker&severity=HIGH");

        Assert.NotNull(page);
        Assert.Equal(2, page.TotalCount);
        Assert.Equal(2, page.TotalPages);
        Assert.Equal(third.Id, Assert.Single(page.Items).Id);

        var reopened = await client.GetFromJsonAsync<AnalysisResponse>($"/api/recent/{third.Id}");

        Assert.NotNull(reopened);
        Assert.Equal(third.Id, reopened.Id);
    }

    [Fact]
    public async Task History_RejectsSearchLongerThanOneHundredCharacters()
    {
        var response = await _client.GetAsync($"/api/history?search={new string('x', 101)}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task History_RejectsUnsupportedSeverity()
    {
        var response = await _client.GetAsync("/api/history?severity=UNKNOWN");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task History_TreatsSearchWildcardsAsLiteralText()
    {
        using var factory = new LogAnalysisApiFactory();
        using var client = factory.CreateAuthenticatedClient();
        await CreateAnalysisAsync(client, "ERROR database pageXmarker");

        var page = await client.GetFromJsonAsync<HistoryPageResponse>(
            "/api/history?search=page_marker");

        Assert.NotNull(page);
        Assert.Equal(0, page.TotalCount);
        Assert.Empty(page.Items);
    }

    [Fact]
    public async Task Analyze_PreservesLeadingBlankLinesForFindingLineNumbers()
    {
        var response = await _client.PostAsJsonAsync("/api/analyze", new
        {
            logText = "\nERROR Failed to connect to database"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonDocument>();
        Assert.NotNull(body);
        Assert.Equal(2, body.RootElement.GetProperty("findings")[0].GetProperty("lineNumber").GetInt32());
    }

    [Fact]
    public async Task Analyze_RedactsSensitiveValuesBeforeReturningAndPersistingFindings()
    {
        const string password = "password=hunter2";
        const string token = "Bearer abc.def.ghi";
        const string email = "person@example.com";
        var response = await _client.PostAsJsonAsync("/api/analyze", new
        {
            logText = $"ERROR database failed {password} {token} contact {email}"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var resultJson = await response.Content.ReadAsStringAsync();
        Assert.Contains("[REDACTED]", resultJson);
        Assert.Contains("[REDACTED_EMAIL]", resultJson);
        Assert.DoesNotContain("hunter2", resultJson);
        Assert.DoesNotContain("abc.def.ghi", resultJson);
        Assert.DoesNotContain(email, resultJson);

        var recentJson = await _client.GetStringAsync("/api/recent?limit=100");
        Assert.DoesNotContain("hunter2", recentJson);
        Assert.DoesNotContain("abc.def.ghi", recentJson);
        Assert.DoesNotContain(email, recentJson);
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

    [Fact]
    public async Task AnalyzeFile_RejectsUploadOverTwoMegabytes()
    {
        using var form = new MultipartFormDataContent();
        using var content = new StringContent(new string('x', 2 * 1024 * 1024 + 1));
        form.Add(content, "file", "oversized.log");

        var response = await _client.PostAsync("/api/analyze-file", form);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task AnalyzeFile_RejectsMalformedMultipartData()
    {
        using var content = new StringContent("not a multipart body");
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("multipart/form-data");

        var response = await _client.PostAsync("/api/analyze-file", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DeleteRecent_RemovesSavedAnalysis()
    {
        var createResponse = await _client.PostAsJsonAsync("/api/analyze", new
        {
            logText = "ERROR Failed to connect to database",
            fileName = "delete-test.log"
        });
        var analysis = await createResponse.Content.ReadFromJsonAsync<AnalysisResponse>();
        Assert.NotNull(analysis);

        var deleteResponse = await _client.DeleteAsync($"/api/recent/{analysis.Id}");

        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);
        var recent = await _client.GetFromJsonAsync<List<AnalysisResponse>>("/api/recent?limit=100");
        Assert.NotNull(recent);
        Assert.DoesNotContain(recent, item => item.Id == analysis.Id);
    }

    [Fact]
    public async Task DeleteRecent_ReturnsNotFoundForUnknownAnalysis()
    {
        var response = await _client.DeleteAsync("/api/recent/does-not-exist");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Analyze_EnforcesConfiguredSavedHistoryLimit()
    {
        using var factory = new LogAnalysisApiFactory { MaxSavedAnalyses = 2 };
        using var client = factory.CreateAuthenticatedClient();
        var ids = new List<string>();

        for (var index = 0; index < 3; index++)
        {
            var response = await client.PostAsJsonAsync("/api/analyze", new
            {
                logText = $"ERROR database failure {index}"
            });
            var analysis = await response.Content.ReadFromJsonAsync<AnalysisResponse>();
            Assert.NotNull(analysis);
            ids.Add(analysis.Id);
        }

        var recent = await client.GetFromJsonAsync<List<AnalysisResponse>>("/api/recent?limit=100");

        Assert.NotNull(recent);
        Assert.True(File.Exists(factory.DatabasePath), $"Expected test database at {factory.DatabasePath}.");
        Assert.Equal(2, recent.Count);
        Assert.DoesNotContain(recent, item => item.Id == ids[0]);
    }

    private sealed class AnalysisResponse
    {
        public string Id { get; set; } = string.Empty;
        public string? FileName { get; set; }
        public string Severity { get; set; } = string.Empty;
        public AnalysisStatistics Statistics { get; set; } = new();
    }

    private static async Task<AnalysisResponse> CreateAnalysisAsync(
        HttpClient client,
        string logText,
        string? fileName = null)
    {
        var response = await client.PostAsJsonAsync("/api/analyze", new { logText, fileName });
        Assert.True(
            response.StatusCode == HttpStatusCode.OK,
            $"Analyze returned {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
        var analysis = await response.Content.ReadFromJsonAsync<AnalysisResponse>();
        Assert.NotNull(analysis);
        return analysis;
    }

    private sealed class HistoryPageResponse
    {
        public List<HistoryItemResponse> Items { get; set; } = new();
        public int TotalCount { get; set; }
        public int TotalPages { get; set; }
    }

    private sealed class HistoryItemResponse
    {
        public string Id { get; set; } = string.Empty;
    }

    private sealed class AnalysisStatistics
    {
        public string TopCategory { get; set; } = string.Empty;
    }
}

public sealed class LogAnalysisApiFactory : WebApplicationFactory<Program>
{
    public const string TestUsername = "test-admin";
    public const string TestPassword = "test-password-123!";
    private static readonly string TestPasswordHash = new PasswordHasher<object>()
        .HashPassword(new object(), TestPassword);
    private readonly string _databasePath = Path.Combine(
        Path.GetTempPath(),
        $"logtriage-tests-{Guid.NewGuid():N}.db");
    public int MaxSavedAnalyses { get; set; } = 1000;
    public bool UseProductionEnvironment { get; set; }
    public string DatabasePath => _databasePath;

    public HttpClient CreateAuthenticatedClient()
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        var csrfResponse = client.GetAsync("/api/auth/csrf").GetAwaiter().GetResult();
        csrfResponse.EnsureSuccessStatusCode();
        var csrfToken = csrfResponse.Content.ReadFromJsonAsync<CsrfResponse>().GetAwaiter().GetResult();
        var csrfCookie = GetCookie(csrfResponse, "LogTriage.Csrf");
        client.DefaultRequestHeaders.Add("Cookie", csrfCookie);
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken!.Token);

        var loginResponse = client.PostAsJsonAsync("/api/auth/login", new
        {
            username = TestUsername,
            password = TestPassword
        }).GetAwaiter().GetResult();
        loginResponse.EnsureSuccessStatusCode();
        var authCookie = GetCookie(loginResponse, "__Host-LogTriage.Auth");
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", $"{csrfCookie}; {authCookie}");

        var authenticatedCsrfResponse = client.GetAsync("/api/auth/csrf").GetAwaiter().GetResult();
        authenticatedCsrfResponse.EnsureSuccessStatusCode();
        var authenticatedCsrf = authenticatedCsrfResponse.Content
            .ReadFromJsonAsync<CsrfResponse>()
            .GetAwaiter()
            .GetResult();
        csrfCookie = TryGetCookie(authenticatedCsrfResponse, "LogTriage.Csrf") ?? csrfCookie;
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", $"{csrfCookie}; {authCookie}");
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", authenticatedCsrf!.Token);
        return client;
    }

    public HttpClient CreateUnauthenticatedClient()
    {
        return CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
    }

    public async Task<string> AddCsrfTokenAsync(HttpClient client)
    {
        var csrfResponse = await client.GetAsync("/api/auth/csrf");
        csrfResponse.EnsureSuccessStatusCode();
        var csrfToken = await csrfResponse.Content.ReadFromJsonAsync<CsrfResponse>();
        client.DefaultRequestHeaders.Add("Cookie", GetCookie(csrfResponse, "LogTriage.Csrf"));
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken!.Token);
        return csrfToken.Token;
    }

    public async Task<HttpClient> CreateRegisteredClientAsync(string username)
    {
        var client = CreateUnauthenticatedClient();
        await AddCsrfTokenAsync(client);
        const string password = "registered-test-password-123!";
        var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            username,
            password,
            confirmPassword = password
        });
        response.EnsureSuccessStatusCode();
        var existingCookies = string.Join("; ", client.DefaultRequestHeaders.GetValues("Cookie"));
        var authCookie = GetCookie(response, "__Host-LogTriage.Auth");
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", $"{existingCookies}; {authCookie}");
        var csrfResponse = await client.GetAsync("/api/auth/csrf");
        csrfResponse.EnsureSuccessStatusCode();
        var csrf = await csrfResponse.Content.ReadFromJsonAsync<CsrfResponse>();
        var refreshedCsrfCookie = TryGetCookie(csrfResponse, "LogTriage.Csrf")
            ?? existingCookies.Split(';', StringSplitOptions.TrimEntries)
                .First(cookie => cookie.StartsWith("LogTriage.Csrf=", StringComparison.Ordinal));
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", $"{refreshedCsrfCookie}; {authCookie}");
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf!.Token);
        return client;
    }

    public async Task CreateLegacyAnalysisSchemaAsync()
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE Analyses (
                Id TEXT PRIMARY KEY,
                AnalyzedAt TEXT NOT NULL,
                Severity TEXT NOT NULL,
                FileName TEXT NOT NULL,
                ResultJson TEXT NOT NULL
            );
            INSERT INTO Analyses (Id, AnalyzedAt, Severity, FileName, ResultJson)
            VALUES (
                'existing-legacy-analysis',
                '2026-01-01T00:00:00.0000000+00:00',
                'HIGH',
                'legacy.log',
                '{"id":"existing-legacy-analysis","fileName":"legacy.log","summary":"Existing legacy analysis","severity":"HIGH"}'
            );
            """;
        await command.ExecuteNonQueryAsync();
    }

    private static string GetCookie(HttpResponseMessage response, string name)
    {
        return TryGetCookie(response, name)
            ?? throw new InvalidOperationException($"The response did not set the {name} cookie.");
    }

    private static string? TryGetCookie(HttpResponseMessage response, string name)
    {
        var cookie = response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders)
            ? setCookieHeaders.First(value => value.StartsWith($"{name}=", StringComparison.Ordinal))
            : null;
        return cookie?.Split(';', 2)[0];
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        if (UseProductionEnvironment)
        {
            builder.UseEnvironment("Production");
        }

        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<LogTriageAssistant.Services.AdminAuthOptions>(options =>
            {
                options.Username = TestUsername;
                options.PasswordHash = TestPasswordHash;
            });
            services.RemoveAll<LogAnalysisStore>();
            var connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = _databasePath,
                Mode = SqliteOpenMode.ReadWriteCreate
            }.ToString();
            services.AddSingleton(new LogAnalysisStore(connectionString, MaxSavedAnalyses));
        });
    }

    private sealed class CsrfResponse
    {
        public string Token { get; set; } = string.Empty;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing)
        {
            return;
        }

        SqliteConnection.ClearAllPools();
        foreach (var path in new[] { _databasePath, $"{_databasePath}-shm", $"{_databasePath}-wal" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}

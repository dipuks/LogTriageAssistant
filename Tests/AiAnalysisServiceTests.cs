using System.Net;
using System.Text;
using LogTriageAssistant.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace LogTriageAssistant.Tests;

public class AiAnalysisServiceTests
{
    [Fact]
    public async Task AnalyzeAsync_RedactsLogContentBeforeSendingItToLocalOllama()
    {
        var handler = new StubHttpMessageHandler(_ => JsonResponse(
            """{"message":{"content":"{\"summary\":\"Database connection failed\",\"likelyCause\":\"Unavailable database\",\"impact\":\"Requests may fail\",\"evidence\":[\"connection refused\"],\"nextSteps\":[\"Check database health\"],\"caveat\":\"Verify with metrics.\"}"}}"""));
        var service = CreateService(handler, new Dictionary<string, string?>
        {
            ["Ai:Ollama:BaseUrl"] = "http://localhost:11434",
            ["Ai:Ollama:Model"] = "test-model"
        });

        var result = await service.AnalyzeAsync(
            "ollama",
            "ERROR database password=hunter2 Authorization: Bearer abc.def.ghi contact person@example.com ghp_1234567890123456789012345678901234",
            CancellationToken.None);

        Assert.Equal("Database connection failed", result.Summary);
        Assert.Equal("test-model", result.Model);
        Assert.DoesNotContain("hunter2", handler.RequestContent, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("abc.def.ghi", handler.RequestContent, StringComparison.Ordinal);
        Assert.DoesNotContain("person@example.com", handler.RequestContent, StringComparison.Ordinal);
        Assert.DoesNotContain("ghp_1234567890123456789012345678901234", handler.RequestContent, StringComparison.Ordinal);
        Assert.Contains("untrusted evidence", handler.RequestContent, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/api/chat", handler.RequestUri?.AbsolutePath);
    }

    [Fact]
    public async Task AnalyzeAsync_UsesServerSideCredentialForHostedProvider()
    {
        var handler = new StubHttpMessageHandler(_ => JsonResponse(
            """{"choices":[{"message":{"content":"{\"summary\":\"A service failed\",\"likelyCause\":\"Upstream timeout\",\"impact\":\"Requests are delayed\",\"evidence\":[\"timeout\"],\"nextSteps\":[\"Check upstream health\"],\"caveat\":\"Confirm duration.\"}"}}]}"""));
        var service = CreateService(handler, new Dictionary<string, string?>
        {
            ["Ai:OpenAICompatible:BaseUrl"] = "https://ai.example.test/v1",
            ["Ai:OpenAICompatible:Model"] = "test-hosted-model",
            ["Ai:OpenAICompatible:ApiKey"] = "server-only-secret"
        });

        var result = await service.AnalyzeAsync("hosted", "ERROR upstream timeout", CancellationToken.None);

        Assert.Equal("A service failed", result.Summary);
        Assert.Equal("/v1/chat/completions", handler.RequestUri?.AbsolutePath);
        Assert.Equal("Bearer", handler.AuthorizationScheme);
        Assert.Equal("server-only-secret", handler.AuthorizationParameter);
    }

    [Fact]
    public async Task AnalyzeAsync_RejectsUnconfiguredHostedProviderWithoutSendingRequest()
    {
        var handler = new StubHttpMessageHandler(_ => JsonResponse("{}"));
        var service = CreateService(handler, new Dictionary<string, string?>());

        await Assert.ThrowsAsync<AiProviderNotConfiguredException>(
            () => service.AnalyzeAsync("hosted", "ERROR upstream timeout", CancellationToken.None));
        Assert.Null(handler.RequestUri);
    }

    [Fact]
    public void GetProviders_RequiresHttpsForHostedApiCredentials()
    {
        var service = CreateService(new StubHttpMessageHandler(_ => JsonResponse("{}")), new Dictionary<string, string?>
        {
            ["Ai:OpenAICompatible:BaseUrl"] = "http://ai.example.test/v1",
            ["Ai:OpenAICompatible:Model"] = "test-model",
            ["Ai:OpenAICompatible:ApiKey"] = "server-only-secret"
        });

        var hosted = Assert.Single(service.GetProviders(), provider => provider.Id == "hosted");

        Assert.False(hosted.Configured);
    }

    [Fact]
    public async Task AnalyzeAsync_RejectsMalformedModelOutput()
    {
        var handler = new StubHttpMessageHandler(_ => JsonResponse(
            """{"message":{"content":"not JSON"}}"""));
        var service = CreateService(handler, new Dictionary<string, string?>());

        await Assert.ThrowsAsync<AiProviderException>(
            () => service.AnalyzeAsync("ollama", "ERROR database", CancellationToken.None));
    }

    [Fact]
    public async Task AnalyzeAsync_RedactsPrivateKeysBeforeSendingAndCredentialsInTheReturnedBrief()
    {
        var brief = System.Text.Json.JsonSerializer.Serialize(new
        {
            summary = "Calls failed with Authorization: Basic dXNlcjpzM2NyM3RQYXNz",
            likelyCause = "Rotated key AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==;",
            impact = $"Payments using {RedactionTests.StripeLiveKey} failed",
            evidence = new[] { "Cookie: session=sess0123456789abcdef" },
            nextSteps = new[] { "Rotate https://x.test/f?sig=AbCdEf1234567890xyzSIG" },
            caveat = "None"
        });
        var handler = new StubHttpMessageHandler(_ => JsonResponse(
            System.Text.Json.JsonSerializer.Serialize(new { message = new { content = brief } })));
        var service = CreateService(handler, new Dictionary<string, string?>
        {
            ["Ai:Ollama:BaseUrl"] = "http://localhost:11434",
            ["Ai:Ollama:Model"] = "test-model"
        });

        var result = await service.AnalyzeAsync(
            "ollama",
            "ERROR tls failed\n-----BEGIN PRIVATE KEY-----\nMIIEvAIBADAKEYBODYONE\nKEYBODYTWOxyz==\n-----END PRIVATE KEY-----\nERROR retry failed",
            CancellationToken.None);

        Assert.DoesNotContain("KEYBODY", handler.RequestContent, StringComparison.Ordinal);
        var returned = string.Join(" ", new[] { result.Summary, result.LikelyCause, result.Impact, result.Caveat }
            .Concat(result.Evidence).Concat(result.NextSteps));
        foreach (var secret in new[] { "dXNlcjpzM2NyM3RQYXNz", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==", RedactionTests.StripeLiveKey, "sess0123456789abcdef", "AbCdEf1234567890xyzSIG" })
            Assert.DoesNotContain(secret, returned, StringComparison.Ordinal);
    }

    private static AiAnalysisService CreateService(
        StubHttpMessageHandler handler,
        Dictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();
        return new AiAnalysisService(new StubHttpClientFactory(handler), configuration);
    }

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class StubHttpMessageHandler(
        Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public string RequestContent { get; private set; } = string.Empty;
        public Uri? RequestUri { get; private set; }
        public string? AuthorizationScheme { get; private set; }
        public string? AuthorizationParameter { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            AuthorizationScheme = request.Headers.Authorization?.Scheme;
            AuthorizationParameter = request.Headers.Authorization?.Parameter;
            RequestContent = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return respond(request);
        }
    }
}

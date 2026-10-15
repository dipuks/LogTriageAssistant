using System.Text.Json;
using LogTriageAssistant.Services;
using Xunit;

namespace LogTriageAssistant.Tests;

/// <summary>Credential redaction in stored findings, file names and AI-bound text.</summary>
public class RedactionTests
{
    private readonly LogAnalyzerService _service = new();

    // Vendor-format test credentials are fake and assembled at runtime so secret scanners do not flag this file.
    internal static readonly string StripeLiveKey = "sk_" + "live_51H8abcdEFGHijklMNOPqrst";
    internal static readonly string StripeTestKey = "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc";
    internal static readonly string GitHubToken = "github_" + "pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz";
    internal static readonly string OpenAiStyleKey = "sk-" + "proj-abcdefghijklmnopqrstuvwxyz123456";

    public static TheoryData<string, string, string> CredentialLines => new()
    {
        // line, secret that must disappear, context that must survive
        { "ERROR upstream call failed Authorization: Basic dXNlcjpzM2NyM3RQYXNz status=500", "dXNlcjpzM2NyM3RQYXNz", "status=500" },
        { "error proxy rejected request authorization=basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA==", "proxy rejected request" },
        { "ERROR client sent Basic YWRtaW46aHVudGVyMg== to upstream", "YWRtaW46aHVudGVyMg==", "to upstream" },
        { "ERROR blob failed DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==;EndpointSuffix=core.windows.net", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==", "AccountName=acct" },
        { "ERROR bus failed Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abcDEF123456789xyzABC=", "abcDEF123456789xyzABC=", "SharedAccessKeyName=RootManageSharedAccessKey" },
        { "ERROR charge failed using " + StripeLiveKey, StripeLiveKey, "charge failed" },
        { "ERROR charge failed with key " + StripeTestKey, StripeTestKey, "charge failed" },
        { "ERROR download failed https://acct.blob.core.windows.net/c/f?sv=2022-11-02&sig=AbCdEf1234567890xyzSIG&se=2026-10-15", "AbCdEf1234567890xyzSIG", "sv=2022-11-02" },
        { "ERROR download failed https://files.example.test/x?Signature=QWERTYuiop123456&Expires=99", "QWERTYuiop123456", "Expires=99" },
        { "ERROR request failed Cookie: session=sess0123456789abcdef; theme=dark", "sess0123456789abcdef", "Cookie: session=" },
        { "ERROR response Set-Cookie: auth=abcSECRET123xyz; Path=/; HttpOnly", "abcSECRET123xyz", "Set-Cookie: auth=" },
        { "ERROR login failed PASSWORD : hunter2xyz user=bob", "hunter2xyz", "user=bob" },
        { """{"level":"Error","message":"login failed","Password" : "s3cr3tJson"}""", "s3cr3tJson", "login failed" },
        { "ERROR call failed X-API-KEY: abcd1234efgh5678", "abcd1234efgh5678", "call failed" },
        { "ERROR call failed api key: abcd1234efgh5678", "abcd1234efgh5678", "call failed" },
        { "ERROR 401 authorization: bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX3Rlc3Q", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX3Rlc3Q", "401" },
        { "ERROR 401 Authorization: Digest username=\"bob\", realm=\"api\", nonce=\"abc123\", response=\"6629fae49393a05397450978507c4ef1\"", "6629fae49393a05397450978507c4ef1", "401" },
        { "ERROR db failed Server=db;User Id=sa;Password=Sup3rS3cret!;", "Sup3rS3cret!", "User Id=sa" },
        { "ERROR queue failed amqps://svc:pa55word@broker.internal:5671/vhost", "pa55word", "broker.internal" },
        { "ERROR clone failed " + GitHubToken, GitHubToken, "clone failed" },
        { "ERROR completion failed " + OpenAiStyleKey, OpenAiStyleKey, "completion failed" },
        { "ERROR s3 failed aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "s3 failed" },
    };

    [Theory]
    [MemberData(nameof(CredentialLines))]
    public void Secrets_are_redacted_from_findings_and_ai_bound_text_while_context_remains(string line, string secret, string context)
    {
        var finding = Assert.Single(_service.Analyze(line).Findings);
        var external = LogAnalyzerService.RedactSensitiveDataForExternalUse(line);

        Assert.DoesNotContain(secret, finding.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, finding.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, external, StringComparison.Ordinal);
        Assert.Contains(context, finding.Message, StringComparison.Ordinal);
        Assert.Contains("REDACTED", external, StringComparison.Ordinal);
    }

    [Fact]
    public void Multiline_private_keys_are_redacted_without_shifting_line_numbers()
    {
        var log = string.Join('\n',
            "INFO service starting",
            "ERROR key load failed",
            "-----BEGIN RSA PRIVATE KEY-----",
            "Proc-Type: 4,ENCRYPTED",
            "MIIEowIBAAKCAQEA7xPRIVATEBODYLINE1abc",
            "QWxhZGRpbjpvcGVu+err/c2VzYW1lLINE2==",
            "-----END RSA PRIVATE KEY-----",
            "ERROR database connection refused") + "\n";

        var result = _service.Analyze(log);
        var external = LogAnalyzerService.RedactSensitiveDataForExternalUse(log);

        Assert.Equal(8, result.Statistics.TotalLines);
        Assert.Equal([2, 8], result.Findings.Select(f => f.LineNumber));
        Assert.Equal("Database", result.Findings[1].Category);
        foreach (var body in new[] { "PRIVATEBODYLINE1", "c2VzYW1lLINE2", "ENCRYPTED" })
        {
            Assert.DoesNotContain(result.Findings, f => f.Message.Contains(body, StringComparison.Ordinal));
            Assert.DoesNotContain(body, external, StringComparison.Ordinal);
        }
        Assert.Equal(log.Split('\n').Length, external.Split('\n').Length);
        Assert.Contains("[REDACTED_PRIVATE_KEY]", external, StringComparison.Ordinal);
    }

    [Fact]
    public void Private_keys_inside_json_strings_and_truncated_keys_are_redacted()
    {
        const string json = """{"level":"Error","message":"key load failed","key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANJSONBODY123\nAnotherJSONBODYline==\n-----END PRIVATE KEY-----"}""";
        const string truncated = "ERROR tls setup failed\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEITRUNCATEDBODY1\nTRUNCATEDBODY2xyz";

        var jsonFinding = Assert.Single(_service.Analyze(json).Findings);
        var jsonExternal = LogAnalyzerService.RedactSensitiveDataForExternalUse(json);
        var truncatedExternal = LogAnalyzerService.RedactSensitiveDataForExternalUse(truncated);

        Assert.DoesNotContain("JSONBODY", jsonFinding.Message + jsonFinding.Evidence + jsonExternal, StringComparison.Ordinal);
        Assert.DoesNotContain("TRUNCATEDBODY", truncatedExternal, StringComparison.Ordinal);
        Assert.Contains("tls setup failed", truncatedExternal, StringComparison.Ordinal);
    }

    [Fact]
    public void File_names_are_redacted()
    {
        var result = _service.Analyze("ERROR failed", "export?token=abcdef123456.log");

        Assert.DoesNotContain("abcdef123456", result.FileName, StringComparison.Ordinal);
    }
}

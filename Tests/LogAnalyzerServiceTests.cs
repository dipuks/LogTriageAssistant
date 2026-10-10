using LogTriageAssistant.Services;
using Xunit;

namespace LogTriageAssistant.Tests;

public class LogAnalyzerServiceTests
{
    private readonly LogAnalyzerService _service = new();

    [Fact]
    public void Analyze_ClassifiesDatabaseFailureAndPreservesLineNumber()
    {
        var result = _service.Analyze("INFO service started\nERROR Failed to connect to database", "app.log");

        var finding = Assert.Single(result.Findings);
        Assert.Equal(2, finding.LineNumber);
        Assert.Equal("Database", finding.Category);
        Assert.Equal("HIGH", finding.Severity);
        Assert.Equal("app.log", result.FileName);
        Assert.Equal("Database", result.Statistics.TopCategory);
    }

    [Fact]
    public void Analyze_UsesHighestFindingSeverityForOverallSeverity()
    {
        var result = _service.Analyze("WARN retrying network request\nFATAL out of memory");

        Assert.Equal("CRITICAL", result.Severity);
        Assert.Equal(2, result.Findings.Count);
        Assert.Contains(result.Findings, finding => finding.Severity == "MEDIUM");
        Assert.Contains(result.Findings, finding => finding.Severity == "CRITICAL");
    }

    [Fact]
    public void Analyze_PrioritizesCategoryWithTheStrongestEvidence()
    {
        var result = _service.Analyze("ERROR HTTP 503 upstream service unavailable");

        var finding = Assert.Single(result.Findings);
        Assert.Equal("Dependency", finding.Category);
    }

    [Theory]
    [InlineData("ERROR request failed", "HIGH")]
    [InlineData("WARN request is degraded", "MEDIUM")]
    public void Analyze_ReportsGenericSeveritySignalsAsGeneralFindings(string line, string expectedSeverity)
    {
        var finding = Assert.Single(_service.Analyze(line).Findings);

        Assert.Equal("General", finding.Category);
        Assert.Equal(expectedSeverity, finding.Severity);
    }

    [Theory]
    [InlineData("ERROR Redis cache unavailable", "Cache")]
    [InlineData("ERROR malformed JSON unexpected token", "Data / Serialization")]
    [InlineData("WARN high CPU queue backlog", "Performance")]
    public void Analyze_DetectsAdditionalOperationalCategories(string line, string expectedCategory)
    {
        var finding = Assert.Single(_service.Analyze(line).Findings);

        Assert.Equal(expectedCategory, finding.Category);
    }

    [Fact]
    public void Analyze_IgnoresBlankLinesAndUnmatchedContent()
    {
        var result = _service.Analyze("service started\n\nrequest completed");

        Assert.Empty(result.Findings);
        Assert.Equal(0, result.Statistics.ErrorLikeLines);
        Assert.Equal("General", result.Statistics.TopCategory);
        Assert.Equal("INFO", result.Severity);
    }

    [Fact]
    public void Analyze_ClipsLongFindingMessages()
    {
        var longLine = $"ERROR database {new string('x', 300)}";

        var finding = Assert.Single(_service.Analyze(longLine).Findings);

        Assert.Equal(220, finding.Message.Length);
        Assert.EndsWith("...", finding.Message);
        Assert.Equal(finding.Message, finding.Evidence);
    }

    [Fact]
    public void Analyze_ReturnsNoFindingsForNullInput()
    {
        var result = _service.Analyze(null);

        Assert.Empty(result.Findings);
        Assert.Equal(0, result.Statistics.ErrorLikeLines);
    }

    [Fact]
    public void Analyze_LimitsReturnedFindingsButEvaluatesSeverityAcrossAllLines()
    {
        var text = string.Join(
            Environment.NewLine,
            Enumerable.Repeat("ERROR database problem", 500).Append("FATAL out of memory"));

        var result = _service.Analyze(text);

        Assert.Equal(500, result.Findings.Count);
        Assert.True(result.FindingsTruncated);
        Assert.Equal(501, result.Statistics.ErrorLikeLines);
        Assert.Equal("CRITICAL", result.Severity);
        Assert.DoesNotContain(result.Findings, finding => finding.Severity == "CRITICAL");
        Assert.Contains("Only the first 500 findings", result.Summary);
    }
}

namespace LogTriageAssistant.Models;

public class LogAnalysisRequest
{
    public string? LogText { get; set; }
    public string? FileName { get; set; }
}

public sealed class AiAnalysisRequest
{
    public string? LogText { get; set; }
    public string? Provider { get; set; }
}

public sealed class AiAnalysisResult
{
    public string Provider { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string LikelyCause { get; set; } = string.Empty;
    public string Impact { get; set; } = string.Empty;
    public List<string> Evidence { get; set; } = [];
    public List<string> NextSteps { get; set; } = [];
    public string Caveat { get; set; } = string.Empty;
}

public sealed record AiProviderStatus(string Id, string Name, bool Configured, string Privacy);

public class LogAnalysisResult
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? FileName { get; set; }
    public DateTimeOffset AnalyzedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Summary { get; set; } = string.Empty;
    public string Severity { get; set; } = "INFO";
    public double Confidence { get; set; }
    public bool FindingsTruncated { get; set; }
    public LogStatistics Statistics { get; set; } = new();
    public List<LogFinding> Findings { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
}

public class LogStatistics
{
    public int TotalLines { get; set; }
    public int ErrorLikeLines { get; set; }
    public int UniqueCategories { get; set; }
    public string TopCategory { get; set; } = "General";
}

public class LogFinding
{
    public int LineNumber { get; set; }
    public int EndLineNumber { get; set; }
    public string? Timestamp { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Severity { get; set; } = "INFO";
    public string Category { get; set; } = "General";
    public string Evidence { get; set; } = string.Empty;
    public string Suggestion { get; set; } = string.Empty;
}

public sealed record LogAnalysisHistoryItem(
    string Id,
    DateTimeOffset AnalyzedAt,
    string? FileName,
    string Severity,
    string Summary,
    double Confidence);

public sealed record LogAnalysisHistoryPage(
    IReadOnlyList<LogAnalysisHistoryItem> Items,
    int TotalCount,
    int Page,
    int PageSize,
    int TotalPages);

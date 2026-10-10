namespace LogTriageAssistant.Models;

public class LogAnalysisRequest
{
    public string? LogText { get; set; }
    public string? FileName { get; set; }
}

public class LogAnalysisResult
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? FileName { get; set; }
    public DateTimeOffset AnalyzedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Summary { get; set; } = string.Empty;
    public string Severity { get; set; } = "INFO";
    public double Confidence { get; set; }
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
    public string Message { get; set; } = string.Empty;
    public string Severity { get; set; } = "INFO";
    public string Category { get; set; } = "General";
    public string Evidence { get; set; } = string.Empty;
    public string Suggestion { get; set; } = string.Empty;
}

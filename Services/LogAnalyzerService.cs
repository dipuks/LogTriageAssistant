using System.Text.RegularExpressions;
using LogTriageAssistant.Models;

namespace LogTriageAssistant.Services;

public class LogAnalyzerService
{
    private static readonly Dictionary<string, string[]> CategoryPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Authentication"] = ["unauthorized", "forbidden", "access denied", "401", "403", "login failed", "token expired"],
        ["Database"] = ["sql", "database", "dbconn", "connection timeout", "deadlock", "timeout while waiting", "ora-", "mysql", "postgres"],
        ["Network"] = ["socket", "dns", "connection refused", "network", "handshake", "tls", "http 502", "http 503", "timeout"],
        ["Dependency"] = ["service unavailable", "upstream", "api call failed", "external dependency", "503", "502", "remote service"],
        ["Configuration"] = ["missing config", "appsettings", "environment variable", "configuration", "null reference", "setting"],
        ["Memory / Resource"] = ["out of memory", "oom", "resource exhausted", "too many open files", "memory leak", "stack overflow"],
        ["Runtime / Crash"] = ["exception", "fatal", "panic", "crash", "segmentation fault", "stacktrace", "thread abort"],
        ["Build / Deploy"] = ["build failed", "publish failed", "assembly not found", "dll not found", "deployment", "artifact"],
    };

    private static readonly Dictionary<string, string> RecommendationMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Authentication"] = "Verify credential rotation, token expiry handling, and authorization rules before retrying the request.",
        ["Database"] = "Check connection strings, retry logic, query timeouts, and database health before making schema changes.",
        ["Network"] = "Inspect the downstream service, DNS, firewall rules, and retry configuration for transient network issues.",
        ["Dependency"] = "Validate upstream service availability, API contracts, and failover behavior for the dependency chain.",
        ["Configuration"] = "Review configuration values, environment variables, and startup settings for missing or stale values.",
        ["Memory / Resource"] = "Watch process memory, thread counts, and file handle limits; investigate leak or resource exhaustion patterns.",
        ["Runtime / Crash"] = "Capture stack traces, reproduce the failure, and inspect recent code paths tied to the exception.",
        ["Build / Deploy"] = "Confirm deployment artifacts, package versions, and environment-specific release configuration are aligned.",
        ["General"] = "Review surrounding log context and verify the service version, environment, and recent deployments.",
    };

    public LogAnalysisResult Analyze(string? rawText, string? fileName = null)
    {
        var text = rawText ?? string.Empty;
        var lines = text.Split('\n', StringSplitOptions.None);

        var findings = new List<LogFinding>();
        var categories = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var errorLikeLines = 0;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var category = DetectCategory(line);
            if (category is null)
            {
                continue;
            }

            errorLikeLines++;
            categories[category] = categories.TryGetValue(category, out var count) ? count + 1 : 1;

            findings.Add(new LogFinding
            {
                LineNumber = i + 1,
                Message = TrimLine(line),
                Severity = EvaluateSeverity(line),
                Category = category,
                Evidence = TrimLine(line),
                Suggestion = RecommendationMap.TryGetValue(category, out var rec) ? rec : RecommendationMap["General"]
            });
        }

        var topCategory = categories.Count > 0 ? categories.OrderByDescending(x => x.Value).First().Key : "General";
        var highestSeverity = findings.Count > 0 ? findings.Max(x => SeverityWeight(x.Severity)) : 0;
        var severity = ToSeverityString(highestSeverity);

        var summary = BuildSummary(topCategory, findings.Count, errorLikeLines, severity);
        var recommendations = GetRecommendations(categories.Keys.ToList(), topCategory);
        var confidence = CalculateConfidence(findings.Count, categories.Count, errorLikeLines, lines.Length);

        return new LogAnalysisResult
        {
            FileName = fileName,
            Summary = summary,
            Severity = severity,
            Confidence = confidence,
            Findings = findings,
            Recommendations = recommendations,
            Statistics = new LogStatistics
            {
                TotalLines = lines.Length,
                ErrorLikeLines = errorLikeLines,
                UniqueCategories = categories.Count,
                TopCategory = topCategory,
            }
        };
    }

    private static string? DetectCategory(string line)
    {
        foreach (var pair in CategoryPatterns)
        {
            var category = pair.Key;
            var patterns = pair.Value;
            if (patterns.Any(pattern => line.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
            {
                return category;
            }
        }

        return null;
    }

    private static string TrimLine(string line)
    {
        var cleaned = line.Trim();
        return cleaned.Length > 220 ? cleaned[..217] + "..." : cleaned;
    }

    private static string EvaluateSeverity(string line)
    {
        if (Regex.IsMatch(line, "(?i)(fatal|panic|segmentation fault|out of memory|stack overflow|critical)", RegexOptions.CultureInvariant))
        {
            return "CRITICAL";
        }

        if (Regex.IsMatch(line, "(?i)(error|exception|failed|timeout|unauthorized|forbidden|access denied|deadlock)", RegexOptions.CultureInvariant))
        {
            return "HIGH";
        }

        if (Regex.IsMatch(line, "(?i)(warn|warning|retry|degraded)", RegexOptions.CultureInvariant))
        {
            return "MEDIUM";
        }

        return "INFO";
    }

    private static int SeverityWeight(string severity)
    {
        return severity switch
        {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            _ => 1
        };
    }

    private static string ToSeverityString(int weight)
    {
        return weight switch
        {
            >= 4 => "CRITICAL",
            >= 3 => "HIGH",
            >= 2 => "MEDIUM",
            _ => "INFO"
        };
    }

    private static string BuildSummary(string topCategory, int findingCount, int errorLikeLines, string severity)
    {
        if (findingCount == 0)
        {
            return "No significant failure signatures were detected in the supplied log content.";
        }

        return $"Detected {findingCount} actionable findings with the strongest signal in {topCategory}. Overall severity is {severity}, and {errorLikeLines} log lines match error-like patterns.";
    }

    private static List<string> GetRecommendations(IReadOnlyCollection<string> categories, string topCategory)
    {
        if (categories.Count == 0)
        {
            return ["Inspect the surrounding context for a recent deploy, config change, or dependency issue."];
        }

        var recommendations = categories
            .OrderByDescending(category => category.Equals(topCategory, StringComparison.OrdinalIgnoreCase))
            .Select(category => RecommendationMap.TryGetValue(category, out var rec) ? rec : RecommendationMap["General"])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(3)
            .ToList();

        if (recommendations.Count == 0)
        {
            recommendations.Add(RecommendationMap["General"]);
        }

        return recommendations;
    }

    private static double CalculateConfidence(int findingsCount, int categoryCount, int errorLikeLines, int totalLines)
    {
        if (totalLines == 0)
        {
            return 0;
        }

        var evidenceStrength = Math.Min(1.0, (double)errorLikeLines / Math.Max(1, totalLines));
        var categoryStrength = Math.Min(1.0, (double)categoryCount / 6.0);
        var findingStrength = Math.Min(1.0, (double)findingsCount / 10.0);

        return Math.Round((evidenceStrength * 0.55 + categoryStrength * 0.2 + findingStrength * 0.25) * 100, 1);
    }
}

using System.Text.Json;
using System.Text.RegularExpressions;
using LogTriageAssistant.Models;

namespace LogTriageAssistant.Services;

public class LogAnalyzerService
{
    private const int MaximumFindings = 500;
    private const int MaximumFileNameLength = 128;
    private static readonly Regex SensitiveAssignmentPattern = new(
        """(?i)(["']?(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?(?:token|key)|refresh[_-]?token|private[_-]?key|connection[_-]?string|token|authorization)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex BearerTokenPattern = new(
        """(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex TokenPattern = new(
        """\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex UrlCredentialPattern = new(
        """(?i)\b((?:https?|ftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/)[^/\s:@]+:[^/\s@]+@""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex PrivateKeyPattern = new(
        """-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex EmailPattern = new(
        """(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, string[]> CategoryPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Authentication"] = ["unauthorized", "forbidden", "access denied", "401", "403", "login failed", "token expired"],
        ["Database"] = ["sql", "database", "dbconn", "connection timeout", "deadlock", "timeout while waiting", "ora-", "mysql", "postgres"],
        ["Network"] = ["socket", "dns", "connection refused", "network", "handshake", "tls", "http 502", "http 503", "timeout"],
        ["Dependency"] = ["service unavailable", "upstream", "api call failed", "external dependency", "503", "502", "remote service"],
        ["Configuration"] = ["missing config", "appsettings", "environment variable", "configuration", "null reference", "setting"],
        ["Performance"] = ["slow query", "high latency", "response time", "high cpu", "cpu usage", "throttling", "rate limit", "queue backlog", "throughput"],
        ["Cache"] = ["cache miss", "cache timeout", "redis", "memcached", "cache unavailable", "eviction storm"],
        ["Data / Serialization"] = ["serialization", "deserialization", "invalid json", "malformed json", "parse error", "schema validation", "unexpected token"],
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
        ["Performance"] = "Compare latency, CPU, query time, and queue depth against normal baselines; identify the slowest dependency or operation.",
        ["Cache"] = "Check cache availability, hit rate, eviction behavior, and key/TTL changes; confirm the backing store can handle fallback traffic.",
        ["Data / Serialization"] = "Validate the payload against the expected schema and inspect recent producer, serializer, or contract changes.",
        ["Memory / Resource"] = "Watch process memory, thread counts, and file handle limits; investigate leak or resource exhaustion patterns.",
        ["Runtime / Crash"] = "Capture stack traces, reproduce the failure, and inspect recent code paths tied to the exception.",
        ["Build / Deploy"] = "Confirm deployment artifacts, package versions, and environment-specific release configuration are aligned.",
        ["General"] = "Review surrounding log context and verify the service version, environment, and recent deployments.",
    };

    public LogAnalysisResult Analyze(string? rawText, string? fileName = null)
    {
        var text = rawText ?? string.Empty;
        var lines = text.Length == 0 ? Array.Empty<string>() : text.Split('\n', StringSplitOptions.None);
        if (lines.Length > 0 && lines[^1].Length == 0)
        {
            lines = lines[..^1];
        }

        var logEvents = ParseLogEvents(lines);
        var findings = new List<LogFinding>();
        var categories = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var errorLikeLines = 0;
        var highestSeverity = 0;
        var findingsTruncated = false;

        foreach (var logEvent in logEvents)
        {
            if (string.IsNullOrWhiteSpace(logEvent.SearchText))
            {
                continue;
            }

            var category = DetectCategory(logEvent.SearchText);
            if (category is null && EvaluateSeverity(logEvent.SearchText) != "INFO")
            {
                category = "General";
            }

            if (category is null)
            {
                continue;
            }

            errorLikeLines++;
            categories[category] = categories.TryGetValue(category, out var count) ? count + 1 : 1;
            var lineSeverity = EvaluateSeverity(logEvent.SearchText);
            highestSeverity = Math.Max(highestSeverity, SeverityWeight(lineSeverity));

            if (findings.Count == MaximumFindings)
            {
                findingsTruncated = true;
                continue;
            }

            var excerpt = TrimLine(logEvent.DisplayText);
            findings.Add(new LogFinding
            {
                LineNumber = logEvent.LineNumber,
                EndLineNumber = logEvent.EndLineNumber,
                Timestamp = logEvent.Timestamp,
                Message = excerpt,
                Severity = lineSeverity,
                Category = category,
                Evidence = excerpt,
                Suggestion = RecommendationMap.TryGetValue(category, out var rec) ? rec : RecommendationMap["General"]
            });
        }

        var topCategory = categories.Count > 0 ? categories.OrderByDescending(x => x.Value).First().Key : "General";
        var overallSeverity = ToSeverityString(highestSeverity);

        var summary = BuildSummary(topCategory, errorLikeLines, findings.Count, overallSeverity, findingsTruncated);
        var recommendations = GetRecommendations(categories.Keys.ToList(), topCategory);
        var confidence = CalculateConfidence(errorLikeLines, categories.Count, errorLikeLines, lines.Length);

        return new LogAnalysisResult
        {
            FileName = NormalizeFileName(fileName),
            Summary = summary,
            Severity = overallSeverity,
            Confidence = confidence,
            FindingsTruncated = findingsTruncated,
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
        return CategoryPatterns
            .Select((pair, order) => new
            {
                Category = pair.Key,
                Order = order,
                MatchCount = pair.Value.Count(pattern => line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            })
            .Where(match => match.MatchCount > 0)
            .OrderByDescending(match => match.MatchCount)
            .ThenBy(match => match.Order)
            .Select(match => match.Category)
            .FirstOrDefault();
    }

    private static List<ParsedLogEvent> ParseLogEvents(string[] lines)
    {
        var events = new List<ParsedLogEvent>();
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (IsStackTraceContinuation(line))
            {
                if (events.Count == 0 || !events[^1].IsActionable)
                {
                    continue;
                }

                var previous = events[^1];
                previous.DisplayText += Environment.NewLine + line.Trim();
                previous.SearchText += " " + line.Trim();
                previous.EndLineNumber = i + 1;
                continue;
            }

            var parsed = ParseStructuredLine(line);
            events.Add(new ParsedLogEvent
            {
                LineNumber = i + 1,
                EndLineNumber = i + 1,
                DisplayText = parsed.Message,
                SearchText = parsed.SearchText,
                Timestamp = parsed.Timestamp,
                IsActionable = DetectCategory(parsed.SearchText) is not null || EvaluateSeverity(parsed.SearchText) != "INFO"
            });
        }

        return events;
    }

    private static ParsedStructuredLine ParseStructuredLine(string line)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return new ParsedStructuredLine(line, line, null);
            }

            var root = document.RootElement;
            var message = ReadFirstString(root, "message", "msg", "renderedmessage", "@m", "body");
            var level = ReadFirstString(root, "level", "severity", "loglevel", "@l");
            var timestamp = ReadFirstString(root, "timestamp", "@t", "time", "datetime");
            var exception = ReadFirstString(root, "exception", "stacktrace", "stack_trace", "error");
            var display = string.IsNullOrWhiteSpace(message) ? line : message;
            var search = string.Join(' ', new[] { line, level, message, exception }.Where(value => !string.IsNullOrWhiteSpace(value)));
            return new ParsedStructuredLine(display, search, timestamp);
        }
        catch (JsonException)
        {
            return new ParsedStructuredLine(line, line, null);
        }
    }

    private static string? ReadFirstString(JsonElement root, params string[] names)
    {
        foreach (var property in root.EnumerateObject())
        {
            if (!names.Contains(property.Name, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            return property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Number => property.Value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => property.Value.GetRawText()
            };
        }

        return null;
    }

    private static bool IsStackTraceContinuation(string line)
    {
        return Regex.IsMatch(
            line,
            @"^\s*(?:at\s+\S+|--- End of stack trace|Caused by:|Inner Exception:|Traceback \(most recent call last\)|File ""[^""]+"", line \d+|\.\.\.\s+\d+\s+more)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private sealed class ParsedLogEvent
    {
        public int LineNumber { get; set; }
        public int EndLineNumber { get; set; }
        public string DisplayText { get; set; } = string.Empty;
        public string SearchText { get; set; } = string.Empty;
        public string? Timestamp { get; set; }
        public bool IsActionable { get; set; }
    }

    private sealed record ParsedStructuredLine(string Message, string SearchText, string? Timestamp);

    private static string TrimLine(string line)
    {
        var cleaned = RedactSensitiveData(line.Trim());
        return cleaned.Length > 220 ? cleaned[..217] + "..." : cleaned;
    }

    private static string RedactSensitiveData(string text)
    {
        var redacted = SensitiveAssignmentPattern.Replace(text, "$1[REDACTED]");
        redacted = BearerTokenPattern.Replace(redacted, "Bearer [REDACTED]");
        redacted = TokenPattern.Replace(redacted, "[REDACTED_TOKEN]");
        redacted = UrlCredentialPattern.Replace(redacted, "$1[REDACTED]@");
        redacted = PrivateKeyPattern.Replace(redacted, "[REDACTED_PRIVATE_KEY]");
        return EmailPattern.Replace(redacted, "[REDACTED_EMAIL]");
    }

    private static string? NormalizeFileName(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return fileName;
        }

        var safeName = fileName.Replace('\\', '/').Split('/').Last().Trim();
        safeName = new string(safeName.Where(character => !char.IsControl(character)).ToArray());
        return safeName.Length > MaximumFileNameLength ? safeName[..MaximumFileNameLength] : safeName;
    }

    private static string EvaluateSeverity(string line)
    {
        if (Regex.IsMatch(line, "(?i)(fatal|panic|segmentation fault|out of memory|stack overflow|critical|\\bcrit\\b)", RegexOptions.CultureInvariant))
        {
            return "CRITICAL";
        }

        if (Regex.IsMatch(line, "(?i)(error|\\berr\\b|exception|failed|timeout|unauthorized|forbidden|access denied|deadlock)", RegexOptions.CultureInvariant))
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

    private static string BuildSummary(
        string topCategory,
        int findingCount,
        int returnedFindingCount,
        string severity,
        bool findingsTruncated)
    {
        if (findingCount == 0)
        {
            return "No significant failure signatures were detected in the supplied log content.";
        }

        var truncationNote = findingsTruncated ? $" Only the first {returnedFindingCount} findings are included." : string.Empty;
        return $"Detected {findingCount} actionable findings with the strongest signal in {topCategory}. Overall severity is {severity}.{truncationNote}";
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

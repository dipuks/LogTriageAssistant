using System.Text.Json;
using System.Text.RegularExpressions;
using LogTriageAssistant.Models;

namespace LogTriageAssistant.Services;

public class LogAnalyzerService
{
    private const int MaximumFindings = 500;
    private const int MaximumFileNameLength = 128;
    private const string RedactedPrivateKey = "[REDACTED_PRIVATE_KEY]";

    // Redaction runs on every finding (stored and returned), on file names, and on the whole log before it is sent to
    // an AI provider. Secret values are replaced; key names, schemes and the surrounding log text are kept.

    // A PEM private key: BEGIN line, optional PEM headers, base64 body lines and END line, separated by real newlines
    // or by escaped "\n" inside JSON strings. A truncated block is redacted up to its last base64 line.
    private static readonly Regex PrivateKeyBlockPattern = new(
        """-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:(?:\r?\n|\\r\\n|\\n)[ \t]*(?:(?:Proc-Type|DEK-Info|Comment):[^\r\n\\]*|[A-Za-z0-9+/=]+(?=\r?\n|\\r\\n|\\n|$|"|-----)))*(?:(?:\r?\n|\\r\\n|\\n)[ \t]*-----END [A-Z0-9 ]*PRIVATE KEY-----)?""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    // key=value / key: value / "key":"value" for secret-bearing names. An authorization scheme (Basic, Bearer, ...) is
    // kept and only the credential after it is replaced.
    private static readonly Regex SensitiveAssignmentPattern = new(
        """(?i)(["']?(?:password|passwd|passphrase|pwd|secret|client[_-]?secret|api[_\s-]?key|access[_-]?(?:token|key)|refresh[_-]?token|id[_-]?token|auth[_-]?token|private[_-]?key|connection[_-]?string|account[_-]?key|shared[_-]?access[_-]?(?:key|signature)|sas[_-]?token|credentials?|token|(?:proxy[_-]?)?authorization)["']?\s*[:=]\s*)((?:basic|bearer|negotiate|ntlm|token|sharedkey(?:lite)?)\s+)?(?:"[^"]*"|'[^']*'|[^\s,;]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex BearerTokenPattern = new(
        """(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    // "Basic <base64>" anywhere (header values, client logs). Requires a digit or base64 punctuation so ordinary words
    // after "basic" are left alone.
    private static readonly Regex BasicCredentialPattern = new(
        """(?i)\bBasic\s+(?=[A-Za-z0-9+/]*[0-9+/=])[A-Za-z0-9+/]{8,}={0,2}""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    // Digest credentials carry several parameters (username, response hash, nonce); everything after the scheme goes.
    private static readonly Regex DigestCredentialPattern = new(
        """(?i)\bDigest\s+(?:[a-z]+=(?:"[^"\r\n]*"|[^\s,;"]+)\s*,?\s*)+""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex CookieHeaderPattern = new(
        """(?i)\b((?:set-)?cookie["']?\s*[:=]\s*["']?)([^\r\n"']+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex CookieValuePattern = new(
        """(^|;\s*|,\s*)([^=;,\s]+)=([^;,]*)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    // Secrets passed in URL query strings: SAS signatures, OAuth tokens and codes, passwords and keys.
    private static readonly Regex QuerySecretPattern = new(
        """(?i)([?&](?:sig|signature|sas|token|access_token|id_token|refresh_token|code|password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|key|auth)=)[^&\s#"'<>]+""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    // Self-identifying vendor credentials that are secret even without a label.
    private static readonly Regex TokenPattern = new(
        """\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}|whsec_[A-Za-z0-9]{16,}|sk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex UrlCredentialPattern = new(
        """(?i)\b((?:https?|ftp|amqps?|redis|postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/)[^/\s:@]+:[^/\s@]+@""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex EmailPattern = new(
        """(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, string[]> CategoryPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Authentication"] = ["unauthorized", "forbidden", "access denied", "401", "403", "login failed", "token expired"],
        ["Database"] = ["sql", "sqlite", "npgsql", "database", "dbconn", "connection timeout", "deadlock", "timeout while waiting", "ora-", "mysql", "postgres"],
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

    /// <summary>
    /// Each keyword is matched as a token, not as an arbitrary substring, so identifiers, numbers and timestamps do not
    /// produce categories ("4031 ms" or a GUID containing "403" is not Authentication, "room" is not Memory):
    /// <list type="bullet">
    /// <item>HTTP status codes (401, 403, 502, 503) count only in a status context: "HTTP 503", "status=401",
    /// "returned (403)", "statusCode":502, or followed by their reason phrase ("401 Unauthorized").</item>
    /// <item>Words and phrases must start at a word boundary (a camelCase or acronym boundary also counts, so
    /// "SqlException" and "NullReferenceException" still match). Short keywords (four characters or fewer) must also end
    /// at a word boundary; longer keywords may be followed by a suffix ("settings", "timeouts").</item>
    /// </list>
    /// A cheap case-insensitive <c>Contains</c> runs first; the boundary regex only runs on candidate lines.
    /// </summary>
    private static readonly (string Category, (string Probe, Regex Rule)[] Keywords)[] CategoryRules = CategoryPatterns
        .Select(pair => (pair.Key, pair.Value.Select(keyword => (keyword.Split(' ')[0], BuildKeywordRule(keyword))).ToArray()))
        .ToArray();

    private static Regex BuildKeywordRule(string keyword)
    {
        if (keyword.All(char.IsAsciiDigit))
        {
            return new Regex(
                $$"""(?i)\b(?:http(?:/[0-9.]+)?|status(?:[ _-]?code)?|response(?:[ _-]?code)?|returned|code|error)\W{0,4}{{keyword}}(?![\w.])|(?<![\w.:/-]){{keyword}}\s+(?:unauthori[sz]ed|forbidden|bad\s+gateway|service\s+unavailable|gateway\s+time-?out)""",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);
        }

        var body = string.Join(@"[\s_-]+", keyword.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(Regex.Escape));
        var start = @"(?:(?<![A-Za-z])|(?<=[a-z])(?=[A-Z]))";
        var end = char.IsAsciiDigit(keyword[^1]) ? @"(?![0-9])"
            : keyword.Length <= 4 ? @"(?![a-z])"
            : string.Empty;
        return new Regex($"{start}(?i:{body}){end}", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    }

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
        // Private-key blocks span lines; redact them before splitting (line count and numbers are preserved).
        var text = RedactPrivateKeyBlocks(rawText ?? string.Empty);
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

            // Lines without stack-trace continuations reuse the values computed while parsing.
            var hasContinuation = logEvent.EndLineNumber != logEvent.LineNumber;
            var category = hasContinuation ? DetectCategory(logEvent.SearchText) : logEvent.Category;
            var lineSeverity = hasContinuation ? EvaluateSeverity(logEvent.SearchText) : logEvent.Severity;
            if (category is null && lineSeverity != "INFO")
            {
                category = "General";
            }

            if (category is null)
            {
                continue;
            }

            errorLikeLines++;
            categories[category] = categories.TryGetValue(category, out var count) ? count + 1 : 1;
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

    /// <summary>The category with the most matching keywords; ties go to the category listed first.</summary>
    private static string? DetectCategory(string line)
    {
        string? best = null;
        var bestCount = 0;
        foreach (var (category, keywords) in CategoryRules)
        {
            var count = 0;
            foreach (var (probe, rule) in keywords)
            {
                if (line.Contains(probe, StringComparison.OrdinalIgnoreCase) && rule.IsMatch(line))
                {
                    count++;
                }
            }

            if (count > bestCount)
            {
                best = category;
                bestCount = count;
            }
        }

        return best;
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
            var category = DetectCategory(parsed.SearchText);
            var severity = EvaluateSeverity(parsed.SearchText);
            events.Add(new ParsedLogEvent
            {
                LineNumber = i + 1,
                EndLineNumber = i + 1,
                DisplayText = parsed.Message,
                SearchText = parsed.SearchText,
                Timestamp = parsed.Timestamp,
                Category = category,
                Severity = severity,
                IsActionable = category is not null || severity != "INFO"
            });
        }

        return events;
    }

    private static ParsedStructuredLine ParseStructuredLine(string line)
    {
        // Only lines that start with '{' can be JSON objects; skipping the parser avoids a thrown exception per
        // plain-text line, which dominated the cost of analysing plain-text logs.
        var trimmed = line.AsSpan().TrimStart();
        if (trimmed.IsEmpty || trimmed[0] != '{')
        {
            return new ParsedStructuredLine(line, line, null);
        }

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
        public string? Category { get; set; }
        public string Severity { get; set; } = "INFO";
        public bool IsActionable { get; set; }
    }

    private sealed record ParsedStructuredLine(string Message, string SearchText, string? Timestamp);

    public static string RedactSensitiveData(string text) =>
        RedactSensitiveDataForExternalUse(text);

    public static string RedactSensitiveDataForExternalUse(string text)
    {
        var bearerSafe = BearerTokenPattern.Replace(RedactPrivateKeyBlocks(text), "******");
        return RedactSensitiveDataCore(bearerSafe);
    }

    private static string TrimLine(string line)
    {
        var cleaned = RedactSensitiveDataCore(line.Trim());
        return cleaned.Length > 220 ? cleaned[..217] + "..." : cleaned;
    }

    private static string RedactSensitiveDataCore(string text)
    {
        var redacted = RedactPrivateKeyBlocks(text);
        redacted = DigestCredentialPattern.Replace(redacted, "Digest [REDACTED] ");
        redacted = CookieHeaderPattern.Replace(redacted, match =>
            match.Groups[1].Value + CookieValuePattern.Replace(match.Groups[2].Value, "$1$2=[REDACTED]"));
        redacted = SensitiveAssignmentPattern.Replace(redacted, "$1$2[REDACTED]");
        redacted = BearerTokenPattern.Replace(redacted, "Bearer [REDACTED]");
        redacted = BasicCredentialPattern.Replace(redacted, "Basic [REDACTED]");
        redacted = QuerySecretPattern.Replace(redacted, "$1[REDACTED]");
        redacted = TokenPattern.Replace(redacted, "[REDACTED_TOKEN]");
        redacted = UrlCredentialPattern.Replace(redacted, "$1[REDACTED]@");
        return EmailPattern.Replace(redacted, "[REDACTED_EMAIL]");
    }

    /// <summary>Replaces every line of a PEM private key with a marker, keeping the number of lines unchanged.</summary>
    private static string RedactPrivateKeyBlocks(string text) =>
        text.Contains("PRIVATE KEY-----", StringComparison.Ordinal)
            ? PrivateKeyBlockPattern.Replace(text, match => string.Join('\n', match.Value.Split('\n')
                .Select(part => part.EndsWith('\r') ? RedactedPrivateKey + "\r" : RedactedPrivateKey)))
            : text;

    private static string? NormalizeFileName(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return fileName;
        }

        var safeName = fileName.Replace('\\', '/').Split('/').Last().Trim();
        safeName = RedactSensitiveDataCore(new string(safeName.Where(character => !char.IsControl(character)).ToArray()));
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

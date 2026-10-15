using LogTriageAssistant.Models;
using LogTriageAssistant.Services;
using Xunit;

namespace LogTriageAssistant.Tests;

/// <summary>Per-owner history retention.</summary>
public class HistoryRetentionTests
{
    [Fact]
    public async Task History_retention_trims_only_the_inserting_owners_rows()
    {
        var path = Path.Combine(Path.GetTempPath(), $"lta-retention-{Guid.NewGuid():N}.db");
        try
        {
            var store = new LogAnalysisStore($"Data Source={path};Pooling=False", maxSavedAnalyses: 3);
            await store.InitializeAsync();
            var start = DateTimeOffset.UtcNow.AddHours(-1);
            for (var i = 0; i < 2; i++)
                await store.AddAsync(new LogAnalysisResult { Id = $"b{i}", AnalyzedAt = start.AddMinutes(i), Severity = "HIGH" }, "owner-b");
            for (var i = 0; i < 5; i++)
                await store.AddAsync(new LogAnalysisResult { Id = $"a{i}", AnalyzedAt = start.AddMinutes(10 + i), Severity = "HIGH" }, "owner-a");

            var a = await store.GetRecentAsync("owner-a", 100);
            var b = await store.GetRecentAsync("owner-b", 100);

            Assert.Equal(["a4", "a3", "a2"], a.Select(x => x.Id));
            Assert.Equal(["b1", "b0"], b.Select(x => x.Id));
        }
        finally
        {
            foreach (var file in Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + "*"))
                File.Delete(file);
        }
    }
}

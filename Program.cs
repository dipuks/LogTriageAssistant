using LogTriageAssistant.Models;
using LogTriageAssistant.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;

const int MaxLogContentBytes = 2 * 1024 * 1024;
const int RequestOverheadAllowanceBytes = 64 * 1024;
const int MaxRequestBodyBytes = MaxLogContentBytes + RequestOverheadAllowanceBytes;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = MaxRequestBodyBytes;
});
var databasePath = builder.Configuration["Storage:DatabasePath"]
    ?? Path.Combine(builder.Environment.ContentRootPath, "App_Data", "logtriage.db");
var databaseDirectory = Path.GetDirectoryName(databasePath);
if (!string.IsNullOrEmpty(databaseDirectory))
{
    Directory.CreateDirectory(databaseDirectory);
}

var connectionString = new SqliteConnectionStringBuilder
{
    DataSource = databasePath,
    Mode = SqliteOpenMode.ReadWriteCreate
}.ToString();
builder.Services.AddSingleton(new LogAnalysisStore(connectionString));
builder.Services.AddSingleton<LogAnalyzerService>();

var app = builder.Build();

await app.Services.GetRequiredService<LogAnalysisStore>().InitializeAsync();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    service = "LogTriageAssistant",
    timestamp = DateTimeOffset.UtcNow
}));

app.MapGet("/api/recent", async (int? limit, LogAnalysisStore store, CancellationToken cancellationToken) =>
    Results.Ok(await store.GetRecentAsync(limit ?? 10, cancellationToken)));

app.MapDelete("/api/recent/{id}", async (string id, LogAnalysisStore store, CancellationToken cancellationToken) =>
    await store.DeleteAsync(id, cancellationToken)
        ? Results.NoContent()
        : Results.NotFound(new { error = "Analysis not found." }));

app.MapPost("/api/analyze", async (
    LogAnalysisRequest request,
    LogAnalyzerService service,
    LogAnalysisStore store,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.LogText))
    {
        return Results.BadRequest(new { error = "LogText must not be empty." });
    }

    if (System.Text.Encoding.UTF8.GetByteCount(request.LogText) > MaxLogContentBytes)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status413PayloadTooLarge,
            title: "Log content is too large.",
            detail: "Log content must be no larger than 2 MB.");
    }

    var result = service.Analyze(request.LogText, request.FileName ?? "manual-entry.log");
    await store.AddAsync(result, cancellationToken);
    return Results.Ok(result);
}).WithMetadata(new RequestSizeLimitAttribute(MaxRequestBodyBytes));

app.MapPost("/api/analyze-file", async (
    HttpRequest request,
    LogAnalyzerService service,
    LogAnalysisStore store,
    CancellationToken cancellationToken) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "Expected multipart/form-data upload." });
    }

    if (request.ContentLength > MaxRequestBodyBytes)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status413PayloadTooLarge,
            title: "Uploaded request is too large.",
            detail: "Uploaded files must be no larger than 2 MB.");
    }

    IFormCollection form;
    try
    {
        form = await request.ReadFormAsync(cancellationToken);
    }
    catch (InvalidDataException)
    {
        return Results.BadRequest(new { error = "The multipart form data is invalid." });
    }

    var file = form.Files["file"];
    if (file is null || file.Length == 0)
    {
        return Results.BadRequest(new { error = "Please upload a file with a non-zero length." });
    }

    if (file.Length > MaxLogContentBytes)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status413PayloadTooLarge,
            title: "Uploaded file is too large.",
            detail: "Uploaded files must be no larger than 2 MB.");
    }

    using var stream = file.OpenReadStream();
    using var streamReader = new StreamReader(stream);
    var content = await streamReader.ReadToEndAsync(cancellationToken);
    var result = service.Analyze(content, file.FileName);
    await store.AddAsync(result, cancellationToken);
    return Results.Ok(result);
}).WithMetadata(new RequestSizeLimitAttribute(MaxRequestBodyBytes));

app.UseDefaultFiles();
app.UseStaticFiles();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program { }

using LogTriageAssistant.Models;
using LogTriageAssistant.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using System.Security.Claims;
using System.Net;
using System.Text;
using System.Threading.RateLimiting;

if (args is ["--hash-admin-password"])
{
    Console.Error.Write("Enter the admin password (minimum 12 characters): ");
    var password = ReadPassword();
    if (password.Length < 12)
    {
        Console.Error.WriteLine("Password must be at least 12 characters.");
        return;
    }

    Console.WriteLine(new PasswordHasher<object>().HashPassword(new object(), password));
    return;
}

const int MaxLogContentBytes = 2 * 1024 * 1024;
const int RequestOverheadAllowanceBytes = 64 * 1024;
const int MaxRequestBodyBytes = MaxLogContentBytes + RequestOverheadAllowanceBytes;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
var trustedProxy = builder.Configuration["AdminAuth:TrustedProxy"];
if (!string.IsNullOrWhiteSpace(trustedProxy) && !IPAddress.TryParse(trustedProxy, out _))
{
    throw new InvalidOperationException("AdminAuth:TrustedProxy must be a single trusted proxy IP address.");
}

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    if (IPAddress.TryParse(trustedProxy, out var trustedProxyAddress))
    {
        options.KnownProxies.Add(trustedProxyAddress);
    }
});
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "LogTriage.Csrf";
    options.Cookie.Path = "/";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Strict;
});
builder.Services
    .AddOptions<AdminAuthOptions>()
    .Bind(builder.Configuration.GetSection("AdminAuth"))
    .Validate(
        options => !string.IsNullOrWhiteSpace(options.Username) && options.Username.Length <= 100,
        "AdminAuth:Username must contain 1-100 characters.")
    .Validate(options => AdminCredentialVerifier.IsValidPasswordHash(options.PasswordHash),
        "AdminAuth:PasswordHash must be an ASP.NET Core PasswordHasher hash.")
    .ValidateOnStart();
builder.Services.AddSingleton<AdminCredentialVerifier>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "__Host-LogTriage.Auth";
        options.Cookie.Path = "/";
        options.LoginPath = "/login.html";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.Events.OnRedirectToLogin = context =>
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }

            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});
var loginAttemptsPerMinute = builder.Configuration.GetValue(
    "AdminAuth:LoginAttemptsPerMinute",
    builder.Environment.IsDevelopment() ? 100 : 5);
if (loginAttemptsPerMinute is < 1 or > 1000)
{
    throw new InvalidOperationException("AdminAuth:LoginAttemptsPerMinute must be between 1 and 1000.");
}

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("admin-login", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = loginAttemptsPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});
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
var maxSavedAnalyses = builder.Configuration.GetValue("Storage:MaxSavedAnalyses", 1000);
builder.Services.AddSingleton(new LogAnalysisStore(connectionString, maxSavedAnalyses));
builder.Services.AddSingleton<LogAnalyzerService>();

var app = builder.Build();

await app.Services.GetRequiredService<LogAnalysisStore>().InitializeAsync();

app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
app.UseHttpsRedirection();

var allowHttp = builder.Configuration.GetValue("AdminAuth:AllowHttp", false);
app.Use(async (context, next) =>
{
    var isHealthCheck = context.Request.Path == "/health" ||
        context.Request.Path == "/health/ready";
    if (!context.Request.IsHttps && !allowHttp && !isHealthCheck)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new
        {
            error = "HTTPS is required. For local-only HTTP testing, explicitly enable AdminAuth:AllowHttp."
        });
        return;
    }

    await next();
});

app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

var auth = app.MapGroup("/api/auth");
auth.MapGet("/csrf", (HttpContext context, IAntiforgery antiforgery) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { token = tokens.RequestToken });
}).AllowAnonymous();

auth.MapPost("/login", async (
    AdminLoginRequest request,
    HttpContext context,
    AdminCredentialVerifier credentialVerifier) =>
{
    if (!credentialVerifier.Verify(request.Username, request.Password))
    {
        return Results.Unauthorized();
    }

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, request.Username!.Trim())
    };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity),
        new AuthenticationProperties { IsPersistent = false });
    return Results.NoContent();
})
    .AllowAnonymous()
    .RequireRateLimiting("admin-login");

auth.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.NoContent();
});

auth.MapGet("/status", (ClaimsPrincipal user) => Results.Ok(new { username = user.Identity?.Name }));

app.MapGet("/login.html", (IWebHostEnvironment environment) =>
    Results.File(Path.Combine(environment.WebRootPath!, "login.html"), "text/html; charset=utf-8"))
    .AllowAnonymous();
app.MapGet("/login.js", (IWebHostEnvironment environment) =>
    Results.File(Path.Combine(environment.WebRootPath!, "login.js"), "text/javascript; charset=utf-8"))
    .AllowAnonymous();

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.Use(async (context, next) =>
{
    var isApiWrite = context.Request.Path.StartsWithSegments("/api") &&
        (HttpMethods.IsPost(context.Request.Method) ||
         HttpMethods.IsPut(context.Request.Method) ||
         HttpMethods.IsPatch(context.Request.Method) ||
         HttpMethods.IsDelete(context.Request.Method));
    if (isApiWrite)
    {
        var antiforgery = context.RequestServices.GetRequiredService<IAntiforgery>();
        if (!await antiforgery.IsRequestValidAsync(context))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(new { error = "A valid CSRF token is required." });
            return;
        }
    }

    await next();
});

app.Use(async (context, next) =>
{
    var path = context.Request.Path;
    var isPublicPath =
        path == "/health" ||
        path == "/health/ready" ||
        path == "/login.html" ||
        path == "/login.js" ||
        path == "/api/auth/csrf" ||
        path == "/api/auth/login";

    if (!isPublicPath && context.User.Identity?.IsAuthenticated != true)
    {
        if (path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Authentication is required." });
        }
        else
        {
            context.Response.Redirect("/login.html");
        }

        return;
    }

    await next();
});

app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    service = "LogTriageAssistant",
    timestamp = DateTimeOffset.UtcNow
})).AllowAnonymous();

app.MapGet("/health/ready", async (
    LogAnalysisStore store,
    ILogger<Program> logger,
    CancellationToken cancellationToken) =>
{
    try
    {
        var isReady = await store.CheckHealthAsync(cancellationToken);
        return isReady
            ? Results.Ok(new { status = "ready" })
            : Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
    catch (SqliteException exception)
    {
        logger.LogWarning(exception, "SQLite readiness check failed.");
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
}).AllowAnonymous();

app.MapGet("/api/history", async (
    int? page,
    int? pageSize,
    string? search,
    string? severity,
    LogAnalysisStore store,
    CancellationToken cancellationToken) =>
{
    if (search?.Length > 100)
    {
        return Results.BadRequest(new { error = "Search text must be no longer than 100 characters." });
    }

    if (!string.IsNullOrEmpty(severity) &&
        !new[] { "CRITICAL", "HIGH", "MEDIUM", "INFO" }.Contains(severity, StringComparer.OrdinalIgnoreCase))
    {
        return Results.BadRequest(new { error = "Severity must be CRITICAL, HIGH, MEDIUM, or INFO." });
    }

    var history = await store.GetHistoryAsync(
        page ?? 1,
        pageSize ?? 20,
        search,
        string.IsNullOrWhiteSpace(severity) ? null : severity.ToUpperInvariant(),
        cancellationToken);
    return Results.Ok(history);
});

app.MapGet("/api/recent", async (int? limit, LogAnalysisStore store, CancellationToken cancellationToken) =>
    Results.Ok(await store.GetRecentAsync(limit ?? 10, cancellationToken)));

app.MapGet("/api/recent/{id}", async (string id, LogAnalysisStore store, CancellationToken cancellationToken) =>
    await store.GetByIdAsync(id, cancellationToken) is { } analysis
        ? Results.Ok(analysis)
        : Results.NotFound(new { error = "Analysis not found." }));

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

static string ReadPassword()
{
    var password = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.WriteLine();
            return password.ToString();
        }

        if (key.Key == ConsoleKey.Backspace && password.Length > 0)
        {
            password.Length--;
        }
        else if (!char.IsControl(key.KeyChar))
        {
            password.Append(key.KeyChar);
        }
    }

}

public partial class Program { }

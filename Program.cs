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
using Microsoft.Extensions.FileProviders;
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
        options =>
            (string.IsNullOrWhiteSpace(options.Username) && string.IsNullOrWhiteSpace(options.PasswordHash)) ||
            (!string.IsNullOrWhiteSpace(options.Username) &&
             options.Username.Length <= 100 &&
             AdminCredentialVerifier.IsValidPasswordHash(options.PasswordHash)),
        "Configure both a valid AdminAuth:Username and PasswordHash, or leave both unset.")
    .ValidateOnStart();
builder.Services.AddSingleton<AdminCredentialVerifier>();
builder.Services.AddSingleton<PasswordHasher<object>>();
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
    options.AddPolicy("account-register", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
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
builder.Services.AddHttpClient("ai-provider", client =>
{
    client.Timeout = TimeSpan.FromSeconds(45);
});
builder.Services.AddSingleton<AiAnalysisService>();

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

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(Path.Combine(app.Environment.WebRootPath!, "assets")),
    RequestPath = "/assets"
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
    AdminCredentialVerifier credentialVerifier,
    LogAnalysisStore store,
    PasswordHasher<object> passwordHasher,
    CancellationToken cancellationToken) =>
{
    var username = request.Username?.Trim();
    var password = request.Password;
    if (credentialVerifier.Verify(username, password))
    {
        await SignInAsync(context, "legacy-admin", username!);
        return Results.NoContent();
    }

    var user = !string.IsNullOrWhiteSpace(username) && username.Length <= 32
        ? await store.GetUserByUsernameAsync(username, cancellationToken)
        : null;
    var passwordIsValidLength = password is { Length: >= 12 and <= 1024 };
    var validUser = user is not null &&
        passwordIsValidLength &&
        passwordHasher.VerifyHashedPassword(new object(), user.PasswordHash, password!) !=
            PasswordVerificationResult.Failed;
    if (!validUser)
    {
        return Results.Unauthorized();
    }

    await SignInAsync(context, user!.Id, user.Username);
    return Results.NoContent();
})
    .AllowAnonymous()
    .RequireRateLimiting("admin-login");

auth.MapPost("/register", async (
    AccountRegistrationRequest request,
    HttpContext context,
    LogAnalysisStore store,
    PasswordHasher<object> passwordHasher,
    Microsoft.Extensions.Options.IOptions<AdminAuthOptions> adminOptions,
    CancellationToken cancellationToken) =>
{
    var username = request.Username?.Trim();
    if (username is null ||
        username.Length is < 3 or > 32 ||
        !System.Text.RegularExpressions.Regex.IsMatch(
            username,
            @"\A[a-zA-Z0-9][a-zA-Z0-9._-]*\z",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant))
    {
        return Results.BadRequest(new
        {
            error = "Username must be 3-32 characters, start with a letter or number, and use only letters, numbers, dots, underscores, or hyphens."
        });
    }

    if (request.Password is not { Length: >= 12 and <= 1024 })
    {
        return Results.BadRequest(new { error = "Password must be between 12 and 1024 characters." });
    }

    if (!string.Equals(request.Password, request.ConfirmPassword, StringComparison.Ordinal))
    {
        return Results.BadRequest(new { error = "Passwords do not match." });
    }

    if (!string.IsNullOrWhiteSpace(adminOptions.Value.Username) &&
        username.Equals(adminOptions.Value.Username, StringComparison.OrdinalIgnoreCase))
    {
        return Results.Conflict(new { error = "That username is unavailable." });
    }

    var account = new UserAccount(
        Guid.NewGuid().ToString("N"),
        username,
        passwordHasher.HashPassword(new object(), request.Password));
    if (!await store.CreateUserAsync(account, cancellationToken))
    {
        return Results.Conflict(new { error = "That username is unavailable." });
    }

    await SignInAsync(context, account.Id, account.Username);
    return Results.NoContent();
})
    .AllowAnonymous()
    .RequireRateLimiting("account-register");

auth.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.NoContent();
});

auth.MapGet("/status", (ClaimsPrincipal user) => Results.Ok(new { username = user.Identity?.Name }));

app.MapGet("/login.html", (IWebHostEnvironment environment) =>
    Results.File(Path.Combine(environment.WebRootPath!, "index.html"), "text/html; charset=utf-8"))
    .AllowAnonymous();
app.MapGet("/register.html", (IWebHostEnvironment environment) =>
    Results.File(Path.Combine(environment.WebRootPath!, "index.html"), "text/html; charset=utf-8"))
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
        path == "/register.html" ||
        path == "/api/auth/csrf" ||
        path == "/api/auth/login" ||
        path == "/api/auth/register";

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
    ClaimsPrincipal user,
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
        GetOwnerId(user),
        page ?? 1,
        pageSize ?? 20,
        search,
        string.IsNullOrWhiteSpace(severity) ? null : severity.ToUpperInvariant(),
        cancellationToken);
    return Results.Ok(history);
});

app.MapGet("/api/ai/providers", (AiAnalysisService service) =>
    Results.Ok(service.GetProviders()));

app.MapPost("/api/ai/analyze", async (
    AiAnalysisRequest request,
    AiAnalysisService service,
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

    if (string.IsNullOrWhiteSpace(request.Provider))
    {
        return Results.BadRequest(new { error = "Choose an AI provider." });
    }

    if (request.Provider is not ("ollama" or "hosted"))
    {
        return Results.BadRequest(new { error = "Choose a supported AI provider." });
    }

    try
    {
        var result = await service.AnalyzeAsync(request.Provider, request.LogText, cancellationToken);
        return Results.Ok(result);
    }
    catch (AiProviderNotConfiguredException exception)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable,
            title: "AI provider is not configured.",
            detail: exception.Message);
    }
    catch (AiProviderTimeoutException exception)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status504GatewayTimeout,
            title: "AI provider timed out.",
            detail: exception.Message);
    }
    catch (AiProviderException exception)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status502BadGateway,
            title: "AI analysis failed.",
            detail: exception.Message);
    }
}).WithMetadata(new RequestSizeLimitAttribute(MaxRequestBodyBytes));

app.MapGet("/api/recent", async (
    int? limit,
    ClaimsPrincipal user,
    LogAnalysisStore store,
    CancellationToken cancellationToken) =>
    Results.Ok(await store.GetRecentAsync(GetOwnerId(user), limit ?? 10, cancellationToken)));

app.MapGet("/api/recent/{id}", async (
    string id,
    ClaimsPrincipal user,
    LogAnalysisStore store,
    CancellationToken cancellationToken) =>
    await store.GetByIdAsync(id, GetOwnerId(user), cancellationToken) is { } analysis
        ? Results.Ok(analysis)
        : Results.NotFound(new { error = "Analysis not found." }));

app.MapDelete("/api/recent/{id}", async (
    string id,
    ClaimsPrincipal user,
    LogAnalysisStore store,
    CancellationToken cancellationToken) =>
    await store.DeleteAsync(id, GetOwnerId(user), cancellationToken)
        ? Results.NoContent()
        : Results.NotFound(new { error = "Analysis not found." }));

app.MapPost("/api/analyze", async (
    LogAnalysisRequest request,
    ClaimsPrincipal user,
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
    await store.AddAsync(result, GetOwnerId(user), cancellationToken);
    return Results.Ok(result);
}).WithMetadata(new RequestSizeLimitAttribute(MaxRequestBodyBytes));

app.MapPost("/api/analyze-file", async (
    HttpRequest request,
    ClaimsPrincipal user,
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
    await store.AddAsync(result, GetOwnerId(user), cancellationToken);
    return Results.Ok(result);
}).WithMetadata(new RequestSizeLimitAttribute(MaxRequestBodyBytes));

app.UseDefaultFiles();
app.UseStaticFiles();
app.MapFallbackToFile("index.html").AllowAnonymous();

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

static Task SignInAsync(HttpContext context, string ownerId, string username)
{
    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, ownerId),
        new Claim(ClaimTypes.Name, username)
    };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    return context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity),
        new AuthenticationProperties { IsPersistent = false });
}

static string GetOwnerId(ClaimsPrincipal user) =>
    user.FindFirstValue(ClaimTypes.NameIdentifier) ?? "legacy-admin";

public partial class Program { }

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace LogTriageAssistant.Services;

public sealed class AdminCredentialVerifier
{
    private static readonly object PasswordHasherUser = new();
    private static readonly PasswordHasher<object> PasswordHasher = new();
    private static readonly string DummyPasswordHash = PasswordHasher.HashPassword(PasswordHasherUser, Guid.NewGuid().ToString());
    private readonly AdminAuthOptions _options;

    public AdminCredentialVerifier(IOptions<AdminAuthOptions> options)
    {
        _options = options.Value;
    }

    public bool Verify(string? username, string? password)
    {
        var usernameMatches = username is { Length: <= 100 } &&
            string.Equals(username, _options.Username, StringComparison.OrdinalIgnoreCase);
        var candidateHash = usernameMatches ? _options.PasswordHash : DummyPasswordHash;
        var passwordIsValidLength = password is { Length: > 0 and <= 1024 };
        var verification = PasswordHasher.VerifyHashedPassword(
            PasswordHasherUser,
            candidateHash,
            passwordIsValidLength ? password! : string.Empty);

        return usernameMatches &&
            passwordIsValidLength &&
            verification != PasswordVerificationResult.Failed;
    }

    public static bool IsValidPasswordHash(string? passwordHash)
    {
        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            return false;
        }

        try
        {
            var hashBytes = Convert.FromBase64String(passwordHash);
            return hashBytes.Length >= 49 && hashBytes[0] == 0x01;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

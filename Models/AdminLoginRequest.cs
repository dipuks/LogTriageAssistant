namespace LogTriageAssistant.Models;

public sealed class AdminLoginRequest
{
    public string? Username { get; set; }
    public string? Password { get; set; }
}

public sealed class AccountRegistrationRequest
{
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? ConfirmPassword { get; set; }
}

public sealed record UserAccount(string Id, string Username, string PasswordHash);

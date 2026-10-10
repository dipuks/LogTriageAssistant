namespace LogTriageAssistant.Services;

public sealed class AdminAuthOptions
{
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
}

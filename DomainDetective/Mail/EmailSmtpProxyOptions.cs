namespace DomainDetective;

/// <summary>SMTP proxy settings (SOCKS5).</summary>
public sealed class EmailSmtpProxyOptions {
    /// <summary>Proxy host name or IP.</summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>Proxy port.</summary>
    public int Port { get; set; } = 1080;

    /// <summary>Proxy username.</summary>
    public string? Username { get; set; }

    /// <summary>Proxy password.</summary>
    public string? Password { get; set; }

    /// <summary>True when proxy configuration is usable.</summary>
    public bool IsConfigured => !string.IsNullOrWhiteSpace(Host) && Port > 0;
}

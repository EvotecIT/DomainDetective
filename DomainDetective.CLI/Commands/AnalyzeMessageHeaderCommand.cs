using Spectre.Console.Cli;
using Spectre.Console;
using DomainDetective.Helpers;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="AnalyzeMessageHeaderCommand"/>.
/// </summary>
internal sealed class AnalyzeMessageHeaderSettings : CommandSettings {
    /// <summary>File containing the message header.</summary>
    [CommandOption("--file <PATH>")]
    public FileInfo? File { get; set; }

    /// <summary>Message header text.</summary>
    [CommandOption("--header <VALUE>")]
    public string? Header { get; set; }

    /// <summary>Output JSON results.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Expected public MX host. May be supplied multiple times.</summary>
    [CommandOption("--expected-mx <HOST>")]
    public string[]? ExpectedMx { get; set; }

    /// <summary>Exact trusted authserv-id, repeatable.</summary>
    [CommandOption("--trusted-authserv-id <ID>")]
    public string[]? TrustedAuthServIds { get; set; }

    /// <summary>Verify DKIM/ARC using original MIME bytes, including the body.</summary>
    [CommandOption("--verify-signatures")]
    public bool VerifySignatures { get; set; }

    /// <summary>Explicitly permit public-key TXT lookups.</summary>
    [CommandOption("--allow-dns")]
    public bool AllowDns { get; set; }

    /// <summary>JSON dictionary of offline TXT public keys indexed by DNS name.</summary>
    [CommandOption("--public-keys <PATH>")]
    public FileInfo? PublicKeys { get; set; }

    /// <summary>Write a plain-text evidence report.</summary>
    [CommandOption("--report <PATH>")]
    public FileInfo? Report { get; set; }

    /// <inheritdoc/>
    public override ValidationResult Validate() {
        if ((File == null) == string.IsNullOrWhiteSpace(Header)) { return ValidationResult.Error("Supply exactly one of --file or --header."); }
        if (VerifySignatures && File == null) { return ValidationResult.Error("Signature verification requires an original MIME --file."); }
        if (!VerifySignatures && (AllowDns || PublicKeys != null)) { return ValidationResult.Error("--allow-dns and --public-keys require --verify-signatures."); }
        return ValidationResult.Success();
    }
}

/// <summary>
/// Analyzes standard message headers for DMARC and authentication issues.
/// </summary>
internal sealed class AnalyzeMessageHeaderCommand : Command<AnalyzeMessageHeaderSettings> {
    [RequiresDynamicCode("Message analysis JSON serialization may require dynamic code.")]
    [RequiresUnreferencedCode("Message analysis JSON serialization requires retained properties.")]
    /// <inheritdoc/>
    protected override int Execute(CommandContext context, AnalyzeMessageHeaderSettings settings, CancellationToken cancellationToken) {
        var options = new MessageVerificationOptions {
            HeaderOptions = new MessageHeaderAnalysisOptions { TrustedAuthServIds = settings.TrustedAuthServIds ?? Array.Empty<string>() },
            AllowDnsLookups = settings.AllowDns
        };
        if (settings.PublicKeys != null) {
            if (settings.PublicKeys.Length > 1024 * 1024) { throw new ArgumentException("Offline public-key file exceeds 1 MiB."); }
            options.PublicKeyRecords = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(System.IO.File.ReadAllText(settings.PublicKeys.FullName))
                ?? throw new ArgumentException("Public-key file must contain a JSON dictionary.");
        }
        using var health = new DomainHealthCheck();
        var result = settings.File != null
            ? health.AnalyzeMessageFileAsync(settings.File.FullName, settings.VerifySignatures, options, settings.ExpectedMx, cancellationToken).GetAwaiter().GetResult()
            : health.AnalyzeMessageHeaders(settings.Header!, options.HeaderOptions, settings.ExpectedMx, cancellationToken);
        if (settings.Json) { Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(result, JsonOptions.Default)); }
        else { Console.WriteLine(DomainDetective.Reports.MessageHeaderReport.ToText(result)); }
        if (settings.Report != null) {
            System.IO.Directory.CreateDirectory(settings.Report.DirectoryName!);
            System.IO.File.WriteAllText(settings.Report.FullName, DomainDetective.Reports.MessageHeaderReport.ToText(result));
        }
        return 0;
    }
}

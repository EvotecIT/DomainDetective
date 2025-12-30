using DomainDetective.CLI;
using DomainDetective.Helpers;
using DomainDetective.TimeSeries;
using DomainDetective.TimeSeries.DmarcAggregate;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Settings for <see cref="ImportDmarcAggregateSnapshotCommand"/>.
/// </summary>
internal sealed class ImportDmarcAggregateSnapshotSettings : CommandSettings {
    /// <summary>Path to a report file/folder/wildcard (XML/GZ/ZIP). If omitted, IMAP mode is used.</summary>
    [Description("Path to a report file/folder/wildcard (XML/GZ/ZIP). If omitted, IMAP mode is used.")]
    [CommandArgument(0, "[path]")]
    public string? Path { get; set; }

    /// <summary>Root directory for snapshot storage.</summary>
    [Description("Root directory for snapshot storage.")]
    [CommandOption("--store|--store-path")]
    public string StorePath { get; set; } = string.Empty;

    /// <summary>Disable in-run deduplication (by report-id/date-range/org/domain).</summary>
    [Description("Disable in-run deduplication (by report-id/date-range/org/domain).")]
    [CommandOption("--no-deduplicate")]
    public bool NoDeduplicate { get; set; }

    /// <summary>Output JSON instead of a console summary.</summary>
    [Description("Output JSON instead of a console summary.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    // IMAP mode
    /// <summary>IMAP host used for mailbox ingestion.</summary>
    [Description("IMAP host used for mailbox ingestion.")]
    [CommandOption("--imap-host")]
    public string? ImapHost { get; set; }

    /// <summary>IMAP port (default 993).</summary>
    [Description("IMAP port (default 993).")]
    [CommandOption("--imap-port")]
    [DefaultValue(993)]
    public int ImapPort { get; set; } = 993;

    /// <summary>Disable SSL/TLS for IMAP connection.</summary>
    [Description("Disable SSL/TLS for IMAP connection.")]
    [CommandOption("--imap-no-ssl")]
    public bool ImapNoSsl { get; set; }

    /// <summary>IMAP username.</summary>
    [Description("IMAP username.")]
    [CommandOption("--imap-user")]
    public string? ImapUser { get; set; }

    /// <summary>IMAP password (discouraged; prefer --imap-password-env).</summary>
    [Description("IMAP password (discouraged; prefer --imap-password-env).")]
    [CommandOption("--imap-password")]
    public string? ImapPassword { get; set; }

    /// <summary>Environment variable name containing IMAP password.</summary>
    [Description("Environment variable name containing IMAP password.")]
    [CommandOption("--imap-password-env")]
    public string? ImapPasswordEnv { get; set; }

    /// <summary>Mailbox folder name (default INBOX).</summary>
    [Description("Mailbox folder name (default INBOX).")]
    [CommandOption("--mailbox")]
    [DefaultValue("INBOX")]
    public string Mailbox { get; set; } = "INBOX";

    /// <summary>Only scan messages with a subject containing this string (IMAP mode).</summary>
    [Description("Only scan messages with a subject containing this string (IMAP mode).")]
    [CommandOption("--imap-subject-contains")]
    public string? ImapSubjectContains { get; set; }

    /// <summary>Only fetch messages delivered since this UTC date/time.</summary>
    [Description("Only fetch messages delivered since this UTC date/time.")]
    [CommandOption("--since-utc")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Maximum number of messages to scan (default 500).</summary>
    [Description("Maximum number of messages to scan (default 500).")]
    [CommandOption("--max-messages")]
    [DefaultValue(500)]
    public int MaxMessages { get; set; } = 500;

    /// <summary>Maximum attachment size to decode in MB (0 for unlimited).</summary>
    [Description("Maximum attachment size to decode in MB (0 for unlimited).")]
    [CommandOption("--max-attachment-mb")]
    [DefaultValue(50)]
    public int MaxAttachmentMb { get; set; } = 50;

    /// <summary>Include seen messages (default scans only unseen).</summary>
    [Description("Include seen messages (default scans only unseen).")]
    [CommandOption("--include-seen")]
    public bool IncludeSeen { get; set; }
}

/// <summary>
/// Imports DMARC aggregate reports into a time-series store.
/// </summary>
internal sealed class ImportDmarcAggregateSnapshotCommand : AsyncCommand<ImportDmarcAggregateSnapshotSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override async Task<int> ExecuteAsync(CommandContext context, ImportDmarcAggregateSnapshotSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (string.IsNullOrWhiteSpace(settings.StorePath)) {
            AnsiConsole.MarkupLine("[red]--store-path is required.[/]");
            return 1;
        }

        bool hasPath = !string.IsNullOrWhiteSpace(settings.Path);
        bool hasImap = !string.IsNullOrWhiteSpace(settings.ImapHost);
        if (hasPath == hasImap) {
            AnsiConsole.MarkupLine("[red]Specify either a [path] argument OR --imap-host (IMAP mode).[/]");
            return 1;
        }

        var store = new DmarcAggregateTimeSeriesStore(settings.StorePath);
        bool deduplicate = !settings.NoDeduplicate;

        DmarcAggregateIngestResult result;
        if (hasImap) {
            var password = ResolvePassword(settings.ImapPassword, settings.ImapPasswordEnv);
            if (password == null) {
                AnsiConsole.MarkupLine("[red]IMAP password is required (use --imap-password-env or --imap-password).[/]");
                return 1;
            }

            var options = new ImapAttachmentIngestOptions {
                Host = settings.ImapHost!.Trim(),
                Port = settings.ImapPort,
                UseSsl = !settings.ImapNoSsl,
                Username = settings.ImapUser?.Trim() ?? string.Empty,
                Password = password,
                Mailbox = string.IsNullOrWhiteSpace(settings.Mailbox) ? "INBOX" : settings.Mailbox.Trim(),
                MaxMessages = settings.MaxMessages,
                OnlyUnseen = !settings.IncludeSeen,
                RequireAttachments = true,
                MaxAttachmentBytes = settings.MaxAttachmentMb <= 0
                    ? 0
                    : (long)settings.MaxAttachmentMb * 1024L * 1024L,
            };
            if (!string.IsNullOrWhiteSpace(settings.ImapSubjectContains)) {
                options.SubjectContains = settings.ImapSubjectContains;
            }
            if (settings.SinceUtc.HasValue) {
                options.SinceUtc = new DateTimeOffset(DateTime.SpecifyKind(settings.SinceUtc.Value, DateTimeKind.Utc));
            }

            try {
                result = await DmarcAggregateIngestion.IngestFromImapAsync(options, store, deduplicate, Program.CancellationToken);
            }
            catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]IMAP ingestion failed:[/] {Markup.Escape(ex.Message)}");
                return 1;
            }
        } else {
            try {
                result = DmarcAggregateIngestion.IngestFromPath(settings.Path!, store, deduplicate);
            }
            catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Path ingestion failed:[/] {Markup.Escape(ex.Message)}");
                return 1;
            }
        }

        foreach (var e in result.Errors) {
            if (!string.IsNullOrWhiteSpace(e)) {
                AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(e)}[/]");
            }
        }

        if (settings.Json) {
            var json = JsonSerializer.Serialize(result, JsonOptions.Default);
            Console.WriteLine(json);
            return 0;
        }

        var domains = result.Snapshots
            .Where(s => s != null && !string.IsNullOrWhiteSpace(s.Domain))
            .Select(s => s.Domain.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        AnsiConsole.MarkupLine($"[green]Ingested[/] {result.Snapshots.Count} snapshot(s) into [blue]{Markup.Escape(settings.StorePath)}[/].");
        if (domains.Count > 0) {
            AnsiConsole.MarkupLine($"[blue]Domains:[/] {Markup.Escape(string.Join(", ", domains))}");
        }

        return 0;
    }

    private static string? ResolvePassword(string? direct, string? envName) {
        if (!string.IsNullOrWhiteSpace(direct)) {
            return direct;
        }
        if (string.IsNullOrWhiteSpace(envName)) {
            return null;
        }
        var value = Environment.GetEnvironmentVariable(envName);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}

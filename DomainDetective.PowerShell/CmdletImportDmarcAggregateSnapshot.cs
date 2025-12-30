using System;
using System.Management.Automation;
using DomainDetective.TimeSeries;
using DomainDetective.TimeSeries.DmarcAggregate;

namespace DomainDetective.PowerShell;

/// <summary>Imports DMARC aggregate reports into a time-series store.</summary>
/// <para>Parses .xml/.gz/.zip DMARC aggregate feedback reports and stores normalized snapshots on disk.</para>
/// <example>
///   <summary>Ingest DMARC aggregate reports from a folder</summary>
///   <code>Import-DDDmarcAggregateSnapshot -Path .\Reports -StorePath .\Store</code>
/// </example>
/// <example>
///   <summary>Ingest DMARC aggregate report attachments from IMAP</summary>
///   <code>Import-DDDmarcAggregateSnapshot -StorePath .\Store -ImapHost imap.example.com -Credential (Get-Credential) -Mailbox INBOX -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7)</code>
/// </example>
[Cmdlet(VerbsData.Import, "DDDmarcAggregateSnapshot", DefaultParameterSetName = "Path")]
[Alias("Import-DmarcAggregateSnapshot")]
[OutputType(typeof(DmarcAggregateSnapshot))]
public sealed class CmdletImportDmarcAggregateSnapshot : PSCmdlet
{
    /// <summary>Path to a report file/folder/wildcard.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Path", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string Path { get; set; } = string.Empty;

    /// <summary>Root directory for snapshot storage.</summary>
    [Parameter(Mandatory = true)]
    [ValidateNotNullOrEmpty]
    public string StorePath { get; set; } = string.Empty;

    /// <summary>IMAP host used for mailbox ingestion.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Imap")]
    [ValidateNotNullOrEmpty]
    public string ImapHost { get; set; } = string.Empty;

    /// <summary>IMAP port (default 993).</summary>
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public int ImapPort { get; set; } = 993;

    /// <summary>Use SSL/TLS for IMAP connection (default true).</summary>
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public bool ImapUseSsl { get; set; } = true;

    /// <summary>Credential for IMAP authentication.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Imap")]
    public PSCredential Credential { get; set; } = null!;

    /// <summary>Mailbox folder name (default INBOX).</summary>
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public string Mailbox { get; set; } = "INBOX";

    /// <summary>Only scan messages with a subject containing this string.</summary>
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public string? SubjectContains { get; set; }

    /// <summary>Only fetch messages delivered since this UTC date/time.</summary>
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Maximum number of messages to scan (default 500).</summary>
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public int MaxMessages { get; set; } = 500;

    /// <summary>Maximum attachment size to decode in MB (0 for unlimited).</summary>
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public int MaxAttachmentMb { get; set; } = 50;

    /// <summary>Only consider unseen messages (default true).</summary>        
    [Parameter(Mandatory = false, ParameterSetName = "Imap")]
    public bool OnlyUnseen { get; set; } = true;

    /// <summary>Disable in-run deduplication (by report-id/date-range/org/domain).</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoDeduplicate { get; set; }

    /// <summary>Return the ingest result wrapper instead of snapshots.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter AsResult { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord()
    {
        var store = new DmarcAggregateTimeSeriesStore(StorePath);
        bool deduplicate = !NoDeduplicate.IsPresent;

        DmarcAggregateIngestResult result;
        if (string.Equals(ParameterSetName, "Imap", StringComparison.OrdinalIgnoreCase))
        {
            var options = new ImapAttachmentIngestOptions
            {
                Host = ImapHost,
                Port = ImapPort,
                UseSsl = ImapUseSsl,
                Username = Credential.UserName ?? string.Empty,
                Password = Credential.GetNetworkCredential().Password ?? string.Empty,
                Mailbox = Mailbox ?? "INBOX",
                MaxMessages = MaxMessages,
                OnlyUnseen = OnlyUnseen,
                RequireAttachments = true,
                MaxAttachmentBytes = MaxAttachmentMb <= 0
                    ? 0
                    : (long)MaxAttachmentMb * 1024L * 1024L,
            };
            if (!string.IsNullOrWhiteSpace(SubjectContains)) {
                options.SubjectContains = SubjectContains;
            }
            if (SinceUtc.HasValue)
            {
                options.SinceUtc = new DateTimeOffset(DateTime.SpecifyKind(SinceUtc.Value, DateTimeKind.Utc));
            }

            result = DmarcAggregateIngestion.IngestFromImapAsync(options, store, deduplicate).GetAwaiter().GetResult();
        }
        else
        {
            result = DmarcAggregateIngestion.IngestFromPath(Path, store, deduplicate);
        }

        foreach (var e in result.Errors)
        {
            if (!string.IsNullOrWhiteSpace(e)) WriteWarning(e);
        }

        if (AsResult.IsPresent)
        {
            WriteObject(result);
        }
        else
        {
            WriteObject(result.Snapshots, enumerateCollection: true);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Composes a security report (Word/HTML) from pipeline view objects (SPF/DKIM/DMARC).</summary>
    /// <para>Pipe outputs from existing cmdlets to build one report without duplicating rendering logic.</para>
    /// <example>
    ///   <summary>Compose SPF+DMARC across two domains.</summary>
    ///   <code>
    ///   Test-DDEmailSpfRecord -DomainName contoso.com, fabrikam.com |
    ///   Test-DDEmailDmarcRecord -DomainName contoso.com, fabrikam.com |
    ///   Export-DDSecurityReport -ExportFormat Word -ExportPath ".\\Reports" -OpenReport
    ///   </code>
    /// </example>
    [Cmdlet(VerbsData.Export, "DDSecurityReport", DefaultParameterSetName = "Default")]
    [Alias("New-DDSecurityReport")]
    public sealed class CmdletExportSecurityReport : ExportableAsyncPSCmdlet {
        /// <summary>Objects to compose (SPF/DKIM/DMARC/… view objects). Optional when using -Compose.</summary>
        [Parameter(Mandatory = false, ValueFromPipeline = true, Position = 0)]
        public object InputObject;

        /// <summary>Detail scope for section writers.</summary>
        [Parameter(Mandatory = false)]
        public DomainDetective.Reports.ReportScope Scope { get; set; } = DomainDetective.Reports.ReportScope.Normal;


        /// <summary>Include Info-level findings in sections when supported.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowInfoFindings { get; set; } = true;

        /// <summary>
        /// Optional script block to run and capture its output for composition.
        /// Enables inline scenarios:
        /// Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\Reports {
        ///     Test-DDEmailSpfRecord -DomainName contoso.com
        ///     Test-DDDnsBlacklist -NameOrIpAddress 203.0.113.5
        /// }
        /// </summary>
        [Parameter(Mandatory = false)]
        public ScriptBlock Compose { get; set; }

        private readonly List<object> _items = new();

    /// <summary>Collects pipeline inputs for composition.</summary>
    protected override Task ProcessRecordAsync() {
        if (InputObject != null) _items.Add(InputObject);
        return Task.CompletedTask;
    }

        /// <summary>Generates the report at the end of the pipeline.</summary>
        protected override Task EndProcessingAsync() {
            // If a script block was provided, invoke and append its results
            if (Compose != null) {
                try {
                    var results = Compose.Invoke();
                    if (results != null) {
                        foreach (var obj in results) if (obj != null) _items.Add(obj.BaseObject ?? obj);
                    }
                } catch (Exception ex) {
                    WriteWarning($"Compose block failed: {ex.Message}");
                }
            }

            if (_items.Count == 0) return Task.CompletedTask;

            var fmt = ExportFormat ?? ExportDefaults.Format;
            // Build label from first two domains we can detect
            var subjects = ExtractSubjects(_items);
            var label = subjects.Count switch {
                0 => "report",
                1 => subjects[0],
                2 => $"{subjects[0]}+{subjects[1]}",
                _ => $"{subjects[0]}+{subjects[1]}(+{subjects.Count - 2})"
            };
            var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, fmt);

            try {
                switch (fmt) {
                    case DomainDetective.Reports.ReportFormat.Word:
                        DomainDetective.Reports.Office.WordCompositionReport.Generate(
                            outPath,
                            _items,
                            Scope,
                            ShowInfoFindings.IsPresent,
                            ExportDefaults.NarrativePlacement,
                            null,
                            ExportDefaults.CompanyName,
                            ExportDefaults.CompanyAddress,
                            ExportDefaults.CompanyYear,
                            string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                            string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                            string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                    case DomainDetective.Reports.ReportFormat.Html:
                        DomainDetective.Reports.Html.HtmlCompositionReport.Generate(outPath, _items, Scope, OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser, ExportDefaults.NarrativePlacement);
                        break;
                    default:
                        return ExportNotImplementedAsync("Export-DDSecurityReport");
                }
            } catch (Exception ex) {
                WriteWarning($"Export failed: {ex.Message}");
            }

            return Task.CompletedTask;
        }

        private static List<string> ExtractSubjects(IEnumerable<object> items) {
            var list = new List<string>();
            foreach (var it in items) {
                switch (it) {
                    case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject): list.Add(spf.Subject); break;
                    case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject): list.Add(dmarc.Subject); break;
                    case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject): list.Add(dkim.Subject); break;
                    case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject): list.Add(mc.Subject); break;
                    case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject): list.Add(ms.Subject); break;
                    case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject): list.Add(tr.Subject); break;
                    case DomainDetective.Views.DnsblInfo db when !string.IsNullOrWhiteSpace(db.Subject): list.Add(db.Subject); break;
                }
            }
            return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
    }
}

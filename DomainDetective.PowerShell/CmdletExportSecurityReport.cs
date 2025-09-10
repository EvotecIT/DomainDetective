using System;
using System.Collections.Generic;
using System.Collections;
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
        public object? InputObject;

        /// <summary>Detail scope for section writers.</summary>
        [Parameter(Mandatory = false)]
        public DomainDetective.Reports.ReportScope Scope { get; set; } = DomainDetective.Reports.ReportScope.Normal;


        /// <summary>Include Info-level findings in sections when supported.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowInfoFindings { get; set; } = true;

        // Provider Help controls
        [Parameter(Mandatory = false)]
        [ValidateSet("Off","Minimal","Standard","Detailed")]
        public string ProviderHelpPreset { get; set; } = "Standard";

        [Parameter(Mandatory = false)]
        public Hashtable? ProviderHelpOptions { get; set; }

        /// <summary>
        /// Optional script block to run and capture its output for composition.
        /// Enables inline scenarios:
        /// Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\Reports {
        ///     Test-DDEmailSpfRecord -DomainName contoso.com
        ///     Test-DDDnsBlacklist -NameOrIpAddress 203.0.113.5
        /// }
        /// </summary>
        [Parameter(Mandatory = false)]
        public ScriptBlock? Compose { get; set; }

        // Per-call narrative overrides (optional)
        /// <summary>Override document title for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Title { get; set; }
        /// <summary>Override document subject/description for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Subject { get; set; }
        /// <summary>Override document category for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Category { get; set; }
        /// <summary>Override document keywords (comma-separated) for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Keywords { get; set; }
        /// <summary>Override document creator/author for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Creator { get; set; }

        // Ordering controls
        [Parameter(Mandatory = false)]
        [ValidateSet("Alphabetical","Input")]
        public string DomainOrder { get; set; } = "Alphabetical";

        [Parameter(Mandatory = false)]
        [ValidateSet("Canonical","Input","Custom")]
        public string SectionOrderMode { get; set; } = "Canonical";

        [Parameter(Mandatory = false)]
        public string[]? SectionOrder { get; set; }

        private readonly List<object> _items = new();

    /// <summary>Collects pipeline inputs for composition.</summary>
    protected override Task ProcessRecordAsync() {
        if (InputObject != null) {
            // Unwrap PSObject and flatten early to avoid nested arrays reaching the composer
            object Unwrap(object o) => (o is PSObject pso && pso.BaseObject != null) ? pso.BaseObject : o;
            if (InputObject is System.Collections.IEnumerable en && InputObject is not string) {
                foreach (var e in en) if (e != null) _items.Add(Unwrap(e));
            } else {
                _items.Add(Unwrap(InputObject));
            }
        }
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

            var fmts = (ExportFormat != null && ExportFormat.Length > 0)
                ? ExportFormat
                : new[] { ExportDefaults.Format };
            // Flatten nested arrays/lists from pipeline variables ($spf, $dmarc, $mx)
            var flat = new List<object>();
            IEnumerable<object> Flatten(object o) {
                object Unwrap(object x) => (x is PSObject pso && pso.BaseObject != null) ? pso.BaseObject : x;
                if (o is System.Collections.IEnumerable en && o is not string) {
                    foreach (var e in en) if (e != null) yield return Unwrap(e);
                } else {
                    yield return Unwrap(o);
                }
            }
            foreach (var raw in _items) foreach (var it in Flatten(raw)) flat.Add(it);

            // Build label from first two domains we can detect
            var subjects = ExtractSubjects(flat);
            WriteVerbose($"Export-DDSecurityReport: composing {flat.Count} item(s) across {subjects.Count} domain(s).");
            var label = subjects.Count switch {
                0 => "report",
                1 => subjects[0],
                2 => $"{subjects[0]}+{subjects[1]}",
                _ => $"{subjects[0]}+{subjects[1]}(+{subjects.Count - 2})"
            };
            // Helper to compute per-format output path when multiple formats were requested
            string ResolveOutPathForFormat(DomainDetective.Reports.ReportFormat f)
            {
                if (!string.IsNullOrWhiteSpace(ExportPath))
                {
                    try
                    {
                        var p = ExportPath!;
                        var looksLikeDirectory = false;
                        if (System.IO.Directory.Exists(p)) looksLikeDirectory = true;
                        else if (p.EndsWith(System.IO.Path.DirectorySeparatorChar.ToString()) || p.EndsWith(System.IO.Path.AltDirectorySeparatorChar.ToString())) looksLikeDirectory = true;
                        else if (!System.IO.Path.HasExtension(p)) looksLikeDirectory = true;

                        if (!looksLikeDirectory && fmts.Length > 1)
                        {
                            // User provided a file path but asked for multiple formats; derive unique paths by replacing extension
                            var dir = System.IO.Path.GetDirectoryName(p) ?? string.Empty;
                            var name = System.IO.Path.GetFileNameWithoutExtension(p);
                            var ext = f switch {
                                DomainDetective.Reports.ReportFormat.Html => ".html",
                                DomainDetective.Reports.ReportFormat.Word => ".docx",
                                DomainDetective.Reports.ReportFormat.Excel => ".xlsx",
                                DomainDetective.Reports.ReportFormat.Pdf => ".pdf",
                                DomainDetective.Reports.ReportFormat.Json => ".json",
                                DomainDetective.Reports.ReportFormat.Markdown => ".md",
                                DomainDetective.Reports.ReportFormat.HtmlAsMarkdown => ".html",
                                _ => ".html"
                            };
                            var combined = System.IO.Path.Combine(string.IsNullOrEmpty(dir) ? "." : dir, name + ext);
                            try { System.IO.Directory.CreateDirectory(string.IsNullOrEmpty(dir) ? "." : dir); } catch { }
                            return combined;
                        }
                    }
                    catch { /* fall through to helper */ }
                }
                return DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, f);
            }

            try {
                foreach (var fmt in fmts) {
                    var outPath = ResolveOutPathForFormat(fmt);
                    switch (fmt) {
                        case DomainDetective.Reports.ReportFormat.Word:
                            var helpOpts = BuildProviderHelpOptions(ProviderHelpPreset, ProviderHelpOptions);
                            DomainDetective.Reports.Office.WordCompositionReport.Generate(
                                outPath,
                                flat,
                            Scope,
                            ShowInfoFindings.IsPresent,
                            ExportDefaults.NarrativePlacement,
                            string.IsNullOrWhiteSpace(Title) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle) : Title,
                            string.IsNullOrWhiteSpace(Subject) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject) : Subject,
                            string.IsNullOrWhiteSpace(Category) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory) : Category,
                            string.IsNullOrWhiteSpace(Keywords) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords) : Keywords,
                            string.IsNullOrWhiteSpace(Creator) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator) : Creator,
                            ExportDefaults.CompanyName,
                            ExportDefaults.CompanyAddress,
                            ExportDefaults.CompanyYear,
                            string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                            string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                            string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText,
                            true,
                            true,
                            helpOpts,
                            (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                            (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                            SectionOrder);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        case DomainDetective.Reports.ReportFormat.Html:
                        DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                            outPath,
                            flat,
                            Scope,
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            ExportDefaults.NarrativePlacement,
                            string.IsNullOrWhiteSpace(Title) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle) : Title,
                            string.IsNullOrWhiteSpace(Creator) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator) : Creator,
                            string.IsNullOrWhiteSpace(Subject) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject) : Subject,
                            (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                            (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                            SectionOrder);
                        break;
                        case DomainDetective.Reports.ReportFormat.Excel:
                            DomainDetective.Reports.Office.ExcelCompositionReport.Generate(
                                outPath,
                                flat,
                                Scope,
                            new DomainDetective.Reports.OrderingOptions {
                                DomainOrder = (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                                SectionOrderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                                SectionOrder = SectionOrder
                            });
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        case DomainDetective.Reports.ReportFormat.Markdown:
                            DomainDetective.Reports.Markdown.MarkdownCompositionReport.Generate(
                                outPath,
                                flat,
                                Scope,
                                new DomainDetective.Reports.OrderingOptions {
                                    DomainOrder = (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                                    SectionOrderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                                    SectionOrder = SectionOrder
                                });
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        case DomainDetective.Reports.ReportFormat.HtmlAsMarkdown:
                            DomainDetective.Reports.Markdown.MarkdownCompositionReport.GenerateHtmlAsMarkdown(
                                outPath,
                                flat,
                                Scope,
                                new DomainDetective.Reports.OrderingOptions {
                                    DomainOrder = (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                                    SectionOrderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                                    SectionOrder = SectionOrder
                                });
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        default:
                            return ExportNotImplementedAsync("Export-DDSecurityReport");
                    }
                }
            } catch (Exception ex) {
                WriteWarning($"Export failed: {ex.Message}");
            }

            return Task.CompletedTask;
        }

            private static List<string> ExtractSubjects(IEnumerable<object> items) {
                var list = new List<string>();
                IEnumerable<object> Flatten(object o) {
                    object Unwrap(object x) => (x is PSObject pso && pso.BaseObject != null) ? pso.BaseObject : x;
                    if (o is System.Collections.IEnumerable en && o is not string) {
                        foreach (var e in en) if (e != null) yield return Unwrap(e);
                    } else {
                        yield return Unwrap(o);
                    }
                }
                foreach (var raw in items ?? Array.Empty<object>()) {
                    foreach (var it in Flatten(raw)) {
                        switch (it) {
                            case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject): list.Add(mx.Subject); break;
                            case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject): list.Add(spf.Subject); break;
                            case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject): list.Add(dmarc.Subject); break;
                            case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject): list.Add(dkim.Subject); break;
                            case DomainDetective.Views.ArcInfo arc when !string.IsNullOrWhiteSpace(arc.Subject): list.Add(arc.Subject); break;
                            case DomainDetective.Views.BimiRecordInfo bimi when !string.IsNullOrWhiteSpace(bimi.Subject): list.Add(bimi.Subject); break;
                            case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject): list.Add(mc.Subject); break;
                            case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject): list.Add(ms.Subject); break;
                            case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject): list.Add(tr.Subject); break;
                            case DomainDetective.Views.DnsblInfo db when !string.IsNullOrWhiteSpace(db.Subject): list.Add(db.Subject); break;
                        }
                    }
                }
                return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }

        private static DomainDetective.Reports.Office.ProviderHelpRenderOptions BuildProviderHelpOptions(string preset, Hashtable? overrides)
        {
            var o = new DomainDetective.Reports.Office.ProviderHelpRenderOptions();
            switch ((preset ?? "Standard").Trim())
            {
                case "Off":
                    o.ShowUnderMx = o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = false; break;
                case "Minimal":
                    o.ShowUnderMx = true; o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = false;
                    o.ShowSummaries = false; o.ShowNotes = false; o.ShowVerified = false; o.ShowBadges = false;
                    break;
                case "Detailed":
                    o.ShowUnderMx = o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = true;
                    o.ShowSummaries = true; o.ShowNotes = true; o.ShowVerified = true; o.ShowBadges = true;
                    break;
                default: // Standard
                    o.ShowUnderMx = o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = true;
                    o.ShowSummaries = true; o.ShowNotes = true; o.ShowVerified = true; o.ShowBadges = true;
                    break;
            }
            if (overrides != null)
            {
                foreach (DictionaryEntry de in overrides)
                {
                    var key = (de.Key?.ToString() ?? string.Empty).Trim();
                    var val = de.Value;
                    if (string.Equals(key, "Under", StringComparison.OrdinalIgnoreCase) && val is System.Collections.IEnumerable en)
                    {
                        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var v in en) if (v != null) set.Add(v.ToString()!);
                        o.ShowUnderMx = set.Contains("MX");
                        o.ShowUnderSpf = set.Contains("SPF");
                        o.ShowUnderDkim = set.Contains("DKIM");
                        o.ShowUnderDmarc = set.Contains("DMARC");
                        // Optional new sections
                        try { o.ShowUnderBimi = set.Contains("BIMI"); } catch {}
                        try { o.ShowUnderArc  = set.Contains("ARC"); } catch {}
                        continue;
                    }
                    if (string.Equals(key, "Topics", StringComparison.OrdinalIgnoreCase) && val is System.Collections.IEnumerable en2)
                    {
                        var list = new List<string>();
                        foreach (var v in en2) if (v != null) list.Add(v.ToString()!.ToUpperInvariant());
                        if (list.Count > 0) o.TopicOrder = list.ToArray();
                        continue;
                    }
                    void setBool(System.Action<bool> assign)
                    {
                        if (val is bool b) assign(b);
                        else if (val is SwitchParameter sp) assign(sp.IsPresent);
                        else if (val != null && bool.TryParse(val.ToString(), out var bb)) assign(bb);
                    }
                    switch (key.ToLowerInvariant())
                    {
                        case "showsummaries": setBool(v => o.ShowSummaries = v); break;
                        case "shownotes": setBool(v => o.ShowNotes = v); break;
                        case "showbadges": setBool(v => o.ShowBadges = v); break;
                        case "showverified": setBool(v => o.ShowVerified = v); break;
                        case "includerestricted": setBool(v => o.IncludeRestricted = v); break;
                        case "includethirdparty": setBool(v => o.IncludeThirdParty = v); break;
                        case "maxproviders": if (val != null && int.TryParse(val.ToString(), out var m)) o.MaxProviders = m; break;
                    }
                }
            }
            return o;
        }
    }
}

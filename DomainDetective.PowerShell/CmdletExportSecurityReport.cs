using System;
using System.Collections.Generic;
using System.Collections;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Management.Automation.Language;
using System.Threading;
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
    /// <example>
    ///   <summary>Inline, positional ScriptBlock (no -Compose switch).</summary>
    ///   <code>
    ///   Export-DDSecurityReport -ExportFormat Markdown -ExportPath ".\\Reports" {
    ///     Test-DDEmailSpfRecord  -DomainName contoso.com,fabrikam.com
    ///     Test-DDEmailDkimRecord -DomainName contoso.com,fabrikam.com
    ///     Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
    ///   }
    ///   </code>
    /// </example>
    /// <example>
    ///   <summary>Pipeline + inline together (pipeline binds to InputObject, block binds to Compose).</summary>
    ///   <code>
    ///   $views = Test-DDEmailSpfRecord -DomainName contoso.com,fabrikam.com
    ///   $views | Export-DDSecurityReport -ExportFormat Markdown -ExportPath ".\\Reports" {
    ///     Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
    ///   }
    ///   </code>
    /// </example>
    /// <example>
    ///   <summary>Preserve input domain order and force a custom section order.</summary>
    ///   <code>
    ///   Export-DDSecurityReport -ExportFormat Html -ExportPath ".\\Reports" -DomainOrder Input `
    ///     -SectionOrderMode Custom -SectionOrder MX,SPF,DMARC {
    ///     Test-DDEmailSpfRecord   -DomainName contoso.com,fabrikam.com
    ///     Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
    ///   }
    ///   </code>
    /// </example>
    [Cmdlet(VerbsData.Export, "DDSecurityReport", DefaultParameterSetName = "Default")]
    [Alias("New-DDSecurityReport")]
    public sealed class CmdletExportSecurityReport : ExportableAsyncPSCmdlet {
        /// <summary>Pipeline input to compose into the report.</summary>
        /// <para>Objects to compose (SPF/DKIM/DMARC/… view objects). Optional when using <c>-Compose</c>.</para>
        /// <para>Accepts single objects or arrays; enumerables are flattened. If a <see cref="ScriptBlock"/> is supplied, it is invoked and its output is composed.</para>
        // Default set: keep positional 0 for backward compatibility when no -Compose is used
        [Parameter(Mandatory = false, ValueFromPipeline = true, Position = 0, ParameterSetName = "Default")]
        // Inline set: accept pipeline as well, but place after the scriptblock
        [Parameter(Mandatory = false, ValueFromPipeline = true, Position = 1, ParameterSetName = "Inline")]
        public object? InputObject;

        /// <summary>Detail scope for section writers.</summary>
        [Parameter(Mandatory = false)]
        public DomainDetective.Reports.ReportScope Scope { get; set; } = DomainDetective.Reports.ReportScope.Normal;


        /// <summary>Include Info-level findings in sections when supported.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowInfoFindings { get; set; } = true;

        // Provider Help controls
        /// <para>Controls how much provider reference material is embedded beneath each section (MX/SPF/DKIM/DMARC, etc.).</para>
        /// <para>
        /// Presets: <c>Off</c> (no provider help), <c>Minimal</c> (only under MX, no summaries/notes),
        /// <c>Standard</c> (balanced defaults), <c>Detailed</c> (enable all summaries/notes/verified/badges under all sections).
        /// Use together with <see cref="ProviderHelpOptions"/> to fine-tune.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Off","Minimal","Standard","Detailed")]
        public string ProviderHelpPreset { get; set; } = "Standard";

        /// <para>Optional overrides for the chosen <see cref="ProviderHelpPreset"/>. Provide as a hashtable.</para>
        /// <para>
        /// Recognized keys: <c>Under</c> (array of section keys such as MX, SPF, DKIM, DMARC, BIMI, ARC),
        /// <c>Topics</c> (array of topic names to order), <c>ShowSummaries</c>, <c>ShowNotes</c>,
        /// <c>ShowBadges</c>, <c>ShowVerified</c>, <c>IncludeRestricted</c>, <c>IncludeThirdParty</c>,
        /// and <c>MaxProviders</c> (integer limit).
        /// Example: <c>@{ Under = 'MX','SPF','DKIM'; ShowNotes = $true; MaxProviders = 10 }</c>.
        /// </para>
        [Parameter(Mandatory = false)]
        public Hashtable? ProviderHelpOptions { get; set; }

        /// <summary>Inline script block used to generate additional input for composition.</summary>
        /// <para>Optional script block executed to produce additional input objects for composition (inline mode).</para>
        /// <para>Example:</para>
        /// <para>
        /// <code>
        /// Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\Reports {
        ///     Test-DDEmailSpfRecord -DomainName contoso.com
        ///     Test-DDDnsBlacklist -NameOrIpAddress 203.0.113.5
        /// }
        /// </code>
        /// </para>
        // Make Compose the first positional parameter in the Inline parameter set, so users can write:
        // Export-DDSecurityReport { Test-DDEmailSpfRecord -DomainName example.com }
        [Parameter(Mandatory = false, Position = 0, ParameterSetName = "Inline")]
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

        // Presentation profiles (optional)
        /// <para>Choose the HTML presentation profile.</para>
        /// <para>
        /// <c>Document</c> provides a narrative, document-style layout; <c>Dashboard</c> focuses on
        /// high-level, concise summaries suitable for quick review or portals.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Document","Dashboard")]
        public string HtmlProfile { get; set; } = "Document";

        /// <para>Choose the Excel presentation profile.</para>
        /// <para>
        /// <c>Workbook</c> exports structured sheets intended for analysis and filtering; <c>Dashboard</c>
        /// emphasizes an at-a-glance overview sheet.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Workbook","Dashboard")]
        public string ExcelProfile { get; set; } = "Workbook";

        // Ordering controls
        /// <para>Controls how domains are ordered in the output.</para>
        /// <para>
        /// <c>Alphabetical</c> sorts domains A→Z. <c>Input</c> preserves first-seen order from the input
        /// stream/inline composition.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Alphabetical","Input")]
        public string DomainOrder { get; set; } = "Alphabetical";

        /// <para>Controls section ordering within each domain.</para>
        /// <para>
        /// <c>Canonical</c> uses the built-in order (e.g. MX, SPF, DKIM, DMARC, …), <c>Input</c> orders by
        /// first appearance in your data, and <c>Custom</c> applies the explicit order from <see cref="SectionOrder"/>.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Canonical","Input","Custom")]
        public string SectionOrderMode { get; set; } = "Canonical";

        /// <para>Explicit section order to use when <see cref="SectionOrderMode"/> is <c>Custom</c>.</para>
        /// <para>
        /// Typical keys include: MX, SPF, DKIM, DMARC, ARC, BIMI, DNSBL, RPKI, NS, SOA, ZoneTransfer,
        /// Wildcard, CAA, Classification, MTA-STS, TLS-RPT, DNSSEC, DANE. Values are normalized (e.g. "TLSRPT" → "TLS-RPT").
        /// </para>
        [Parameter(Mandatory = false)]
        public string[]? SectionOrder { get; set; }

        /// <summary>Max status columns in the Word executive summary table.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(1, 12)]
        public int? SummaryColumnCap { get; set; }

        private readonly List<object> _items = new();

        private static readonly HashSet<string> _autoVariables = new(StringComparer.OrdinalIgnoreCase) {
            "_",
            "PSItem",
            "args",
            "PSBoundParameters",
            "MyInvocation",
            "ExecutionContext",
            "input",
            "null",
            "true",
            "false",
            "Error",
            "HOME",
            "Host",
            "PID",
            "PSCommandPath",
            "PSCulture",
            "PSHome",
            "PSScriptRoot",
            "PSSessionApplicationName",
            "PSSessionConfigurationName",
            "PSSessionOption",
            "PSUICulture",
            "PSVersionTable",
            "PWD",
            "ShellId"
        };

        private static readonly string[] _preferenceVariables = {
            "VerbosePreference",
            "DebugPreference",
            "ErrorActionPreference",
            "WarningPreference",
            "InformationPreference",
            "ProgressPreference",
            "PSDefaultParameterValues"
        };

        // Recursively append objects, executing ScriptBlocks when provided via InputObject
        private void AppendObject(object obj)
        {
            if (obj == null) return;
            object Unwrap(object o) => (o is PSObject pso && pso.BaseObject != null) ? pso.BaseObject : o;
            var o2 = Unwrap(obj);

            // If caller passed a ScriptBlock as InputObject (positional or via pipeline), execute it and append its results
            if (o2 is ScriptBlock sb)
            {
                try
                {
                    var results = sb.Invoke();
                    if (results != null)
                    {
                        foreach (var r in results) if (r != null) AppendObject(Unwrap(r));
                    }
                }
                catch (Exception ex)
                {
                    WriteWarning($"InputObject ScriptBlock failed: {ex.Message}");
                }
                return;
            }

            // Flatten enumerables (excluding strings) and process items recursively
            if (o2 is System.Collections.IEnumerable en && o2 is not string)
            {
                foreach (var e in en) if (e != null) AppendObject(Unwrap(e));
                return;
            }

            _items.Add(o2);
        }

    /// <summary>Collects pipeline inputs for composition.</summary>
    protected override Task ProcessRecordAsync() {
        if (InputObject != null) AppendObject(InputObject);
        return Task.CompletedTask;
    }

        /// <summary>Generates the report at the end of the pipeline.</summary>
        protected override async Task EndProcessingAsync() {
            // If a script block was provided, invoke and append its results
            if (Compose != null) {
                WriteVerbose("Export-DDSecurityReport: Compose execution started.");
                var composeSw = Stopwatch.StartNew();
                var composeAdded = 0;
                var ranParallel = false;
                if (!DisableParallel.IsPresent) {
                    try {
                        ranParallel = TryExecuteComposeInParallel(Compose, out var parallelResults);
                        if (ranParallel && parallelResults.Count > 0) {
                            foreach (var obj in parallelResults) {
                                if (obj != null) {
                                    _items.Add(obj.BaseObject ?? obj);
                                    composeAdded++;
                                }
                            }
                        }
                    } catch (OperationCanceledException) {
                        throw;
                    } catch (PipelineStoppedException) {
                        throw;
                    } catch (Exception ex) {
                        WriteWarning($"Compose parallel execution failed: {ex.Message}");
                        WriteVerbose(ex.ToString());
                    }
                }

                if (!ranParallel) {
                    try {
                        CancelToken.ThrowIfCancellationRequested();
                        var results = InvokeComposeWithPreferences(Compose);
                        if (results != null) {
                            foreach (var obj in results) {
                                if (obj != null) {
                                    _items.Add(obj.BaseObject ?? obj);
                                    composeAdded++;
                                }
                            }
                        }
                    } catch (OperationCanceledException) {
                        throw;
                    } catch (PipelineStoppedException) {
                        throw;
                    } catch (Exception ex) {
                        WriteWarning($"Compose block failed: {ex.Message}");
                        WriteVerbose(ex.ToString());
                    }
                }
                composeSw.Stop();
                WriteVerbose($"Export-DDSecurityReport: Compose completed in {composeSw.ElapsedMilliseconds} ms (items added: {composeAdded}).");
            }

            if (_items.Count == 0) {
                return;
            }

            var logger = new DomainDetective.InternalLogger(false);
            _ = new InternalLoggerPowerShell(
                logger,
                IsVerboseEnabled() ? WriteVerbose : null,
                WriteWarning,
                WriteDebug,
                WriteError,
                WriteProgress,
                WriteInformation);

            var ordering = new DomainDetective.Reports.OrderingOptions {
                DomainOrder = (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                SectionOrderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                SectionOrder = SectionOrder
            };

            var titleOverride = string.IsNullOrWhiteSpace(Title)
                ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle)
                : Title;
            var subjectOverride = string.IsNullOrWhiteSpace(Subject)
                ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject)
                : Subject;
            var categoryOverride = string.IsNullOrWhiteSpace(Category)
                ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory)
                : Category;
            var keywordsOverride = string.IsNullOrWhiteSpace(Keywords)
                ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords)
                : Keywords;
            var creatorOverride = string.IsNullOrWhiteSpace(Creator)
                ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator)
                : Creator;

            var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format);
            var providerHelp = DomainDetective.Reports.ProviderHelpOptionsFactory.Build(ProviderHelpPreset, ProviderHelpOptions);
            var openInBrowser = OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser;
            var request = new DomainDetective.Reports.CompositionExportRequest {
                Items = _items,
                Formats = formats,
                Scope = Scope,
                ShowInfoFindings = ShowInfoFindings.IsPresent,
                Ordering = ordering,
                HtmlProfile = this.HtmlProfile,
                ExcelProfile = this.ExcelProfile,
                Title = titleOverride,
                Subject = subjectOverride,
                Category = categoryOverride,
                Keywords = keywordsOverride,
                Creator = creatorOverride,
                NarrativePlacement = ExportDefaults.NarrativePlacement,
                CompanyName = ExportDefaults.CompanyName,
                CompanyAddress = ExportDefaults.CompanyAddress,
                CompanyYear = ExportDefaults.CompanyYear,
                LogoPath = string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                HeaderText = string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                WatermarkText = string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText,
                SummaryColumnCap = SummaryColumnCap ?? ExportDefaults.SummaryColumnCap,
                HeaderLogoSizePx = ExportDefaults.HeaderLogoSizePx,
                FooterLogoSizePx = ExportDefaults.FooterLogoSizePx,
                ProviderHelpOptions = providerHelp,
                ExportPath = ExportPath,
                DefaultOutputDirectory = ExportDefaults.OutputDirectory,
                OpenInBrowser = openInBrowser,
                LogSectionOrder = IsVerboseEnabled(),
                AutoCollectTtl = true,
                ExecutionOptions = new DomainDetective.Reports.CompositionExecutionOptions {
                    EnableParallelism = !DisableParallel.IsPresent,
                    MaxParallelism = MaxParallelism
                }
            };

            await DomainDetective.Reports.CompositionExportService.ExportAsync(request, logger, CancelToken).ConfigureAwait(false);
            return;
        }

        private sealed class ComposeScriptItem {
            public ComposeScriptItem(string scriptText, Dictionary<string, object?> variables) {
                ScriptText = scriptText;
                Variables = variables;
            }

            public string ScriptText { get; }
            public Dictionary<string, object?> Variables { get; }
        }

        private sealed class ComposeInvocationResult {
            public List<PSObject> Output { get; set; } = new();
            public List<string> Verbose { get; set; } = new();
            public List<string> Warnings { get; set; } = new();
            public List<ErrorRecord> Errors { get; set; } = new();
            public List<InformationRecord> Information { get; set; } = new();
        }

        private bool TryExecuteComposeInParallel(ScriptBlock compose, out List<PSObject> results) {
            results = new List<PSObject>();
            var plan = BuildParallelComposePlan(compose, out var reason);
            if (plan == null) {
                if (!string.IsNullOrWhiteSpace(reason)) {
                    WriteVerbose($"Export-DDSecurityReport: Compose not parallelized ({reason}).");
                }
                WriteVerbose("Export-DDSecurityReport: executing Compose serially.");
                return false;
            }

            var throttle = GetEffectiveThrottleLimit();
            var execOptions = new DomainDetective.Reports.CompositionExecutionOptions {
                EnableParallelism = !DisableParallel.IsPresent,
                MaxParallelism = throttle
            };
            if (execOptions.EnableParallelism && plan.Items.Count > 1) {
                WriteVerbose($"Export-DDSecurityReport: executing Compose in parallel ({plan.Description}, throttle {throttle}).");
            } else {
                var note = execOptions.EnableParallelism ? "single item" : "parallel disabled";
                WriteVerbose($"Export-DDSecurityReport: executing Compose serially ({note}).");
            }

            var modulePath = this.MyInvocation?.MyCommand?.Module?.Path;
            var iss = InitialSessionState.CreateDefault();
            if (!string.IsNullOrWhiteSpace(modulePath)) {
                iss.ImportPSModule(new[] { modulePath });
            }

            var min = 1;
            using var pool = RunspaceFactory.CreateRunspacePool(min, throttle, iss, this.Host);
            pool.ThreadOptions = PSThreadOptions.ReuseThread;
            pool.Open();

            var ordered = DomainDetective.Reports.CompositionWorkExecutor
                .ExecuteAsync(
                    plan,
                    (item, ct) => Task.FromResult(InvokeComposeItem(pool, item, ct)),
                    execOptions,
                    null,
                    null,
                    CancelToken)
                .GetAwaiter()
                .GetResult();
            foreach (var result in ordered) {
                foreach (var message in result.Verbose) {
                    WriteVerbose(message);
                }
                foreach (var message in result.Warnings) {
                    WriteWarning(message);
                }
                foreach (var info in result.Information) {
                    WriteInformation(info);
                }
                foreach (var error in result.Errors) {
                    WriteError(error);
                }
                if (result.Output.Count > 0) {
                    results.AddRange(result.Output);
                }
            }

            WriteVerbose($"Export-DDSecurityReport: Compose produced {results.Count} item(s).");
            return true;
        }

        private Collection<PSObject>? InvokeComposeWithPreferences(ScriptBlock compose) {
            if (!IsVerboseEnabled()) {
                return compose.Invoke();
            }

            var vars = new List<PSVariable> {
                new PSVariable("VerbosePreference", ActionPreference.Continue)
            };
            return compose.InvokeWithContext(null, vars);
        }

        private ComposeInvocationResult InvokeComposeItem(RunspacePool pool, ComposeScriptItem item, CancellationToken cancellationToken) {
            var result = new ComposeInvocationResult();
            using var ps = System.Management.Automation.PowerShell.Create();
            ps.RunspacePool = pool;
            using var reg = cancellationToken.Register(() => {
                try {
                    ps.Stop();
                } catch {
                    // Ignore stop exceptions during cancellation.
                }
            });
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var kvp in item.Variables) {
                ps.AddCommand("Set-Variable")
                    .AddParameter("Name", kvp.Key)
                    .AddParameter("Value", kvp.Value);
                ps.AddStatement();
            }

            if (IsVerboseEnabled()) {
                ps.AddCommand("Set-Variable")
                    .AddParameter("Name", "VerbosePreference")
                    .AddParameter("Value", ActionPreference.Continue);
                ps.AddStatement();
            }

            ps.AddScript(item.ScriptText);

            try {
                var output = ps.Invoke();
                if (output != null) {
                    result.Output.AddRange(output);
                }
                cancellationToken.ThrowIfCancellationRequested();
            } catch (OperationCanceledException) {
                throw;
            } catch (PipelineStoppedException) {
                throw;
            } catch (Exception ex) {
                result.Warnings.Add($"Compose item failed: {ex.Message}");
            }

            if (ps.Streams.Verbose != null) {
                result.Verbose.AddRange(ps.Streams.Verbose.Select(v => v.Message));
            }
            if (ps.Streams.Warning != null) {
                result.Warnings.AddRange(ps.Streams.Warning.Select(w => w.Message));
            }
            if (ps.Streams.Information != null) {
                result.Information.AddRange(ps.Streams.Information);
            }
            if (ps.Streams.Error != null && ps.Streams.Error.Count > 0) {
                result.Errors.AddRange(ps.Streams.Error);
            }

            return result;
        }

        private DomainDetective.Reports.CompositionWorkPlan<ComposeScriptItem>? BuildParallelComposePlan(ScriptBlock compose, out string? reason) {
            reason = null;
            if (compose.Ast is not ScriptBlockAst ast) {
                reason = "missing AST";
                return null;
            }
            if (ast.ParamBlock != null || ast.BeginBlock != null || ast.ProcessBlock != null) {
                reason = "Compose has parameters or Begin/Process blocks";
                return null;
            }
            var end = ast.EndBlock;
            if (end == null || end.Statements.Count == 0) {
                reason = "Compose is empty";
                return null;
            }
            var items = new List<ComposeScriptItem>();
            foreach (var stmt in end.Statements) {
                switch (stmt) {
                    case PipelineAst pipelineAst:
                        if (!TryAppendPipelineItem(pipelineAst, null, items)) {
                            continue;
                        }
                        break;
                    case ForEachStatementAst foreachAst:
                        if (!TryAppendForeachItems(foreachAst, items, out reason)) {
                            return null;
                        }
                        break;
                    default:
                        reason = "Compose contains non-parallelizable statements";
                        return null;
                }
            }
            if (items.Count == 0) {
                reason = "Compose contained no runnable statements";
                return null;
            }
            return new DomainDetective.Reports.CompositionWorkPlan<ComposeScriptItem>(items, $"statements={items.Count}");
        }

        private bool TryAppendPipelineItem(
            PipelineAst pipelineAst,
            string? excludeVar,
            List<ComposeScriptItem> items) {
            var text = pipelineAst.Extent.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(text)) {
                return false;
            }
            var vars = CollectVariables(pipelineAst, excludeVar);
            items.Add(new ComposeScriptItem(text, vars));
            return true;
        }

        private bool TryAppendForeachItems(
            ForEachStatementAst foreachAst,
            List<ComposeScriptItem> items,
            out string? reason) {
            reason = null;
            var varName = foreachAst.Variable?.VariablePath?.UserPath;
            if (string.IsNullOrWhiteSpace(varName)) {
                reason = "foreach variable missing";
                return false;
            }
            var varNameValue = varName!;

            var collectionText = foreachAst.Condition?.Extent.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(collectionText)) {
                reason = "foreach collection is empty";
                return false;
            }

            Collection<PSObject>? values = null;
            try {
                values = this.InvokeCommand.InvokeScript(collectionText);
            } catch (Exception ex) {
                reason = $"foreach collection failed: {ex.Message}";
                return false;
            }

            if (values == null || values.Count == 0) {
                reason = "foreach collection yielded no values";
                return false;
            }

            var bodyStatements = foreachAst.Body?.Statements;
            if (bodyStatements == null || bodyStatements.Count == 0) {
                reason = "foreach body is empty";
                return false;
            }
            if (bodyStatements.Any(s => s is not PipelineAst)) {
                reason = "foreach body contains non-parallelizable statements";
                return false;
            }

            var startCount = items.Count;
            foreach (var value in values) {
                var itemValue = value?.BaseObject ?? value;
                foreach (var stmt in bodyStatements.Cast<PipelineAst>()) {
                    var text = stmt.Extent.Text?.Trim() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(text)) {
                        continue;
                    }
                    var vars = CollectVariables(stmt, varNameValue);
                    var map = new Dictionary<string, object?>(vars, StringComparer.OrdinalIgnoreCase) {
                        [varNameValue] = itemValue
                    };
                    items.Add(new ComposeScriptItem(text, map));
                }
            }

            if (items.Count == startCount) {
                reason = "foreach produced no work items";
                return false;
            }

            return true;
        }

        private DomainDetective.Reports.CompositionWorkPlan<ComposeScriptItem>? BuildForeachPlan(ForEachStatementAst foreachAst, out string? reason) {
            reason = null;
            var varName = foreachAst.Variable?.VariablePath?.UserPath;
            if (string.IsNullOrWhiteSpace(varName)) {
                reason = "foreach variable missing";
                return null;
            }
            var varNameValue = varName!;

            var bodyText = foreachAst.Body?.Extent.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(bodyText)) {
                reason = "foreach body is empty";
                return null;
            }
            if (bodyText.StartsWith("{", StringComparison.Ordinal) && bodyText.EndsWith("}", StringComparison.Ordinal)) {
                bodyText = bodyText.Substring(1, bodyText.Length - 2).Trim();
            }
            if (string.IsNullOrWhiteSpace(bodyText)) {
                reason = "foreach body is empty";
                return null;
            }

            var collectionText = foreachAst.Condition?.Extent.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(collectionText)) {
                reason = "foreach collection is empty";
                return null;
            }

            Collection<PSObject>? values = null;
            try {
                values = this.InvokeCommand.InvokeScript(collectionText);
            } catch (Exception ex) {
                reason = $"foreach collection failed: {ex.Message}";
                return null;
            }

            if (values == null || values.Count == 0) {
                reason = "foreach collection yielded no values";
                return null;
            }

            var vars = CollectVariables(foreachAst.Body!, varNameValue);
            var items = new List<ComposeScriptItem>();
            foreach (var value in values) {
                var map = new Dictionary<string, object?>(vars, StringComparer.OrdinalIgnoreCase) {
                    [varNameValue] = value?.BaseObject ?? value
                };
                items.Add(new ComposeScriptItem(bodyText, map));
            }
            if (items.Count == 0) {
                reason = "foreach produced no work items";
                return null;
            }
            return new DomainDetective.Reports.CompositionWorkPlan<ComposeScriptItem>(items, $"foreach({varNameValue}) x {items.Count}");
        }

        private Dictionary<string, object?> CollectVariables(Ast ast, string? excludeVar) {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var variable in ast.FindAll(n => n is VariableExpressionAst, true).Cast<VariableExpressionAst>()) {
                var name = variable.VariablePath?.UserPath;
                if (string.IsNullOrWhiteSpace(name)) {
                    continue;
                }
                var nameValue = name!;
                if (_autoVariables.Contains(nameValue)) {
                    continue;
                }
                if (!string.IsNullOrWhiteSpace(excludeVar) && string.Equals(nameValue, excludeVar, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }
                if (nameValue.Contains(":", StringComparison.Ordinal)) {
                    continue;
                }
                names.Add(nameValue);
            }

            var vars = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in names) {
                try {
                    var val = GetVariableValue(name, null);
                    if (val != null) {
                        vars[name] = val;
                    }
                } catch { }
            }

            foreach (var pref in _preferenceVariables) {
                if (!vars.ContainsKey(pref)) {
                    try {
                        var val = SessionState?.PSVariable?.GetValue(pref);
                        if (val != null) {
                            vars[pref] = val;
                        }
                    } catch { }
                }
            }

            return vars;
        }
    }
}



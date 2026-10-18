using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using Spectre.Console;

namespace DomainDetective.CLI;

internal static partial class CommandUtilities {
    /// <summary>Renders every collected domain run before returning the first batch failure to the command.</summary>
    internal static void WriteBatchResults(IReadOnlyList<DomainHealthCheckRun> runs, HealthCheckType[] checks,
        bool checkHttp, bool checkWeb, bool checkTakeover, bool autodiscoverEndpoints, bool outputJson, bool summaryOnly, bool unicodeOutput) {
        ExceptionDispatchInfo? failure = null;
        foreach (var run in runs) {
            if (run.Error != null) { failure ??= ExceptionDispatchInfo.Capture(run.Error); }
            var hc = run.HealthCheck;
            if (outputJson) {
                // Keep JSON output machine-readable, including a factory failure with no analysis instance.
                Console.WriteLine(hc != null ? hc.ToJson() : JsonSerializer.Serialize(new {
                    DomainName = run.DomainName, VerificationCompleted = false, VerificationError = run.Error?.Message
                }));
                continue;
            }
            if (run.Error != null) {
                AnsiConsole.MarkupLine($"[yellow]Scan incomplete for {run.DomainName.EscapeMarkup()}: {run.Error.Message.EscapeMarkup()}[/]");
            }
            if (hc == null) { continue; }
            if (summaryOnly) {
                AnsiConsole.MarkupLine($"[bold]Summary for {run.DomainName.EscapeMarkup()}[/]");
                OutputFormatters.FormatAsSelectedSummary(hc, hc.VerificationRequestedChecks.ToArray(), hc.VerificationCompletedChecks.ToHashSet());
            } else {
                WriteDetailedRun(run.DomainName, hc, checks, checkHttp, checkWeb, checkTakeover, autodiscoverEndpoints, unicodeOutput);
            }
        }
        failure?.Throw();
    }

    private static void WriteDetailedRun(string domain, DomainHealthCheck hc, HealthCheckType[] checks,
        bool checkHttp, bool checkWeb, bool checkTakeover, bool autodiscoverEndpoints, bool unicodeOutput) {
        var analysisMap = hc.GetAnalysisMap();
        foreach (var check in checks) {
            if (!OutputFormatters.HasCompletedCheck(hc, check)) {
                AnsiConsole.MarkupLine($"[yellow]{check} for {domain.EscapeMarkup()}: Incomplete; collected evidence may be partial.[/]");
                continue;
            }
            if (!analysisMap.TryGetValue(check, out var data) || data == null) { continue; }
            var desc = DomainHealthCheck.GetCheckDescription(check);
            var header = desc != null ? $"{check} for {domain} - {desc.Summary}" : $"{check} for {domain}";
            CliHelpers.ShowPropertiesTable(header, data, unicodeOutput);
            if (check == HealthCheckType.AUTODISCOVER && autodiscoverEndpoints) {
                CliHelpers.ShowPropertiesTable($"AUTODISCOVER ENDPOINTS for {domain}", hc.AutodiscoverHttpAnalysis.Endpoints, unicodeOutput);
            }
        }
        void WriteSupplemental(string title, object data, bool? completed) {
            if (completed == true || !hc.VerificationCompleted.HasValue) { CliHelpers.ShowPropertiesTable(title, data, unicodeOutput); }
            else if (completed == false) { AnsiConsole.MarkupLine($"[yellow]{title.EscapeMarkup()}: Incomplete; collected evidence may be partial.[/]"); }
        }
        if (checkHttp) { WriteSupplemental($"PLAIN HTTP for {domain}", hc.PlainHttpAnalysis, hc.VerificationPlainHttpCompleted); }
        if (checkWeb && OutputFormatters.HasCompletedCheck(hc, HealthCheckType.WEBSITE)) {
            CliHelpers.ShowPropertiesTable($"WEB CERT for {domain}", hc.CertificateAnalysis, unicodeOutput);
            CliHelpers.ShowPropertiesTable($"HTTPS SECURITY for {domain}", hc.HttpAnalysis, unicodeOutput);
        }
        if (checkTakeover) { WriteSupplemental($"TAKEOVER for {domain}", hc.TakeoverCnameAnalysis, hc.VerificationTakeoverCompleted); }
    }
}

using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;


namespace DomainDetective.CLI.Commands;

/// <summary>
/// Displays endpoint-level certificate risk posture from persisted inventory snapshots.
/// </summary>
internal sealed class CertificateInventoryRiskCommand : AsyncCommand<CertificateInventoryRiskSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryRiskSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxEndpoints < 0) {
            AnsiConsole.MarkupLine("[red]--max-endpoints must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ExpiringWithinDays < 0) {
            AnsiConsole.MarkupLine("[red]--expiring-within-days must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.CriticalExpiringWithinDays < 0) {
            AnsiConsole.MarkupLine("[red]--critical-expiring-within-days must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.CriticalExpiringWithinDays > settings.ExpiringWithinDays) {
            AnsiConsole.MarkupLine("[red]--critical-expiring-within-days cannot be greater than --expiring-within-days.[/]");
            return Task.FromResult(1);
        }
        if (settings.PortEquals.HasValue && (settings.PortEquals.Value <= 0 || settings.PortEquals.Value > 65535)) {
            AnsiConsole.MarkupLine("[red]--port must be between 1 and 65535.[/]");
            return Task.FromResult(1);
        }
        if (settings.ScoreMin.HasValue && (settings.ScoreMin.Value < 0 || settings.ScoreMin.Value > 100)) {
            AnsiConsole.MarkupLine("[red]--score-min must be between 0 and 100.[/]");
            return Task.FromResult(1);
        }
        if (settings.ScoreMax.HasValue && (settings.ScoreMax.Value < 0 || settings.ScoreMax.Value > 100)) {
            AnsiConsole.MarkupLine("[red]--score-max must be between 0 and 100.[/]");
            return Task.FromResult(1);
        }
        if (settings.ScoreMin.HasValue && settings.ScoreMax.HasValue && settings.ScoreMin.Value > settings.ScoreMax.Value) {
            AnsiConsole.MarkupLine("[red]--score-min cannot be greater than --score-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReasonCountMin.HasValue && settings.ReasonCountMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--reason-count-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReasonCountMax.HasValue && settings.ReasonCountMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--reason-count-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReasonCountMin.HasValue && settings.ReasonCountMax.HasValue && settings.ReasonCountMin.Value > settings.ReasonCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reason-count-min cannot be greater than --reason-count-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseEndpointCountMin.HasValue && settings.ReuseEndpointCountMin.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-endpoint-min must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseEndpointCountMax.HasValue && settings.ReuseEndpointCountMax.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-endpoint-max must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseEndpointCountMin.HasValue && settings.ReuseEndpointCountMax.HasValue && settings.ReuseEndpointCountMin.Value > settings.ReuseEndpointCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reuse-endpoint-min cannot be greater than --reuse-endpoint-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseCrossServiceOnly && settings.ReuseSingleServiceOnly) {
            AnsiConsole.MarkupLine("[red]--reuse-cross-service-only cannot be combined with --reuse-single-service-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseServiceCountMin.HasValue && settings.ReuseServiceCountMin.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-service-min must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseServiceCountMax.HasValue && settings.ReuseServiceCountMax.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-service-max must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseServiceCountMin.HasValue && settings.ReuseServiceCountMax.HasValue && settings.ReuseServiceCountMin.Value > settings.ReuseServiceCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reuse-service-min cannot be greater than --reuse-service-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReusePortCountMin.HasValue && settings.ReusePortCountMin.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-port-min must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReusePortCountMax.HasValue && settings.ReusePortCountMax.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-port-max must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReusePortCountMin.HasValue && settings.ReusePortCountMax.HasValue && settings.ReusePortCountMin.Value > settings.ReusePortCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reuse-port-min cannot be greater than --reuse-port-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseCrossPortOnly && settings.ReuseSinglePortOnly) {
            AnsiConsole.MarkupLine("[red]--reuse-cross-port-only cannot be combined with --reuse-single-port-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainLengthMin.HasValue && settings.ChainLengthMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--chain-length-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainLengthMax.HasValue && settings.ChainLengthMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--chain-length-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainLengthMin.HasValue && settings.ChainLengthMax.HasValue && settings.ChainLengthMin.Value > settings.ChainLengthMax.Value) {
            AnsiConsole.MarkupLine("[red]--chain-length-min cannot be greater than --chain-length-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.IntermediateCountMin.HasValue && settings.IntermediateCountMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--intermediate-count-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.IntermediateCountMax.HasValue && settings.IntermediateCountMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--intermediate-count-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.IntermediateCountMin.HasValue && settings.IntermediateCountMax.HasValue && settings.IntermediateCountMin.Value > settings.IntermediateCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--intermediate-count-min cannot be greater than --intermediate-count-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.CtObservedOnly && settings.CtMissingOnly) {
            AnsiConsole.MarkupLine("[red]--ct-observed-only cannot be combined with --ct-missing-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainCompleteOnly && settings.ChainIncompleteOnly) {
            AnsiConsole.MarkupLine("[red]--chain-complete-only cannot be combined with --chain-incomplete-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReachableOnly && settings.UnreachableOnly) {
            AnsiConsole.MarkupLine("[red]--reachable-only cannot be combined with --unreachable-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.HostnameMatchOnly && settings.HostnameMismatchOnly) {
            AnsiConsole.MarkupLine("[red]--hostname-match-only cannot be combined with --hostname-mismatch-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.SelfSignedOnly && settings.CaSignedOnly) {
            AnsiConsole.MarkupLine("[red]--self-signed-only cannot be combined with --ca-signed-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.WeakKeyOnly && settings.StrongKeyOnly) {
            AnsiConsole.MarkupLine("[red]--weak-key-only cannot be combined with --strong-key-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.Sha1SignatureOnly && settings.NonSha1SignatureOnly) {
            AnsiConsole.MarkupLine("[red]--sha1-signature-only cannot be combined with --non-sha1-signature-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ExpiredOnly && settings.NotExpiredOnly) {
            AnsiConsole.MarkupLine("[red]--expired-only cannot be combined with --not-expired-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.NotYetValidOnly && settings.AlreadyValidOnly) {
            AnsiConsole.MarkupLine("[red]--not-yet-valid-only cannot be combined with --already-valid-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.CurrentlyValidOnly && settings.CurrentlyInvalidOnly) {
            AnsiConsole.MarkupLine("[red]--currently-valid-only cannot be combined with --currently-invalid-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysToExpireMin.HasValue && settings.DaysToExpireMax.HasValue && settings.DaysToExpireMin.Value > settings.DaysToExpireMax.Value) {
            AnsiConsole.MarkupLine("[red]--days-to-expire-min cannot be greater than --days-to-expire-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysUntilValidMin.HasValue && settings.DaysUntilValidMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--days-until-valid-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysUntilValidMax.HasValue && settings.DaysUntilValidMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--days-until-valid-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysUntilValidMin.HasValue && settings.DaysUntilValidMax.HasValue && settings.DaysUntilValidMin.Value > settings.DaysUntilValidMax.Value) {
            AnsiConsole.MarkupLine("[red]--days-until-valid-min cannot be greater than --days-until-valid-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.KnownCaOnly && settings.UnknownCaOnly) {
            AnsiConsole.MarkupLine("[red]--known-ca-only cannot be combined with --unknown-ca-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.KnownRootCaOnly && settings.UnknownRootCaOnly) {
            AnsiConsole.MarkupLine("[red]--known-root-ca-only cannot be combined with --unknown-root-ca-only.[/]");
            return Task.FromResult(1);
        }
        var normalizedMinimumSeverity = settings.MinimumSeverity;
        if (!string.IsNullOrWhiteSpace(settings.MinimumSeverity)) {
            if (!CertificateInventoryRiskAnalyzer.TryResolveMinimumSeverity(settings.MinimumSeverity, out _, out var normalized)) {
                AnsiConsole.MarkupLine($"[red]--minimum-severity must be one of: {CertificateInventoryRiskAnalyzer.MinimumSeverityAcceptedValues}.[/]");
                return Task.FromResult(1);
            }

            // Validate early for user-friendly CLI messaging; analyzer validates again for API callers.
            normalizedMinimumSeverity = normalized;
        }
        var normalizedRiskProfile = settings.RiskProfile;
        if (!string.IsNullOrWhiteSpace(settings.RiskProfile)) {
            if (!CertificateInventoryRiskAnalyzer.TryResolveRiskProfile(settings.RiskProfile, out var normalized)) {
                AnsiConsole.MarkupLine($"[red]--risk-profile must be one of: {CertificateInventoryRiskAnalyzer.RiskProfileAcceptedValues}.[/]");
                return Task.FromResult(1);
            }

            normalizedRiskProfile = normalized;
        }

        var cacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var risk = monitor.BuildInventoryRisk(
            sinceUtc: CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc),
            includeNoRisk: settings.IncludeHealthy,
            expiringWithinDays: settings.ExpiringWithinDays,
            criticalExpiringWithinDays: settings.CriticalExpiringWithinDays,
            maxEndpoints: settings.MaxEndpoints,
            minimumSeverity: normalizedMinimumSeverity,
            scoreMin: settings.ScoreMin,
            scoreMax: settings.ScoreMax,
            reasonCountMin: settings.ReasonCountMin,
            reasonCountMax: settings.ReasonCountMax,
            certificateReuseEndpointCountMin: settings.ReuseEndpointCountMin,
            certificateReuseEndpointCountMax: settings.ReuseEndpointCountMax,
            certificateReuseCrossServiceOnly: settings.ReuseCrossServiceOnly ? true : settings.ReuseSingleServiceOnly ? false : null,
            certificateReuseDistinctServiceCountMin: settings.ReuseServiceCountMin,
            certificateReuseDistinctServiceCountMax: settings.ReuseServiceCountMax,
            certificateReuseDistinctPortCountMin: settings.ReusePortCountMin,
            certificateReuseDistinctPortCountMax: settings.ReusePortCountMax,
            certificateReuseCrossPortOnly: settings.ReuseCrossPortOnly ? true : settings.ReuseSinglePortOnly ? false : null,
            riskProfile: normalizedRiskProfile,
            reasonContains: settings.ReasonContains,
            reasonAnyOf: settings.ReasonAnyOf,
            reasonAllOf: settings.ReasonAllOf,
            issuerContains: settings.IssuerContains,
            issuerContainsAnyOf: settings.IssuerContainsAnyOf,
            issuerContainsAllOf: settings.IssuerContainsAllOf,
            rootIssuerContains: settings.RootIssuerContains,
            rootIssuerContainsAnyOf: settings.RootIssuerContainsAnyOf,
            rootIssuerContainsAllOf: settings.RootIssuerContainsAllOf,
            authorityFamilyEquals: settings.AuthorityFamilyEquals,
            rootAuthorityFamilyEquals: settings.RootAuthorityFamilyEquals,
            ctSourceContains: settings.CtSourceContains,
            ctTemplateErrorContains: settings.CtTemplateErrorContains,
            chainSourceContains: settings.ChainSourceContains,
            thumbprintEquals: settings.ThumbprintEquals,
            rootThumbprintEquals: settings.RootThumbprintEquals,
            serialNumberEquals: settings.SerialNumberEquals,
            hostContains: settings.HostContains,
            serviceEquals: settings.ServiceEquals,
            portEquals: settings.PortEquals,
            chainLengthMin: settings.ChainLengthMin,
            chainLengthMax: settings.ChainLengthMax,
            intermediateCountMin: settings.IntermediateCountMin,
            intermediateCountMax: settings.IntermediateCountMax,
            ctObservedOnly: settings.CtObservedOnly ? true : settings.CtMissingOnly ? false : null,
            chainCompleteOnly: settings.ChainCompleteOnly ? true : settings.ChainIncompleteOnly ? false : null,
            reachableOnly: settings.ReachableOnly ? true : settings.UnreachableOnly ? false : null,
            hostnameMatchOnly: settings.HostnameMatchOnly ? true : settings.HostnameMismatchOnly ? false : null,
            selfSignedOnly: settings.SelfSignedOnly ? true : settings.CaSignedOnly ? false : null,
            weakKeyOnly: settings.WeakKeyOnly ? true : settings.StrongKeyOnly ? false : null,
            sha1SignatureOnly: settings.Sha1SignatureOnly ? true : settings.NonSha1SignatureOnly ? false : null,
            expiredOnly: settings.ExpiredOnly ? true : settings.NotExpiredOnly ? false : null,
            notYetValidOnly: settings.NotYetValidOnly ? true : settings.AlreadyValidOnly ? false : null,
            currentlyValidOnly: settings.CurrentlyValidOnly ? true : settings.CurrentlyInvalidOnly ? false : null,
            daysToExpireMin: settings.DaysToExpireMin,
            daysToExpireMax: settings.DaysToExpireMax,
            daysUntilValidMin: settings.DaysUntilValidMin,
            daysUntilValidMax: settings.DaysUntilValidMax,
            knownAuthorityOnly: settings.KnownCaOnly ? true : settings.UnknownCaOnly ? false : null,
            knownRootAuthorityOnly: settings.KnownRootCaOnly ? true : settings.UnknownRootCaOnly ? false : null,
            authenticationProfileEquals: settings.AuthenticationProfileEquals,
            serverAuthOnly: settings.ServerAuthOnly,
            clientAuthOnly: settings.ClientAuthOnly,
            secureEmailOnly: settings.SecureEmailOnly);

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(risk, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(risk, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(risk, JsonOptions.Default));
            return Task.FromResult(0);
        }

        if (risk.SnapshotCount == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Snapshots", risk.SnapshotCount.ToString());
        summary.AddRow("Endpoints (Total)", risk.EndpointCount.ToString());
        summary.AddRow("Matched Endpoints", risk.MatchedEndpointCount.ToString());
        summary.AddRow("Returned Endpoints", risk.Endpoints.Count.ToString());
        summary.AddRow("Truncated Endpoints", risk.EndpointsTruncatedByMaxEndpoints.ToString());
        summary.AddRow("Critical", risk.CriticalCount.ToString());
        summary.AddRow("High", risk.HighCount.ToString());
        summary.AddRow("Medium", risk.MediumCount.ToString());
        summary.AddRow("Low", risk.LowCount.ToString());
        summary.AddRow("No Risk", risk.NoRiskCount.ToString());
        summary.AddRow("Average Score", risk.AverageScore.ToString("0.00"));
        summary.AddRow("Unique Cert Identities", risk.UniqueCertificateIdentityCount.ToString());
        summary.AddRow("Reused Cert Identities", risk.ReusedCertificateIdentityCount.ToString());
        summary.AddRow("Reused Cert Identities %", risk.ReusedCertificateIdentityPercentage.ToString("0.00"));
        summary.AddRow("Endpoints with Reuse", risk.EndpointsWithReusedCertificateCount.ToString());
        summary.AddRow("Endpoints with Reuse %", risk.EndpointsWithReusedCertificatePercentage.ToString("0.00"));
        summary.AddRow("Cross-Service Reused Certs", risk.CrossServiceReusedCertificateIdentityCount.ToString());
        summary.AddRow("Cross-Service Reused Certs %", risk.CrossServiceReusedCertificateIdentityPercentage.ToString("0.00"));
        summary.AddRow("Cross-Port Reused Certs", risk.CrossPortReusedCertificateIdentityCount.ToString());
        summary.AddRow("Cross-Port Reused Certs %", risk.CrossPortReusedCertificateIdentityPercentage.ToString("0.00"));
        summary.AddRow("Endpoints with Cross-Service Reuse", risk.EndpointsWithCrossServiceReuseCount.ToString());
        summary.AddRow("Endpoints with Cross-Service Reuse %", risk.EndpointsWithCrossServiceReusePercentage.ToString("0.00"));
        summary.AddRow("Endpoints with Cross-Port Reuse", risk.EndpointsWithCrossPortReuseCount.ToString());
        summary.AddRow("Endpoints with Cross-Port Reuse %", risk.EndpointsWithCrossPortReusePercentage.ToString("0.00"));
        summary.AddRow("Max Reuse Endpoint Count", risk.MaxCertificateReuseEndpointCount.ToString());
        summary.AddRow("Max Reuse Service Spread", risk.MaxCertificateReuseDistinctServiceCount.ToString());
        summary.AddRow("Max Reuse Port Spread", risk.MaxCertificateReuseDistinctPortCount.ToString());
        AnsiConsole.Write(summary);

        if (risk.ReasonCounts.Count > 0) {
            var reasons = new Table().Border(TableBorder.Rounded);
            reasons.Title = new TableTitle("Top Risk Reasons");
            reasons.AddColumn("Reason");
            reasons.AddColumn("Count");
            foreach (var reason in risk.ReasonCounts
                         .OrderByDescending(x => x.Value)
                         .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                         .Take(20)) {
                reasons.AddRow(reason.Key, reason.Value.ToString());
            }
            AnsiConsole.Write(reasons);
        }

        if (risk.Endpoints.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No endpoint risk rows to display.[/]");
            return Task.FromResult(0);
        }

        if (risk.Truncated) {
            AnsiConsole.MarkupLine($"[yellow]Endpoint rows truncated by --max-endpoints:[/] {risk.EndpointsTruncatedByMaxEndpoints}");
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Risk Posture");
        rows.AddColumn("Host");
        rows.AddColumn("Port");
        rows.AddColumn("Service");
        rows.AddColumn("Reuse");
        rows.AddColumn("Chain");
        rows.AddColumn("Score");
        rows.AddColumn("Severity");
        rows.AddColumn("Valid From");
        rows.AddColumn("Expiry");
        rows.AddColumn("Auth");
        rows.AddColumn("Issuer");
        rows.AddColumn("Reasons");
        foreach (var endpoint in risk.Endpoints) {
            var validFrom = endpoint.NotBeforeUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            if (endpoint.DaysUntilValid.HasValue && endpoint.DaysUntilValid.Value > 0) {
                validFrom = $"{validFrom} (in {endpoint.DaysUntilValid.Value}d)";
            }

            var expiry = endpoint.NotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            if (endpoint.DaysToExpire.HasValue) {
                expiry = $"{expiry} ({endpoint.DaysToExpire.Value}d)";
            }

            var chain = endpoint.ChainLength > 0
                ? $"{endpoint.ChainLength}/{endpoint.IntermediateCount}"
                : "-";
            var reuse = $"{endpoint.CertificateReuseEndpointCount}ep/{endpoint.CertificateReuseDistinctServiceCount}svc/{endpoint.CertificateReuseDistinctPortCount}prt";
            var auth = BuildAuthSummary(endpoint);
            var reasons = endpoint.Reasons.Count > 0 ? string.Join(",", endpoint.Reasons) : "-";
            rows.AddRow(
                endpoint.Host,
                endpoint.Port.ToString(),
                endpoint.Service,
                reuse,
                chain,
                endpoint.Score.ToString(),
                endpoint.Severity,
                validFrom,
                expiry,
                auth,
                endpoint.Issuer,
                reasons);
        }
        AnsiConsole.Write(rows);
        AnsiConsole.MarkupLine("[grey]Auth flags: S=ServerAuth, C=ClientAuth, E=SecureEmail.[/]");

        return Task.FromResult(0);
    }

    private static void WriteCsv(CertificateInventoryRiskSummary risk, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("Host,Port,Service,Score,Severity,Reasons,CertificateThumbprint,CertificateRootThumbprint,CertificateSerialNumber,Issuer,RootIssuer,AuthorityFamily,RootAuthorityFamily,NotBeforeUtc,NotAfterUtc,DaysUntilValid,DaysToExpire,Valid,Expired,NotYetValid,ChainComplete,ChainLength,IntermediateCount,HostnameMatch,IsReachable,IsSelfSigned,IsKnownCertificateAuthority,IsKnownRootCertificateAuthority,CertificateReuseEndpointCount,CertificateReuseDistinctServiceCount,CertificateReuseDistinctPortCount,AllowsServerAuthentication,AllowsClientAuthentication,AllowsSecureEmail,AuthenticationProfile,ChainSource,ChainSources,CtDiscoverySources,CtTemplateFormatErrors,WeakKey,Sha1Signature,PresentInCtLogs");
        foreach (var endpoint in risk.Endpoints) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Host));
            sb.Append(',');
            sb.Append(endpoint.Port);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Service));
            sb.Append(',');
            sb.Append(endpoint.Score);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Severity));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.Reasons)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CertificateThumbprint));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CertificateRootThumbprint));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CertificateSerialNumber));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Issuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.RootIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.AuthorityFamily));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.RootAuthorityFamily));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.NotBeforeUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.NotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(endpoint.DaysUntilValid?.ToString() ?? string.Empty);
            sb.Append(',');
            sb.Append(endpoint.DaysToExpire?.ToString() ?? string.Empty);
            sb.Append(',');
            sb.Append(endpoint.Valid ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.Expired ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.NotYetValid ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.ChainComplete ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.ChainLength);
            sb.Append(',');
            sb.Append(endpoint.IntermediateCount);
            sb.Append(',');
            sb.Append(endpoint.HostnameMatch ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.IsReachable ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.IsSelfSigned ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.IsKnownCertificateAuthority ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.IsKnownRootCertificateAuthority ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.CertificateReuseEndpointCount);
            sb.Append(',');
            sb.Append(endpoint.CertificateReuseDistinctServiceCount);
            sb.Append(',');
            sb.Append(endpoint.CertificateReuseDistinctPortCount);
            sb.Append(',');
            sb.Append(endpoint.AllowsServerAuthentication ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.AllowsClientAuthentication ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.AllowsSecureEmail ? "true" : "false");
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.AuthenticationProfile));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.ChainSource));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.ChainSources)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.CtDiscoverySources)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.CtTemplateFormatErrors)));
            sb.Append(',');
            sb.Append(endpoint.WeakKey ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.Sha1Signature ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.PresentInCtLogs ? "true" : "false");
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventoryRiskSummary risk, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        foreach (var endpoint in risk.Endpoints) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(endpoint));
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static string BuildAuthSummary(CertificateInventoryEndpointRisk endpoint) {
        var flags = string.Empty;
        if (endpoint.AllowsServerAuthentication) {
            flags += "S";
        }
        if (endpoint.AllowsClientAuthentication) {
            flags += "C";
        }
        if (endpoint.AllowsSecureEmail) {
            flags += "E";
        }

        if (flags.Length == 0) {
            flags = "-";
        }

        if (string.IsNullOrWhiteSpace(endpoint.AuthenticationProfile)) {
            return flags;
        }

        return $"{flags} ({endpoint.AuthenticationProfile})";
    }
}


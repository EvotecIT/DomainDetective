using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Providers.Endpoint;

/// <summary>Versioned collection of reusable endpoint attribution rules.</summary>
public sealed class EndpointAttributionCatalog {
    /// <summary>Version of the built-in catalog shape and point-in-time seed data.</summary>
    public const string BuiltInVersion = "2026-09-01";

    /// <summary>Catalog version persisted with detection results.</summary>
    public string Version { get; set; } = BuiltInVersion;

    /// <summary>Rules evaluated by the detector.</summary>
    public List<EndpointAttributionRule> Rules { get; } = new();

    /// <summary>Creates the built-in provider and managed-service catalog.</summary>
    public static EndpointAttributionCatalog CreateDefault() {
        var catalog = new EndpointAttributionCatalog();
        catalog.Rules.Add(CreateAzureFrontDoorRule());
        catalog.Rules.Add(CreateAzureCdnRule());
        catalog.Rules.Add(CreateAzureTrafficManagerRule());
        catalog.Rules.Add(CreateNameShieldRule());
        catalog.Rules.Add(CreateMicrosoft365Rule());
        catalog.Rules.Add(CreateCpanelCandidateRule());
        return catalog;
    }

    /// <summary>Adds or replaces a rule with the same rule identifier.</summary>
    public void AddOrReplace(EndpointAttributionRule rule) {
        if (rule == null) {
            throw new ArgumentNullException(nameof(rule));
        }
        ValidateAndCompileRule(rule, nameof(rule));

        Rules.RemoveAll(existing => existing != null &&
            string.Equals(existing.RuleId?.Trim(), rule.RuleId, StringComparison.OrdinalIgnoreCase));
        Rules.Add(rule);
    }

    internal static IReadOnlyList<IpCidrRange> ValidateAndCompileRule(
        EndpointAttributionRule rule,
        string? parameterName = null) {
        if (rule == null) {
            throw new ArgumentNullException(parameterName ?? nameof(rule));
        }
        if (string.IsNullOrWhiteSpace(rule.RuleId)) {
            throw new ArgumentException("An attribution rule requires a stable RuleId.", parameterName ?? nameof(rule));
        }
        rule.RuleId = rule.RuleId.Trim();
        if (string.IsNullOrWhiteSpace(rule.RuleVersion)) {
            throw new ArgumentException(
                $"Endpoint attribution rule '{rule.RuleId}' requires a stable RuleVersion.",
                parameterName ?? nameof(rule));
        }
        rule.RuleVersion = rule.RuleVersion.Trim();
        if (string.IsNullOrWhiteSpace(rule.ProviderId)) {
            throw new ArgumentException(
                $"Endpoint attribution rule '{rule.RuleId}' requires a stable ProviderId.",
                parameterName ?? nameof(rule));
        }
        rule.ProviderId = rule.ProviderId.Trim();
        if (string.IsNullOrWhiteSpace(rule.ServiceId)) {
            throw new ArgumentException(
                $"Endpoint attribution rule '{rule.RuleId}' requires a stable ServiceId.",
                parameterName ?? nameof(rule));
        }
        rule.ServiceId = rule.ServiceId.Trim();
        foreach (EndpointAttributionSignalKind signalKind in rule.IpAddressPrimaryCorroboratingSignals) {
            if (!Enum.IsDefined(typeof(EndpointAttributionSignalKind), signalKind)) {
                throw new ArgumentOutOfRangeException(
                    parameterName ?? nameof(rule),
                    signalKind,
                    $"Endpoint attribution rule '{rule.RuleId}' contains undefined corroborating signal kind '{(int)signalKind}'.");
            }
        }
        if (rule.IpAddressPrimaryCorroboratingSignals.Contains(EndpointAttributionSignalKind.IpAddress)) {
            throw new ArgumentException(
                $"Endpoint attribution rule '{rule.RuleId}' cannot use IpAddress as its own corroborating signal.",
                parameterName ?? nameof(rule));
        }
        if (double.IsNaN(rule.MinimumScore) ||
            double.IsInfinity(rule.MinimumScore) ||
            rule.MinimumScore < 0d ||
            rule.MinimumScore > 1d) {
            throw new ArgumentOutOfRangeException(
                parameterName ?? nameof(rule),
                rule.MinimumScore,
                $"Endpoint attribution rule '{rule.RuleId}' requires MinimumScore between 0 and 1.");
        }
        foreach (int port in rule.ApplicablePorts) {
            if (port < 1 || port > 65535) {
                throw new ArgumentOutOfRangeException(
                    parameterName ?? nameof(rule),
                    port,
                    $"Endpoint attribution rule '{rule.RuleId}' contains invalid applicable port '{port}'. " +
                    "Ports must be between 1 and 65535.");
            }
        }
        var normalizedServices = new List<string>(rule.ApplicableServices.Count);
        var uniqueServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string service in rule.ApplicableServices) {
            if (string.IsNullOrWhiteSpace(service)) {
                throw new ArgumentException(
                    $"Endpoint attribution rule '{rule.RuleId}' contains an empty applicable service.",
                    parameterName ?? nameof(rule));
            }
            string normalizedService = service.Trim();
            if (uniqueServices.Add(normalizedService)) {
                normalizedServices.Add(normalizedService);
            }
        }
        rule.ApplicableServices.Clear();
        rule.ApplicableServices.AddRange(normalizedServices);
        NormalizeHostSuffixMatchers(rule.CnameSuffixes);
        NormalizeHostSuffixMatchers(rule.RedirectTargetSuffixes);
        NormalizeHostSuffixMatchers(rule.ReverseDnsSuffixes);
        var normalizedAutonomousSystems = new List<string>(rule.AutonomousSystemNumbers.Count);
        var uniqueAutonomousSystems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string autonomousSystem in rule.AutonomousSystemNumbers) {
            if (string.IsNullOrWhiteSpace(autonomousSystem)) {
                continue;
            }
            if (!TryNormalizeAutonomousSystemNumber(autonomousSystem, out string normalizedAutonomousSystem)) {
                throw new ArgumentException(
                    $"Endpoint attribution rule '{rule.RuleId}' contains invalid autonomous system number '{autonomousSystem}'.",
                    parameterName ?? nameof(rule));
            }
            if (uniqueAutonomousSystems.Add(normalizedAutonomousSystem)) {
                normalizedAutonomousSystems.Add(normalizedAutonomousSystem);
            }
        }
        rule.AutonomousSystemNumbers.Clear();
        rule.AutonomousSystemNumbers.AddRange(normalizedAutonomousSystems);
        if (!HasUsableEvidenceMatcher(rule)) {
            throw new ArgumentException(
                $"Endpoint attribution rule '{rule.RuleId}' requires at least one usable evidence matcher.",
                parameterName ?? nameof(rule));
        }

        var compiledPrefixes = new List<IpCidrRange>(rule.IpAddressPrefixes.Count);
        foreach (string prefix in rule.IpAddressPrefixes) {
            if (!IpCidrRange.TryParse(prefix, out IpCidrRange compiledPrefix)) {
                throw new FormatException(
                    $"Endpoint attribution rule '{rule.RuleId}' contains invalid IP prefix '{prefix}'.");
            }
            compiledPrefixes.Add(compiledPrefix);
        }
        return compiledPrefixes;
    }

    internal static bool TryNormalizeAutonomousSystemNumber(string? value, out string normalized) {
        normalized = string.Empty;
        string candidate = (value ?? string.Empty).Trim();
        if (candidate.StartsWith("AS", StringComparison.OrdinalIgnoreCase)) {
            candidate = candidate.Substring(2).Trim();
        }
        if (!uint.TryParse(
                candidate,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out uint number) ||
            number == 0) {
            return false;
        }
        normalized = number.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return true;
    }

    private static bool HasUsableEvidenceMatcher(EndpointAttributionRule rule) =>
        HasText(rule.HostnamePrefixes) ||
        HasText(rule.CnameSuffixes) ||
        HasText(rule.IpAddressPrefixes) ||
        HasText(rule.AzureServiceTagNames) ||
        HasText(rule.CertificateIssuerContains) ||
        HasText(rule.RedirectTargetSuffixes) ||
        HasText(rule.ReverseDnsSuffixes) ||
        HasText(rule.AutonomousSystemNumbers);

    private static bool HasText(IEnumerable<string> values) =>
        values.Any(value => !string.IsNullOrWhiteSpace(value));

    private static void NormalizeHostSuffixMatchers(List<string> values) {
        var normalizedValues = new List<string>(values.Count);
        var uniqueValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string value in values) {
            string normalized = NormalizeHostSuffixMatcher(value);
            if (normalized.Length > 0 && uniqueValues.Add(normalized)) {
                normalizedValues.Add(normalized);
            }
        }
        values.Clear();
        values.AddRange(normalizedValues);
    }

    internal static string NormalizeHostSuffixMatcher(string? value) =>
        (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    private static EndpointAttributionRule CreateAzureFrontDoorRule() {
        var rule = CreateRule(
            "microsoft",
            "azure-front-door",
            "Azure Front Door",
            "builtin.microsoft.azure-front-door");
        rule.CnameSuffixes.Add("azurefd.net");
        rule.RedirectTargetSuffixes.Add("azurefd.net");
        rule.AzureServiceTagNames.Add("AzureFrontDoor.Frontend");
        rule.CertificateIssuerContains.Add("DigiCert");
        rule.CertificateIssuerContains.Add("Microsoft");
        AddHttpServices(rule);
        return rule;
    }

    private static EndpointAttributionRule CreateAzureCdnRule() {
        var rule = CreateRule(
            "microsoft",
            "azure-cdn",
            "Azure CDN",
            "builtin.microsoft.azure-cdn");
        rule.CnameSuffixes.Add("azureedge.net");
        rule.RedirectTargetSuffixes.Add("azureedge.net");
        rule.CertificateIssuerContains.Add("DigiCert");
        rule.CertificateIssuerContains.Add("Microsoft");
        AddHttpServices(rule);
        return rule;
    }

    private static EndpointAttributionRule CreateAzureTrafficManagerRule() {
        var rule = CreateRule(
            "microsoft",
            "azure-traffic-manager",
            "Azure Traffic Manager",
            "builtin.microsoft.azure-traffic-manager");
        rule.CnameSuffixes.Add("trafficmanager.net");
        rule.RedirectTargetSuffixes.Add("trafficmanager.net");
        rule.CertificateIssuerContains.Add("DigiCert");
        rule.CertificateIssuerContains.Add("Microsoft");
        AddHttpServices(rule);
        return rule;
    }

    private static EndpointAttributionRule CreateNameShieldRule() {
        var rule = CreateRule(
            "nameshield",
            "redirection",
            "NameShield Redirection Service",
            "builtin.nameshield.redirection");
        rule.Source = "Versioned public endpoint seed; validate against current provider data before enforcement.";
        rule.CnameSuffixes.AddRange(new[] { "cdn.perf1.com", "perf1.com", "perf1.fr" });
        rule.RedirectTargetSuffixes.AddRange(new[] { "cdn.perf1.com", "perf1.com", "perf1.fr" });
        rule.IpAddressPrefixes.AddRange(new[] {
            "81.92.94.54/32",
            "81.92.95.55/32",
            "152.89.172.56/32",
            "2a01:c8:101::55/128",
            "2a01:c8:100::54/128",
            "2a09:35c0:102::56/128"
        });
        rule.CertificateIssuerContains.Add("DigiCert");
        rule.RequireCorroborationForIpAddressPrimary = true;
        rule.IpAddressPrimaryCorroboratingSignals.Add(EndpointAttributionSignalKind.Cname);
        rule.IpAddressPrimaryCorroboratingSignals.Add(EndpointAttributionSignalKind.RedirectTarget);
        AddHttpServices(rule);
        return rule;
    }

    private static EndpointAttributionRule CreateMicrosoft365Rule() {
        var rule = CreateRule(
            "microsoft",
            "microsoft-365-service",
            "Microsoft 365 Managed Service",
            "builtin.microsoft.microsoft-365-service");
        rule.CnameSuffixes.AddRange(new[] {
            "outlook.com",
            "office.com",
            "office365.com",
            "online.lync.com",
            "microsoftonline.com",
            "microsoftonline-p.net"
        });
        rule.CertificateIssuerContains.Add("Microsoft");
        rule.ApplicableServices.AddRange(new[] { "HTTPS", "HTTPS-Alt", "SMTP-STARTTLS", "SMTP-SUBMISSION-STARTTLS", "IMAPS", "POP3S" });
        return rule;
    }

    private static EndpointAttributionRule CreateCpanelCandidateRule() {
        var rule = CreateRule(
            "cpanel",
            "generated-service-hostname",
            "cPanel/WHM Generated Service Hostname Candidate",
            "builtin.cpanel.generated-service-hostname");
        rule.HostnamePrefixes.AddRange(new[] { "cpanel.", "cpcalendars.", "webdisk.", "whm." });
        rule.MinimumScore = 0.65;
        return rule;
    }

    private static EndpointAttributionRule CreateRule(
        string providerId,
        string serviceId,
        string displayName,
        string ruleId) {
        return new EndpointAttributionRule {
            ProviderId = providerId,
            ServiceId = serviceId,
            DisplayName = displayName,
            RuleId = ruleId,
            RuleVersion = BuiltInVersion,
            Source = "DomainDetective built-in attribution catalog"
        };
    }

    private static void AddHttpServices(EndpointAttributionRule rule) {
        rule.ApplicableServices.Add("HTTPS");
        rule.ApplicableServices.Add("HTTPS-Alt");
    }
}

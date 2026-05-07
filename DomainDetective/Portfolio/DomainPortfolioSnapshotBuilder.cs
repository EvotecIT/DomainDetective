using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;

namespace DomainDetective;

/// <summary>
/// Builds storage-free portfolio snapshots from DomainDetective analysis results.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public static class DomainPortfolioSnapshotBuilder {
    private const char CollectionEscape = '\\';
    private const char CollectionSeparator = '|';

    private static readonly ConcurrentDictionary<Type, PropertyInfo[]> PropertyCache = new();

    private static readonly HashSet<string> IgnoredPropertyNames = new(StringComparer.OrdinalIgnoreCase) {
        "Assessments",
        "Recommendations",
        "DnsConfiguration",
        "QueryDnsOverride",
        "Logger"
    };

    /// <summary>
    /// Builds a portfolio snapshot from a populated <see cref="DomainHealthCheck"/>.
    /// </summary>
    /// <param name="subject">Domain or host represented by the snapshot.</param>
    /// <param name="healthCheck">Health check that contains analysis results.</param>
    /// <param name="checks">Optional subset of checks to include.</param>
    /// <param name="capturedAtUtc">Optional capture time. Defaults to the current UTC time.</param>
    /// <returns>Storage-free portfolio snapshot.</returns>
    public static DomainPortfolioSnapshot Build(
        string subject,
        DomainHealthCheck healthCheck,
        IEnumerable<HealthCheckType>? checks = null,
        DateTimeOffset? capturedAtUtc = null) {
        if (string.IsNullOrWhiteSpace(subject)) throw new ArgumentException("Subject is required.", nameof(subject));
        if (healthCheck == null) throw new ArgumentNullException(nameof(healthCheck));

        var selected = checks != null
            ? new HashSet<HealthCheckType>(checks)
            : null;

        var snapshot = new DomainPortfolioSnapshot {
            Subject = subject.Trim(),
            CapturedAtUtc = capturedAtUtc?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
            EvaluatorVersion = typeof(DomainHealthCheck).Assembly.GetName().Version?.ToString() ?? string.Empty
        };

        var analyses = healthCheck.GetAnalysisMap()
            .Where(item => selected == null || selected.Contains(item.Key))
            .Where(static item => item.Value != null)
            .OrderBy(static item => item.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Select(static pair => BuildSection(pair.Key, pair.Value!))
            .Where(static section => section.Facts.Count != 0 || section.Assessments.Count != 0);

        foreach (var section in analyses) {
            snapshot.Sections.Add(section);
            snapshot.Assessments.AddRange(section.Assessments);
        }

        snapshot.Summaries = BuildSummaries(snapshot);
        return snapshot;
    }

    /// <summary>
    /// Builds typed high-value summary projections from snapshot sections.
    /// </summary>
    /// <param name="snapshot">Snapshot with populated sections.</param>
    /// <returns>Typed summary projections.</returns>
    public static DomainPortfolioSummaries BuildSummaries(DomainPortfolioSnapshot snapshot) {
        if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));

        var facts = new SnapshotFactLookup(snapshot);
        return new DomainPortfolioSummaries {
            Registration = BuildRegistrationSummary(snapshot, facts),
            Dns = BuildDnsSummary(facts),
            Certificate = BuildCertificateSummary(snapshot, facts),
            Mail = BuildMailSummary(facts),
            Website = BuildWebsiteSummary(facts)
        };
    }

    /// <summary>
    /// Builds a portfolio snapshot from this health check.
    /// </summary>
    /// <param name="healthCheck">Health check that contains analysis results.</param>
    /// <param name="subject">Domain or host represented by the snapshot.</param>
    /// <param name="checks">Optional subset of checks to include.</param>
    /// <param name="capturedAtUtc">Optional capture time. Defaults to the current UTC time.</param>
    /// <returns>Storage-free portfolio snapshot.</returns>
    public static DomainPortfolioSnapshot ToPortfolioSnapshot(
        this DomainHealthCheck healthCheck,
        string subject,
        IEnumerable<HealthCheckType>? checks = null,
        DateTimeOffset? capturedAtUtc = null)
        => Build(subject, healthCheck, checks, capturedAtUtc);

    private static DomainPortfolioSection BuildSection(HealthCheckType check, object analysis) {
        var assessments = analysis is IHasAssessments hasAssessments
            ? hasAssessments.Assessments.Where(static item => item != null).ToList()
            : new List<Assessment>();

        var section = new DomainPortfolioSection {
            Key = check.ToString(),
            DisplayName = ResolveDisplayName(check),
            Area = ResolveArea(check),
            Assessments = assessments
        };

        section.WarningCount = assessments.Count(static item => item.Severity == AssessmentSeverity.Warning);
        section.ErrorCount = assessments.Count(static item => item.Severity == AssessmentSeverity.Error);
        section.Status = section.ErrorCount > 0 ? "Error" : section.WarningCount > 0 ? "Warning" : "OK";
        section.Facts.AddRange(ExtractFacts(analysis));
        return section;
    }

    private static string ResolveDisplayName(HealthCheckType check) {
        var description = CheckDescriptions.Get(check);
        var summary = description?.Summary;
        if (!string.IsNullOrWhiteSpace(summary)) return summary!.Trim();
        return check.ToString();
    }

    internal static string ResolveArea(HealthCheckType check)
        => check switch {
            HealthCheckType.NS or
            HealthCheckType.DELEGATION or
            HealthCheckType.SOA or
            HealthCheckType.EDNSSUPPORT or
            HealthCheckType.REVERSEDNS or
            HealthCheckType.FCRDNS or
            HealthCheckType.DNSSEC or
            HealthCheckType.CAA or
            HealthCheckType.TTL or
            HealthCheckType.WILDCARDDNS or
            HealthCheckType.ZONETRANSFER or
            HealthCheckType.DNSHEALTH or
            HealthCheckType.APEXADDRESS or
            HealthCheckType.SUBDOMAINS or
            HealthCheckType.DNSINVENTORY or
            HealthCheckType.DNSTRACE or
            HealthCheckType.DNSPROPAGATION or
            HealthCheckType.DNSAMPLIFICATION or
            HealthCheckType.DNSOVERTLS => "DNS",
            HealthCheckType.MX or
            HealthCheckType.SPF or
            HealthCheckType.DKIM or
            HealthCheckType.DMARC or
            HealthCheckType.BIMI or
            HealthCheckType.MTASTS or
            HealthCheckType.TLSRPT or
            HealthCheckType.STARTTLS or
            HealthCheckType.SMTPTLS or
            HealthCheckType.IMAPTLS or
            HealthCheckType.POP3TLS or
            HealthCheckType.SMTPAUTH or
            HealthCheckType.SMTPBANNER or
            HealthCheckType.MAILLATENCY or
            HealthCheckType.SMIMEA or
            HealthCheckType.AUTODISCOVER or
            HealthCheckType.OPENRELAY or
            HealthCheckType.SPFFLATTENED or
            HealthCheckType.MAILCLASSIFICATION or
            HealthCheckType.ARC => "Mail",
            HealthCheckType.RDAP or
            HealthCheckType.WHOIS => "Registration",
            HealthCheckType.HTTP or
            HealthCheckType.CERT or
            HealthCheckType.DANE or
            HealthCheckType.SECURITYTXT or
            HealthCheckType.ROBOTS or
            HealthCheckType.HPKP or
            HealthCheckType.DIRECTORYEXPOSURE or
            HealthCheckType.WEBSITE or
            HealthCheckType.CTTIMELINE => "Web",
            HealthCheckType.IDENTITYPROVIDER or
            HealthCheckType.MICROSOFT365 => "Identity",
            HealthCheckType.RPKI or
            HealthCheckType.DNSBL or
            HealthCheckType.OPENRESOLVER or
            HealthCheckType.DANGLINGCNAME or
            HealthCheckType.SNMP or
            HealthCheckType.NTP or
            HealthCheckType.TYPOSQUATTING or
            HealthCheckType.THREATINTEL or
            HealthCheckType.THREATFEED or
            HealthCheckType.IPNEIGHBOR or
            HealthCheckType.IPENRICHMENT or
            HealthCheckType.PORTSCAN or
            HealthCheckType.PORTAVAILABILITY or
            HealthCheckType.DNSTUNNELING or
            HealthCheckType.FLATTENINGSERVICE or
            HealthCheckType.CONTACT => "Security",
            HealthCheckType.MESSAGEHEADER => "Mail",
            _ => "General"
        };

    internal static IEnumerable<DomainPortfolioFact> ExtractFacts(object analysis) {
        var properties = PropertyCache.GetOrAdd(
            analysis.GetType(),
            static type => type.GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Where(static property => property.GetMethod != null && property.GetIndexParameters().Length == 0)
                .OrderBy(static property => property.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray());

        return properties
            .Where(static property => !IgnoredPropertyNames.Contains(property.Name))
            .Select(property => TryExtractFact(property, analysis))
            .Where(static fact => fact != null)
            .Select(static fact => fact!);
    }

    private static DomainPortfolioFact? TryExtractFact(PropertyInfo property, object analysis) {
        if (!TryRead(property, analysis, out var value)) {
            return null;
        }

        if (!TryFormat(value, out var formatted, out var kind)) {
            return null;
        }

        return new DomainPortfolioFact {
            Key = property.Name,
            Label = ToDisplayLabel(property.Name),
            Value = formatted,
            Kind = kind
        };
    }

    private static bool TryRead(PropertyInfo property, object instance, out object value) {
        try {
            value = property.GetValue(instance)!;
            return value != null;
        } catch (TargetInvocationException) {
            value = null!;
            return false;
        } catch (InvalidOperationException) {
            value = null!;
            return false;
        }
    }

    private static bool TryFormat(object value, out string formatted, out DomainPortfolioFactKind kind) {
        formatted = string.Empty;
        kind = DomainPortfolioFactKind.String;

        var type = Nullable.GetUnderlyingType(value.GetType()) ?? value.GetType();
        if (type == typeof(string)) {
            formatted = ((string)value).Trim();
            kind = DomainPortfolioFactKind.String;
            return formatted.Length > 0;
        }

        if (type == typeof(bool)) {
            formatted = ((bool)value) ? "true" : "false";
            kind = DomainPortfolioFactKind.Boolean;
            return true;
        }

        if (type.IsEnum) {
            formatted = value.ToString() ?? string.Empty;
            kind = DomainPortfolioFactKind.String;
            return formatted.Length > 0;
        }

        if (IsNumeric(type)) {
            formatted = Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
            kind = DomainPortfolioFactKind.Number;
            return formatted.Length > 0;
        }

        if (type == typeof(DateTime)) {
            var dateTime = NormalizeDateTime((DateTime)value);
            if (dateTime == DateTime.MinValue) {
                return false;
            }

            formatted = dateTime.ToString("O", CultureInfo.InvariantCulture);
            kind = DomainPortfolioFactKind.DateTime;
            return true;
        }

        if (type == typeof(DateTimeOffset)) {
            var dateTimeOffset = ((DateTimeOffset)value).ToUniversalTime();
            if (dateTimeOffset == DateTimeOffset.MinValue) {
                return false;
            }

            formatted = dateTimeOffset.ToString("O", CultureInfo.InvariantCulture);
            kind = DomainPortfolioFactKind.DateTime;
            return true;
        }

        if (type == typeof(TimeSpan)) {
            var duration = (TimeSpan)value;
            if (duration == TimeSpan.Zero) {
                return false;
            }

            formatted = duration.ToString("c", CultureInfo.InvariantCulture);
            kind = DomainPortfolioFactKind.Duration;
            return true;
        }

        if (value is Uri uri) {
            formatted = uri.ToString();
            kind = DomainPortfolioFactKind.String;
            return formatted.Length > 0;
        }

        if (value is IEnumerable enumerable && value is not string) {
            var items = new List<string>();
            foreach (var item in enumerable) {
                if (item == null) continue;
                if (!TryFormatScalarCollectionItem(item, out var itemValue)) continue;
                if (!string.IsNullOrWhiteSpace(itemValue)) items.Add(itemValue);
            }

            if (items.Count == 0) {
                formatted = string.Empty;
                return false;
            }

            formatted = string.Join("|", items
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .Select(EscapeCollectionItem));
            kind = DomainPortfolioFactKind.Collection;
            return true;
        }

        formatted = string.Empty;
        kind = DomainPortfolioFactKind.String;
        return false;
    }

    private static bool TryFormatScalarCollectionItem(object item, out string value) {
        var type = Nullable.GetUnderlyingType(item.GetType()) ?? item.GetType();
        if (type == typeof(string)) {
            value = ((string)item).Trim();
            return true;
        }

        if (type == typeof(bool)) {
            value = ((bool)item) ? "true" : "false";
            return true;
        }

        if (type.IsEnum || IsNumeric(type)) {
            value = Convert.ToString(item, CultureInfo.InvariantCulture) ?? string.Empty;
            return true;
        }

        if (type == typeof(DateTime)) {
            var dateTime = NormalizeDateTime((DateTime)item);
            if (dateTime == DateTime.MinValue) {
                value = string.Empty;
                return false;
            }

            value = dateTime.ToString("O", CultureInfo.InvariantCulture);
            return true;
        }

        if (type == typeof(DateTimeOffset)) {
            var dateTimeOffset = ((DateTimeOffset)item).ToUniversalTime();
            if (dateTimeOffset == DateTimeOffset.MinValue) {
                value = string.Empty;
                return false;
            }

            value = dateTimeOffset.ToString("O", CultureInfo.InvariantCulture);
            return true;
        }

        if (type == typeof(TimeSpan)) {
            var duration = (TimeSpan)item;
            if (duration == TimeSpan.Zero) {
                value = string.Empty;
                return false;
            }

            value = duration.ToString("c", CultureInfo.InvariantCulture);
            return true;
        }

        if (item is Uri uri) {
            value = uri.ToString();
            return value.Length > 0;
        }

        value = string.Empty;
        return false;
    }

    private static string EscapeCollectionItem(string value) {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value) {
            if (character == CollectionEscape || character == CollectionSeparator) {
                builder.Append(CollectionEscape);
            }

            builder.Append(character);
        }

        return builder.ToString();
    }

    private static List<string> SplitCollectionValue(string value) {
        var items = new List<string>();
        var builder = new StringBuilder(value.Length);
        var escaped = false;

        foreach (var character in value) {
            if (escaped) {
                builder.Append(character);
                escaped = false;
                continue;
            }

            if (character == CollectionEscape) {
                escaped = true;
                continue;
            }

            if (character == CollectionSeparator) {
                AddCollectionValue(items, builder);
                continue;
            }

            builder.Append(character);
        }

        if (escaped) {
            builder.Append(CollectionEscape);
        }

        AddCollectionValue(items, builder);
        return items;
    }

    private static void AddCollectionValue(List<string> items, StringBuilder builder) {
        var item = builder.ToString().Trim();
        if (item.Length > 0) {
            items.Add(item);
        }

        builder.Clear();
    }

    private static DateTime NormalizeDateTime(DateTime value) {
        if (value == DateTime.MinValue) {
            return DateTime.MinValue;
        }

        return value.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(value, DateTimeKind.Utc)
            : value.ToUniversalTime();
    }

    private static bool IsNumeric(Type type)
        => type == typeof(byte) ||
           type == typeof(sbyte) ||
           type == typeof(short) ||
           type == typeof(ushort) ||
           type == typeof(int) ||
           type == typeof(uint) ||
           type == typeof(long) ||
           type == typeof(ulong) ||
           type == typeof(float) ||
           type == typeof(double) ||
           type == typeof(decimal);

    internal static string ToDisplayLabel(string key) {
        if (string.IsNullOrWhiteSpace(key)) return string.Empty;

        var builder = new StringBuilder(key.Length + 8);
        for (var i = 0; i < key.Length; i++) {
            var current = key[i];
            if (current == '_' || current == '-') {
                AppendSpace(builder);
                continue;
            }

            if (builder.Length > 0 && char.IsUpper(current)) {
                var previous = key[i - 1];
                var next = i + 1 < key.Length ? key[i + 1] : '\0';
                if (char.IsLower(previous) ||
                    char.IsDigit(previous) && !char.IsDigit(next) ||
                    char.IsUpper(previous) && char.IsLower(next) && HasAcronymPrefix(key, i)) {
                    AppendSpace(builder);
                }
            }

            builder.Append(current);
        }

        return builder.ToString().Trim();
    }

    private static bool HasAcronymPrefix(string value, int index) {
        var uppercaseCount = 0;
        for (var i = index - 1; i >= 0 && char.IsUpper(value[i]); i--) {
            uppercaseCount++;
        }

        return uppercaseCount >= 2;
    }

    private static void AppendSpace(StringBuilder builder) {
        if (builder.Length == 0) return;
        if (builder[builder.Length - 1] == ' ') return;
        builder.Append(' ');
    }

    private static DomainRegistrationPortfolioSummary BuildRegistrationSummary(DomainPortfolioSnapshot snapshot, SnapshotFactLookup facts) {
        var expiresAt = facts.Date("WHOIS", "Expires", "ExpirationDate", "ExpiryDate", "RegistryExpiryDate", "RegistrarRegistrationExpirationDate")
            ?? facts.Date("RDAP", "ExpiresAt", "ExpirationDate", "ExpiryDate");
        return new DomainRegistrationPortfolioSummary {
            Registrar = facts.String("WHOIS", "Registrar", "RegistrarName")
                ?? facts.String("RDAP", "Registrar", "RegistrarName"),
            CreatedAtUtc = facts.Date("WHOIS", "Created", "CreationDate", "RegisteredAt", "RegistrationDate")
                ?? facts.Date("RDAP", "CreatedAt", "RegistrationDate"),
            UpdatedAtUtc = facts.Date("WHOIS", "Updated", "UpdatedDate", "LastUpdated")
                ?? facts.Date("RDAP", "UpdatedAt", "UpdatedDate"),
            ExpiresAtUtc = expiresAt,
            DaysToExpiry = DaysBetween(snapshot.CapturedAtUtc, expiresAt),
            Statuses = facts.List("WHOIS", "Status", "Statuses", "DomainStatus")
                .Concat(facts.List("RDAP", "Status", "Statuses", "DomainStatus"))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            NameServers = facts.List("WHOIS", "NameServers", "NameServer")
                .Concat(facts.List("RDAP", "NameServers", "NameServer"))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    private static DomainDnsPortfolioSummary BuildDnsSummary(SnapshotFactLookup facts)
        => new() {
            NameServers = facts.List("NS", "NameServers", "Hosts", "Servers"),
            MxHosts = facts.List("MX", "Hosts", "MxHosts", "MailServers", "Exchanges"),
            IPv4Addresses = facts.List("APEXADDRESS", "IPv4Addresses", "Ipv4Addresses", "ARecords", "Addresses"),
            IPv6Addresses = facts.List("APEXADDRESS", "IPv6Addresses", "Ipv6Addresses", "AAAARecords"),
            DnssecEnabled = facts.Bool("DNSSEC", "ChainValid", "IsSigned", "HasDnssec", "DnssecEnabled"),
            CaaPresent = facts.Bool("CAA", "CaaRecordExists", "RecordExists", "HasCaaRecords", "HasRecords")
        };

    private static DomainCertificatePortfolioSummary BuildCertificateSummary(DomainPortfolioSnapshot snapshot, SnapshotFactLookup facts) {
        var notAfter = facts.Date("CERT", "NotAfter", "NotAfterUtc", "ValidTo", "ExpiresAtUtc", "ExpirationDate");
        return new DomainCertificatePortfolioSummary {
            Fingerprint = facts.String("CERT", "Fingerprint", "Thumbprint", "CertificateThumbprint", "Sha256Fingerprint", "Sha1Thumbprint"),
            Subject = facts.String("CERT", "Subject", "SubjectName", "SubjectCommonName"),
            Issuer = facts.String("CERT", "Issuer", "IssuerName", "IssuerCommonName", "IssuerOrganization"),
            NotBeforeUtc = facts.Date("CERT", "NotBefore", "NotBeforeUtc", "ValidFrom"),
            NotAfterUtc = notAfter,
            DaysToExpiry = DaysBetween(snapshot.CapturedAtUtc, notAfter),
            Valid = facts.Bool("CERT", "Valid", "IsValid", "CertificateValid"),
            HostnameMatch = facts.Bool("CERT", "HostnameMatch", "NameMatches", "SubjectMatches")
        };
    }

    private static DomainMailPortfolioSummary BuildMailSummary(SnapshotFactLookup facts)
        => new() {
            MxHosts = facts.List("MX", "Hosts", "MxHosts", "MailServers", "Exchanges"),
            Provider = facts.String("MX", "ProviderPrimary", "MailProvider", "Provider")
                ?? facts.String("DNSINVENTORY", "MailProvider", "MailProviderName"),
            SpfRecord = facts.String("SPF", "SpfRecord", "Record", "RecordValue"),
            SpfAllMechanism = facts.String("SPF", "AllMechanism", "All", "AllMechanismValue"),
            DmarcRecord = facts.String("DMARC", "DmarcRecord", "Record", "RecordValue"),
            DmarcPolicy = facts.String("DMARC", "PolicyShort", "Policy"),
            MtaStsMode = facts.String("MTASTS", "Mode", "PolicyMode"),
            TlsRptRecord = facts.String("TLSRPT", "TlsRptRecord", "Record", "RecordValue")
        };

    private static DomainWebsitePortfolioSummary BuildWebsiteSummary(SnapshotFactLookup facts)
        => new() {
            StatusCode = facts.Int("HTTP", "StatusCode", "ResponseStatusCode", "HttpStatusCode"),
            FinalUrl = facts.String("HTTP", "FinalUrl", "EffectiveUrl", "Url"),
            UsesHttps = facts.Bool("HTTP", "UsesHttps", "IsHttps", "Https"),
            SecurityTxtPresent = facts.Bool("SECURITYTXT", "Present", "Exists", "SecurityTxtExists", "Found"),
            RobotsTxtPresent = facts.Bool("ROBOTS", "Present", "Exists", "RobotsTxtExists", "Found")
        };

    private static int? DaysBetween(DateTimeOffset capturedAtUtc, DateTimeOffset? futureUtc) {
        if (!futureUtc.HasValue) return null;
        return (int)Math.Floor((futureUtc.Value.ToUniversalTime() - capturedAtUtc.ToUniversalTime()).TotalDays);
    }

    private sealed class SnapshotFactLookup {
        private readonly Dictionary<string, Dictionary<string, DomainPortfolioFact>> _sections;

        public SnapshotFactLookup(DomainPortfolioSnapshot snapshot) {
            _sections = (snapshot.Sections ?? new List<DomainPortfolioSection>())
                .Where(static section => section != null && !string.IsNullOrWhiteSpace(section.Key))
                .GroupBy(static section => section.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    static group => group.Key,
                    static group => (group.First().Facts ?? new List<DomainPortfolioFact>())
                        .Where(static fact => fact != null && !string.IsNullOrWhiteSpace(fact.Key))
                        .GroupBy(static fact => fact.Key, StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(static factGroup => factGroup.Key, static factGroup => factGroup.First(), StringComparer.OrdinalIgnoreCase),
                    StringComparer.OrdinalIgnoreCase);
        }

        public string? String(string sectionKey, params string[] keys) {
            return keys
                .Select(key => Value(sectionKey, key))
                .FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value));
        }

        public List<string> List(string sectionKey, params string[] keys) {
            var value = String(sectionKey, keys);
            if (string.IsNullOrWhiteSpace(value)) return new List<string>();
            return SplitCollectionValue(value!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public bool? Bool(string sectionKey, params string[] keys) {
            var value = String(sectionKey, keys);
            if (string.IsNullOrWhiteSpace(value)) return null;
            if (bool.TryParse(value, out var parsed)) return parsed;
            if (string.Equals(value, "1", StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(value, "0", StringComparison.OrdinalIgnoreCase)) return false;
            return null;
        }

        public int? Int(string sectionKey, params string[] keys) {
            var value = String(sectionKey, keys);
            if (string.IsNullOrWhiteSpace(value)) {
                return null;
            }

            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)) return parsed;
            return null;
        }

        public DateTimeOffset? Date(string sectionKey, params string[] keys) {
            var value = String(sectionKey, keys);
            if (string.IsNullOrWhiteSpace(value)) return null;
            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)) {
                return parsed.ToUniversalTime();
            }

            return null;
        }

        private string? Value(string sectionKey, string key) {
            if (!_sections.TryGetValue(sectionKey, out var section)) return null;
            return section.TryGetValue(key, out var fact) ? fact.Value : null;
        }
    }
}

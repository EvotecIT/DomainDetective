using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using DomainDetective.Providers.Endpoint;

namespace DomainDetective.Providers.Hosting;

/// <summary>What kind of service a hosting provider runs on an address.</summary>
public enum HostingKind {
    /// <summary>Not known.</summary>
    Unknown,
    /// <summary>Cloud compute, storage or platform services.</summary>
    Cloud,
    /// <summary>A content delivery network or edge proxy.</summary>
    Cdn
}

/// <summary>How a hosting attribution was made.</summary>
public enum HostingMatchKind {
    /// <summary>The address is inside a range the provider publishes.</summary>
    PublishedRange,
    /// <summary>Only the announcing autonomous system matched a provider network.</summary>
    AutonomousSystem
}

/// <summary>The provider that hosts an address, with the evidence behind it.</summary>
public sealed class HostingAttribution {
    /// <summary>Provider name, for example "Cloudflare" or "Amazon Web Services".</summary>
    public string Provider { get; init; } = string.Empty;
    /// <summary>Cloud or CDN.</summary>
    public HostingKind Kind { get; init; }
    /// <summary>Provider services published for the matching range, for example "EC2" or "CLOUDFRONT".</summary>
    public string Service { get; init; } = string.Empty;
    /// <summary>Provider region published for the matching range, when there is one.</summary>
    public string Region { get; init; } = string.Empty;
    /// <summary>The matching range in CIDR notation, or the autonomous system ("AS13335").</summary>
    public string MatchedBy { get; init; } = string.Empty;
    /// <summary>Whether a published range or only the autonomous system matched.</summary>
    public HostingMatchKind MatchKind { get; init; }
    /// <summary>High for a published range, Medium for an autonomous-system match.</summary>
    public EndpointAttributionConfidence Confidence => MatchKind == HostingMatchKind.PublishedRange
        ? EndpointAttributionConfidence.High
        : EndpointAttributionConfidence.Medium;

    /// <summary>Short text such as "Cloudflare (CDN)" or "Amazon Web Services EC2 eu-west-1".</summary>
    public override string ToString() {
        var parts = new List<string> { Provider };
        if (Service.Length > 0) parts.Add(Service);
        if (Region.Length > 0) parts.Add(Region);
        if (Kind == HostingKind.Cdn && Service.Length == 0) parts.Add("(CDN)");
        return string.Join(" ", parts);
    }
}

/// <summary>
/// Address ranges published by hosting and CDN providers (AWS, Google Cloud, Cloudflare, Fastly and Akamai), bundled
/// as <c>Data/hosting_ranges.tsv.gz</c> and refreshed by <c>Scripts/Update-HostingRanges.ps1</c>. A lookup returns the
/// most specific published range; when none matches, a known provider autonomous system gives a weaker match.
/// </summary>
public sealed class HostingRangeCatalog {
    private const string ResourceName = "DomainDetective.hosting_ranges.tsv.gz";
    private static readonly Lazy<HostingRangeCatalog> BundledCatalog = new(LoadBundled, LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly Dictionary<string, List<RangeEntry>> _ranges;
    private readonly int[] _ipv4Lengths;
    private readonly int[] _ipv6Lengths;
    private readonly Dictionary<int, RangeEntry> _autonomousSystems;

    private sealed class RangeEntry {
        public string Cidr = string.Empty;
        public string Provider = string.Empty;
        public HostingKind Kind;
        public string Service = string.Empty;
        public string Region = string.Empty;
    }

    private HostingRangeCatalog(Dictionary<string, List<RangeEntry>> ranges, int[] ipv4Lengths, int[] ipv6Lengths,
        Dictionary<int, RangeEntry> autonomousSystems, IReadOnlyList<string> notes, int rangeCount) {
        _ranges = ranges;
        _ipv4Lengths = ipv4Lengths;
        _ipv6Lengths = ipv6Lengths;
        _autonomousSystems = autonomousSystems;
        Notes = notes;
        RangeCount = rangeCount;
    }

    /// <summary>The catalog bundled with the library.</summary>
    public static HostingRangeCatalog Default => BundledCatalog.Value;

    /// <summary>Number of published ranges loaded.</summary>
    public int RangeCount { get; }

    /// <summary>Header lines of the data file: generation date and sources.</summary>
    public IReadOnlyList<string> Notes { get; }

    /// <summary>Distinct providers in the catalog.</summary>
    public IReadOnlyList<string> Providers =>
        _ranges.Values.SelectMany(static list => list).Select(static e => e.Provider).Distinct(StringComparer.Ordinal).OrderBy(static p => p, StringComparer.Ordinal).ToArray();

    /// <summary>Loads a catalog from a file in the bundled format (plain text or gzip).</summary>
    /// <param name="path">Path to a <c>.tsv</c> or <c>.tsv.gz</c> file.</param>
    public static HostingRangeCatalog LoadFile(string path) {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
        using FileStream file = File.OpenRead(path);
        Stream stream = path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? new GZipStream(file, CompressionMode.Decompress) : file;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return Parse(reader);
    }

    /// <summary>
    /// Parses the catalog format: one range per line as CIDR, provider, kind, service and region separated by tabs;
    /// lines starting with <c>as</c> map an autonomous system number instead of a range; <c>#</c> starts a note.
    /// </summary>
    /// <param name="reader">Reader over the catalog text.</param>
    public static HostingRangeCatalog Parse(TextReader reader) {
        if (reader == null) throw new ArgumentNullException(nameof(reader));
        var ranges = new Dictionary<string, List<RangeEntry>>(StringComparer.Ordinal);
        var ipv4 = new HashSet<int>();
        var ipv6 = new HashSet<int>();
        var asns = new Dictionary<int, RangeEntry>();
        var notes = new List<string>();
        int count = 0;
        string? line;
        while ((line = reader.ReadLine()) != null) {
            if (line.Length == 0) continue;
            if (line[0] == '#') {
                notes.Add(line.TrimStart('#', ' '));
                continue;
            }
            string[] fields = line.Split('\t');
            if (fields.Length < 2) continue;
            var entry = new RangeEntry {
                Cidr = fields[0].Trim(),
                Provider = fields[1].Trim(),
                Kind = fields.Length > 2 && Enum.TryParse(fields[2].Trim(), true, out HostingKind kind) ? kind : HostingKind.Unknown,
                Service = fields.Length > 3 ? fields[3].Trim() : string.Empty,
                Region = fields.Length > 4 ? fields[4].Trim() : string.Empty
            };
            if (entry.Provider.Length == 0) continue;
            if (entry.Cidr.StartsWith("as", StringComparison.OrdinalIgnoreCase)) {
                if (int.TryParse(entry.Cidr.Substring(2), NumberStyles.None, CultureInfo.InvariantCulture, out int asn)) {
                    entry.Cidr = "AS" + asn.ToString(CultureInfo.InvariantCulture);
                    asns[asn] = entry;
                }
                continue;
            }
            if (!IpCidrRange.TryParse(entry.Cidr, out IpCidrRange range)) continue;
            string key = Key(range.Network.GetAddressBytes(), range.PrefixLength);
            if (!ranges.TryGetValue(key, out List<RangeEntry>? list)) {
                list = new List<RangeEntry>();
                ranges[key] = list;
                count++;
            }
            list.Add(entry);
            (range.Network.AddressFamily == AddressFamily.InterNetwork ? ipv4 : ipv6).Add(range.PrefixLength);
        }
        return new HostingRangeCatalog(ranges,
            ipv4.OrderByDescending(static l => l).ToArray(),
            ipv6.OrderByDescending(static l => l).ToArray(),
            asns, notes, count);
    }

    /// <summary>Finds the provider hosting <paramref name="address"/>.</summary>
    /// <param name="address">Address to look up.</param>
    /// <param name="autonomousSystem">Announcing autonomous system, when known; used only when no range matches.</param>
    /// <param name="attribution">The match.</param>
    /// <returns>True when a provider matched.</returns>
    public bool TryMatch(IPAddress? address, int? autonomousSystem, out HostingAttribution? attribution) {
        attribution = null;
        if (address != null) {
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            byte[] bytes = address.GetAddressBytes();
            int[] lengths = address.AddressFamily == AddressFamily.InterNetwork ? _ipv4Lengths : _ipv6Lengths;
            foreach (int length in lengths) {
                if (_ranges.TryGetValue(Key(Mask(bytes, length), length), out List<RangeEntry>? entries)) {
                    RangeEntry first = entries[0];
                    attribution = new HostingAttribution {
                        Provider = first.Provider,
                        Kind = entries.Any(static e => e.Kind == HostingKind.Cdn) ? HostingKind.Cdn : first.Kind,
                        Service = string.Join(", ", entries.Select(static e => e.Service).Where(static s => s.Length > 0).Distinct(StringComparer.Ordinal)),
                        Region = string.Join(", ", entries.Select(static e => e.Region).Where(static s => s.Length > 0).Distinct(StringComparer.Ordinal)),
                        MatchedBy = first.Cidr,
                        MatchKind = HostingMatchKind.PublishedRange
                    };
                    return true;
                }
            }
        }
        if (autonomousSystem.HasValue && _autonomousSystems.TryGetValue(autonomousSystem.Value, out RangeEntry? network)) {
            attribution = new HostingAttribution {
                Provider = network.Provider,
                Kind = network.Kind,
                MatchedBy = network.Cidr,
                MatchKind = HostingMatchKind.AutonomousSystem
            };
            return true;
        }
        return false;
    }

    /// <summary>Finds the provider hosting <paramref name="address"/>.</summary>
    /// <param name="address">Address text.</param>
    /// <param name="autonomousSystem">Announcing autonomous system, when known.</param>
    /// <returns>The match, or null.</returns>
    public HostingAttribution? Match(string? address, int? autonomousSystem = null) {
        IPAddress? parsed = null;
        if (!string.IsNullOrWhiteSpace(address) && IPAddress.TryParse(address!.Trim(), out IPAddress? value)) parsed = value;
        return TryMatch(parsed, autonomousSystem, out HostingAttribution? attribution) ? attribution : null;
    }

    private static HostingRangeCatalog LoadBundled() {
        using Stream? resource = typeof(HostingRangeCatalog).Assembly.GetManifestResourceStream(ResourceName);
        if (resource == null) return Parse(new StringReader(string.Empty));
        using var gzip = new GZipStream(resource, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        return Parse(reader);
    }

    private static byte[] Mask(byte[] address, int prefixLength) {
        var masked = new byte[address.Length];
        int full = prefixLength / 8;
        Array.Copy(address, masked, Math.Min(full, address.Length));
        int remaining = prefixLength % 8;
        if (remaining > 0 && full < address.Length) masked[full] = (byte)(address[full] & (0xFF << (8 - remaining)));
        return masked;
    }

    private static string Key(byte[] network, int prefixLength) {
        var builder = new StringBuilder(network.Length * 2 + 4);
        foreach (byte b in network) builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return builder.Append('/').Append(prefixLength.ToString(CultureInfo.InvariantCulture)).ToString();
    }
}

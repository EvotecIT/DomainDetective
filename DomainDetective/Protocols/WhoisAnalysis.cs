using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Text.Json;
using DomainDetective.Helpers;
using DnsClientX;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Queries WHOIS servers and parses registration details.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public partial class WhoisAnalysis : IHasAssessments {
    /// <summary>DNS configuration used for auxiliary lookups (e.g., whois-servers.net).</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();
    private string TLD { get; set; } = string.Empty;
    private string _domainName = string.Empty;

    /// <summary>The domain name being queried.</summary>
    public string DomainName {
        get => _domainName;
        set {
            try {
                _domainName = DomainHelper.ValidateIdn(value);
            } catch (ArgumentException) {
                _domainName = value;
            }
        }
    }
    /// <summary>Top-level domain portion of <see cref="DomainName"/>.</summary>
    public string Tld => TLD;

    /// <summary>WHOIS registrar name.</summary>
    public string? Registrar { get; set; }

    /// <summary>Creation date string as returned by the server.</summary>
    public string? CreationDate { get; set; }

    /// <summary>Expiry date string as returned by the server.</summary>
    public string? ExpiryDate { get; set; }

    /// <summary>Last updated date string.</summary>
    public string? LastUpdated { get; set; }

    /// <summary>Entity the domain is registered to.</summary>
    public string? RegisteredTo { get; set; }

    /// <summary>Name servers listed in the response.</summary>
    public List<string> NameServers { get; set; } = new List<string>();

    /// <summary>Timeout applied when querying WHOIS servers.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Type of registrant if provided.</summary>
    public string? RegistrantType { get; set; }

    /// <summary>Registrant country code.</summary>
    public string? Country { get; set; }

    /// <summary>DNSSEC status string.</summary>
    public string? DnsSec { get; set; }

    /// <summary>Raw DNS record returned, if any.</summary>
    public string? DnsRecord { get; set; }

    /// <summary>Registrar address text.</summary>
    public string? RegistrarAddress { get; set; }

    /// <summary>Registrar phone number.</summary>
    public string? RegistrarTel { get; set; }

    /// <summary>Registrar website URL.</summary>
    public string? RegistrarWebsite { get; set; }

    /// <summary>Registrar licence identifier.</summary>
    public string? RegistrarLicense { get; set; }
    public string? RegistrarEmail { get; set; }
    public string? RegistrarAbuseEmail { get; set; }
    public string? RegistrarAbusePhone { get; set; }
    public string WhoisData { get; set; } = string.Empty;
    /// <summary>When true, follows Registrar WHOIS referrals for gTLDs when available.</summary>
    public bool FollowReferral { get; set; } = false;
    /// <summary>Maximum referral depth when <see cref="FollowReferral"/> is enabled.</summary>
    public int MaxReferralDepth { get; set; } = 2;
    /// <summary>WHOIS servers visited via referral (in order).</summary>
    public List<string> ReferralChain { get; private set; } = new List<string>();
    public bool ExpiresSoon { get; private set; }
    public bool IsExpired { get; private set; }
    public int? DaysUntilExpiration { get; private set; }
    public bool RegistrarLocked { get; private set; }
    public bool PrivacyProtected { get; private set; }
    public TimeSpan ExpirationWarningThreshold { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan ExpirationLongTermThreshold { get; set; } = TimeSpan.FromDays(365);
    public string? SnapshotDirectory { get; set; }
    public string? RegistrarId { get; private set; }
    public Func<string, Task<string>>? IanaQueryOverride { private get; set; }
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Maximum number of WHOIS TCP connect/query retries on transient failures.</summary>
    public int MaxQueryRetries { get; set; } = 3;
    /// <summary>Base delay used for exponential backoff between retries.</summary>
    public TimeSpan RetryBackoffBase { get; set; } = TimeSpan.FromMilliseconds(200);
    /// <summary>Maximum additional random jitter (in milliseconds) added to backoff.</summary>
    public int RetryJitterMaxMs { get; set; } = 100;

    /// <summary>The WHOIS server used to fulfill the query.</summary>
    public string? WhoisServerUsed { get; private set; }
    /// <summary>How the WHOIS server was determined (StaticMap, whois-servers.net, IANA).</summary>
    public string? WhoisLookupSource { get; private set; }

    private static readonly InternalLogger _logger = new();
    private static readonly string[] _licensePrefixes = {
        "Registrar License:",
        "Registrar Licence:",
        "Registrar License Number:",
        "Registrar Licence Number:"
    };

    private static readonly string[] _privacyIndicators = {
        "redacted for privacy",
        "contact privacy",
        "whois privacy",
        "privacy service",
        "domains by proxy",
        "whoisguard",
        "withheld for privacy",
        "privacyguardian.org",
        "privacy protection"
    };

    private static readonly Regex _expiryDateRegex = new(
        "^\\s*(Registry Expiry Date:|Expiry date:|expire:|renewal date:)\\s*(.*)$",
        RegexOptions.IgnoreCase);

    private static readonly Regex _whoisServerRegex = new(
        "whois:\\s*([A-Za-z0-9:._-]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex _referralServerRegex1 = new(
        "Registrar\\s+WHOIS\\s+Server:\\s*([A-Za-z0-9:._-]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex _referralServerRegex2 = new(
        "Whois\\s+Server:\\s*([A-Za-z0-9:._-]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex _referralServerRegex3 = new(
        "ReferralServer:\\s*whois://([A-Za-z0-9:._-]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private void SetExpiryDate(string value) {
        if (DateTime.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var expiry)) {
            ExpiryDate = expiry.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        } else {
            ExpiryDate = value.Trim();
        }
    }

    private void NormalizeExpiryDateInData() {
        if (string.IsNullOrEmpty(ExpiryDate) || string.IsNullOrEmpty(WhoisData)) {
            return;
        }
        var lines = WhoisData.Split('\n');
        for (var i = 0; i < lines.Length; i++) {
            var match = _expiryDateRegex.Match(lines[i]);
            if (match.Success) {
                lines[i] = $"{match.Groups[1].Value} {ExpiryDate}";
            }
        }
        WhoisData = string.Join("\n", lines);
    }

    private void ParseRegistrarLicense(string trimmedLine) {
        foreach (var prefix in _licensePrefixes) {
            if (trimmedLine.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) {
                RegistrarLicense = trimmedLine.Substring(prefix.Length).Trim();
                break;
            }
        }
    }

    // Lock object used to synchronize access to the WhoisServers dictionary
    // since Dictionary<TK,TV> is not thread safe for concurrent writes.
    private readonly object _whoisServersLock = new();

    // Lock object used to synchronize access to the IpWhoisServers list.
    private readonly object _ipWhoisServersLock = new();

    // List of WHOIS servers queried for IP information. Modify this collection
    // only while holding _ipWhoisServersLock to avoid race conditions.
    private readonly List<string> IpWhoisServers = new() {
        "whois.arin.net",
        "whois.ripe.net",
        "whois.apnic.net"
    };

    // Mapping of TLDs to WHOIS servers. Modify this collection only while
    // holding _whoisServersLock to avoid race conditions in multi-threaded tests
    // or applications.
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> GlobalWhoisServersCache = new(System.StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> WhoisServers =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
        {"ac", "whois.nic.ac"},
        {"ad", "whois.ripe.net"},
        {"ae", "whois.aeda.net.ae"},
        {"aero", "whois.aero"},
        {"af", "whois.nic.af"},
        {"ag", "whois.nic.ag"},
        {"ai", "whois.ai"},
        {"al", "whois.ripe.net"},
        {"am", "whois.amnic.net"},
        {"as", "whois.nic.as"},
        {"asia", "whois.nic.asia"},
        {"at", "whois.nic.at"},
        {"au", "whois.aunic.net"},
        {"aw", "whois.nic.aw"},
        {"ax", "whois.ax"},
        {"az", "whois.ripe.net"},
        {"ba", "whois.ripe.net"},
        {"bar", "whois.nic.bar"},
        {"be", "whois.dns.be"},
        {"berlin", "whois.nic.berlin"},
        {"best", "whois.nic.best"},
        {"bg", "whois.register.bg"},
        {"bi", "whois.nic.bi"},
        {"biz", "whois.neulevel.biz"},
        {"bj", "www.nic.bj"},
        {"bo", "whois.nic.bo"},
        {"br", "whois.nic.br"},
        {"br.com", "whois.centralnic.com"},
        {"bt", "whois.netnames.net"},
        {"bw", "whois.nic.net.bw"},
        {"by", "whois.cctld.by"},
        {"bz", "whois.belizenic.bz"},
        {"bzh", "whois-bzh.nic.fr"},
        {"ca", "whois.cira.ca"},
        {"cat", "whois.cat"},
        {"cc", "whois.nic.cc"},
        {"cd", "whois.nic.cd"},
        {"ceo", "whois.nic.ceo"},
        {"cf", "whois.dot.cf"},
        {"ch", "whois.nic.ch"},
        {"ci", "whois.nic.ci"},
        {"ck", "whois.nic.ck"},
        {"cl", "whois.nic.cl"},
        {"cloud", "whois.nic.cloud"},
        {"club", "whois.nic.club"},
        {"cn", "whois.cnnic.net.cn"},
        {"cn.com", "whois.centralnic.com"},
        {"co", "whois.nic.co"},
        {"co.nl", "whois.co.nl"},
        {"com", "whois.verisign-grs.com"},
        {"coop", "whois.nic.coop"},
        {"cx", "whois.nic.cx"},
        {"cy", "whois.ripe.net"},
        //{"cz", "whois.nic.cz"},
        {"cz", "cz.whois-servers.net" },
        {"de", "whois.denic.de"},
        {"dk", "whois.dk-hostmaster.dk"},
        {"dm", "whois.nic.cx"},
        {"dz", "whois.nic.dz"},
        {"ec", "whois.nic.ec"},
        {"edu", "whois.educause.net"},
        {"ee", "whois.tld.ee"},
        {"eg", "whois.ripe.net"},
        {"es", "whois.nic.es"},
        {"eu", "whois.eu"},
        {"eu.com", "whois.centralnic.com"},
        {"eus", "whois.nic.eus"},
        {"fi", "whois.fi"},
        {"fo", "whois.nic.fo"},
        {"fr", "whois.nic.fr"},
        {"gb", "whois.ripe.net"},
        {"gb.com", "whois.centralnic.com"},
        {"gb.net", "whois.centralnic.com"},
        {"qc.com", "whois.centralnic.com"},
        {"ge", "whois.ripe.net"},
        {"gg", "whois.gg"},
        {"gi", "whois2.afilias-grs.net"},
        {"gl", "whois.nic.gl"},
        {"gm", "whois.ripe.net"},
        {"gov", "whois.nic.gov"},
        {"gr", "whois.ripe.net"},
        {"gs", "whois.nic.gs"},
        {"gy", "whois.registry.gy"},
        {"hamburg", "whois.nic.hamburg"},
        {"hiphop", "whois.uniregistry.net"},
        {"hk", "whois.hknic.net.hk"},
        {"hm", "whois.registry.hm"},
        {"hn", "whois2.afilias-grs.net"},
        {"host", "whois.nic.host"},
        {"hr", "whois.dns.hr"},
        {"ht", "whois.nic.ht"},
        {"hu", "whois.nic.hu"},
        {"hu.com", "whois.centralnic.com"},
        {"id", "whois.pandi.or.id"},
        {"ie", "whois.domainregistry.ie"},
        {"il", "whois.isoc.org.il"},
        {"im", "whois.nic.im"},
        {"in", "whois.inregistry.net"},
        {"info", "whois.afilias.info"},
        {"ing", "domain-registry-whois.l.google.com"},
        {"ink", "whois.centralnic.com"},
        {"int", "whois.isi.edu"},
        {"io", "whois.nic.io"},
        {"iq", "whois.cmc.iq"},
        {"ir", "whois.nic.ir"},
        {"is", "whois.isnic.is"},
        {"it", "whois.nic.it"},
        {"je", "whois.je"},
        {"jobs", "jobswhois.verisign-grs.com"},
        {"jp", "whois.jprs.jp"},
        {"ke", "whois.kenic.or.ke"},
        {"kg", "whois.domain.kg"},
        {"ki", "whois.nic.ki"},
        {"kr", "whois.kr"},
        {"kz", "whois.nic.kz"},
        {"la", "whois2.afilias-grs.net"},
        {"li", "whois.nic.li"},
        {"london", "whois.nic.london"},
        {"lt", "whois.domreg.lt"},
        {"lu", "whois.restena.lu"},
        {"lv", "whois.nic.lv"},
        {"ly", "whois.lydomains.com"},
        {"ma", "whois.iam.net.ma"},
        {"mc", "whois.ripe.net"},
        {"md", "whois.nic.md"},
        {"me", "whois.nic.me"},
        {"mg", "whois.nic.mg"},
        {"mil", "whois.nic.mil"},
        {"mk", "whois.ripe.net"},
        {"ml", "whois.dot.ml"},
        {"mo", "whois.monic.mo"},
        {"mobi", "whois.dotmobiregistry.net"},
        {"ms", "whois.nic.ms"},
        {"mt", "whois.ripe.net"},
        {"mu", "whois.nic.mu"},
        {"museum", "whois.museum"},
        {"mx", "whois.nic.mx"},
        {"my", "whois.mynic.net.my"},
        {"mz", "whois.nic.mz"},
        {"na", "whois.na-nic.com.na"},
        {"name", "whois.nic.name"},
        {"nc", "whois.nc"},
        {"net", "whois.verisign-grs.com"},
        {"nf", "whois.nic.cx"},
        {"ng", "whois.nic.net.ng"},
        {"nl", "whois.domain-registry.nl"},
        {"no", "whois.norid.no"},
        {"no.com", "whois.centralnic.com"},
        {"nu", "whois.nic.nu"},
        {"nz", "whois.srs.net.nz"},
        {"om", "whois.registry.om"},
        {"ong", "whois.publicinterestregistry.net"},
        {"ooo", "whois.nic.ooo"},
        {"org", "whois.pir.org"},
        {"paris", "whois-paris.nic.fr"},
        {"pe", "kero.yachay.pe"},
        {"pf", "whois.registry.pf"},
        {"pics", "whois.uniregistry.net"},
        {"pl", "whois.dns.pl"},
        {"pm", "whois.nic.pm"},
        {"pr", "whois.nic.pr"},
        {"press", "whois.nic.press"},
        {"pro", "whois.registrypro.pro"},
        {"pt", "whois.dns.pt"},
        {"pub", "whois.unitedtld.com"},
        {"pw", "whois.nic.pw"},
        {"qa", "whois.registry.qa"},
        {"re", "whois.nic.re"},
        {"ro", "whois.rotld.ro"},
        {"rs", "whois.rnids.rs"},
        {"ru", "whois.tcinet.ru"},
        {"sa", "saudinic.net.sa"},
        {"sa.com", "whois.centralnic.com"},
        {"sb", "whois.nic.net.sb"},
        {"sc", "whois2.afilias-grs.net"},
        {"se", "whois.nic-se.se"},
        {"se.com", "whois.centralnic.com"},
        {"se.net", "whois.centralnic.com"},
        {"sg", "whois.nic.net.sg"},
        {"sh", "whois.nic.sh"},
        {"si", "whois.arnes.si"},
        {"sk", "whois.sk-nic.sk"},
        {"sm", "whois.nic.sm"},
        {"st", "whois.nic.st"},
        {"so", "whois.nic.so"},
        {"su", "whois.tcinet.ru"},
        {"sx", "whois.sx"},
        {"sy", "whois.tld.sy"},
        {"tc", "whois.adamsnames.tc"},
        {"tel", "whois.nic.tel"},
        {"tf", "whois.nic.tf"},
        {"th", "whois.thnic.net"},
        {"tj", "whois.nic.tj"},
        {"tk", "whois.nic.tk"},
        {"tl", "whois.domains.tl"},
        {"tm", "whois.nic.tm"},
        {"tn", "whois.ati.tn"},
        {"to", "whois.tonic.to"},
        {"top", "whois.nic.top"},
        {"tp", "whois.domains.tl"},
        {"tr", "whois.nic.tr"},
        {"travel", "whois.nic.travel"},
        {"tw", "whois.twnic.net.tw"},
        {"tv", "whois.nic.tv"},
        {"tz", "whois.tznic.or.tz"},
        {"ua", "whois.ua"},
        {"ug", "whois.co.ug"},
        {"uk", "whois.nic.uk"},
        {"uk.com", "whois.centralnic.com"},
        {"uk.net","whois.centralnic.com"},
        {"ac.uk","whois.ja.net"},
        {"gov.uk","whois.ja.net"},
        {"us","whois.nic.us"},
        {"us.com","whois.centralnic.com"},
        {"uy","nic.uy"},
        {"uy.com","whois.centralnic.com"},
        {"uz","whois.cctld.uz"},
        {"va","whois.ripe.net"},
        {"vc","whois2.afilias-grs.net"},
        {"ve","whois.nic.ve"},
        {"vg","ccwhois.ksregistry.net"},
        {"vu","vunic.vu"},
        {"wang","whois.nic.wang"},
        {"wf","whois.nic.wf"},
        {"wiki","whois.nic.wiki"},
        {"ws","whois.website.ws"},
        {"xxx","whois.nic.xxx"},
        {"xyz","whois.nic.xyz"},
        {"yu","whois.ripe.net"},
        {"za.com","whois.centralnic.com"}
    };

    public WhoisAnalysis() { }

    private async Task<string?> GetWhoisServer(string domain) {
        string[] domainParts = domain.Split('.');
        if (domainParts.Length > 2) {
            string compoundTld = string.Join(".", domainParts.Skip(domainParts.Length - 2));
            lock (_whoisServersLock) {
                if (WhoisServers.TryGetValue(compoundTld, out var server) && !string.IsNullOrWhiteSpace(server)) {
                    TLD = compoundTld;
                    _logger?.WriteVerbose("WHOIS TLD '{0}' uses server '{1}'", TLD, server);
                    WhoisServerUsed = server;
                    WhoisLookupSource = "StaticMap";
                    return server;
                }
                if (GlobalWhoisServersCache.TryGetValue(compoundTld, out var cached)) {
                    WhoisServers[compoundTld] = cached;
                    TLD = compoundTld;
                    WhoisLookupSource = "Cache";
                    WhoisServerUsed = cached;
                    return cached;
                }
            }
        }

        string singleTld = domainParts[domainParts.Length - 1];
        TLD = singleTld;
        lock (_whoisServersLock) {
            if (WhoisServers.TryGetValue(singleTld, out var server) && !string.IsNullOrWhiteSpace(server)) {
                _logger?.WriteVerbose("WHOIS TLD '{0}' uses server '{1}'", TLD, server);
                WhoisServerUsed = server;
                WhoisLookupSource = "StaticMap";
                return server;
            }
            if (GlobalWhoisServersCache.TryGetValue(singleTld, out var cached2)) {
                WhoisServers[singleTld] = cached2;
                WhoisServerUsed = cached2;
                WhoisLookupSource = "Cache";
                return cached2;
            }
        }

        string? dynamicServer = await LookupWhoisServerAsync(singleTld).ConfigureAwait(false);
        if (dynamicServer != null) {
            lock (_whoisServersLock) {
                WhoisServers[singleTld] = dynamicServer;
            }
            WhoisServerUsed = dynamicServer;
            GlobalWhoisServersCache[singleTld] = dynamicServer;
            }

        return dynamicServer;
    }

    private async Task<string?> LookupWhoisServerAsync(string tld) {
        var host = $"{tld}.whois-servers.net";
        try {
            // Prefer configured DNS resolver when available
            DnsAnswer[] answers = Array.Empty<DnsAnswer>();
            try {
                answers = await DnsConfiguration.QueryDNS(host, DnsRecordType.A).ConfigureAwait(false);
            } catch { }
            if (answers != null && answers.Length > 0) {
                _logger?.WriteVerbose("WHOIS server autodetected via DNS (configured resolver): {0}", host);
                WhoisLookupSource = "whois-servers.net";
                return host;
            }
            // Fallback to system DNS
            _ = await System.Net.Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            _logger?.WriteVerbose("WHOIS server autodetected via DNS (system resolver): {0}", host);
            WhoisLookupSource = "whois-servers.net";
            return host;
        } catch (Exception) {
            // Fallback to IANA lookup below.
        }

        string response;
        if (IanaQueryOverride != null) {
            response = await IanaQueryOverride(tld).ConfigureAwait(false);
        } else {
            try {
                using var httpResponse = await SharedHttpClient.Instance.GetAsync($"https://www.iana.org/whois?q={tld}").ConfigureAwait(false);
                response = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
            } catch (HttpRequestException) {
                return null;
            }
        }

        Match match = _whoisServerRegex.Match(response);
        if (match.Success) {
            var server = match.Groups[1].Value;
            _logger?.WriteVerbose("WHOIS server discovered via IANA: {0}", server);
            WhoisLookupSource = "IANA";
            return server;
        }
        _logger?.WriteVerbose("WHOIS server not found via IANA for TLD '{0}'", tld);
        return null;
    }

    /// <summary>
    /// Queries a single WHOIS server for the specified domain.
    /// </summary>
    public async Task QueryWhoisServer(string domain, CancellationToken cancellationToken = default) {
        DomainName = domain;
        if (string.IsNullOrWhiteSpace(domain) || !domain.Contains('.')) {
            throw new UnsupportedTldException(domain, domain);
        }
        var whoisServer = await GetWhoisServer(domain).ConfigureAwait(false);
        if (whoisServer == null) {
            throw new UnsupportedTldException(domain, TLD);
        }


        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);
        try {
            var serverParts = whoisServer.Split(':');
            var host = serverParts[0];
            var port = 43;
            if (serverParts.Length > 1 && int.TryParse(serverParts[1], out var customPort)) {
                port = customPort;
            }

            byte[] responseBytes = Array.Empty<byte>();
            Exception? lastEx = null;
            var retries = Math.Max(1, MaxQueryRetries);
            for (int attempt = 0; attempt < retries; attempt++) {
                try {
                    using TcpClient tcpClient = new TcpClient();
                    await tcpClient.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
                    _logger?.WriteVerbose("Connected to WHOIS server {0}:{1} (attempt {2})", host, port, attempt + 1);

                    using NetworkStream networkStream = tcpClient.GetStream();
                    using (var streamWriter = new StreamWriter(networkStream, Encoding.ASCII, 1024, leaveOpen: true) { NewLine = "\r\n" }) {
                        await streamWriter.WriteLineAsync(domain).WaitWithCancellation(timeoutCts.Token);
                        await streamWriter.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                    }

                    await networkStream.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                    using var memoryStream = new MemoryStream();
                    await networkStream.CopyToAsync(memoryStream, 81920, timeoutCts.Token);
                    responseBytes = memoryStream.ToArray();
                    lastEx = null;
                    break;
                } catch (IOException ex) {
                    lastEx = ex;
                } catch (SocketException ex) {
                    lastEx = ex;
                }
                // Exponential backoff with jitter
                var baseMs = (int)System.Math.Max(0, RetryBackoffBase.TotalMilliseconds);
                var jitter = new System.Random().Next(0, System.Math.Max(0, RetryJitterMaxMs));
                var delayMs = baseMs * (int)System.Math.Pow(2, attempt) + jitter;
                await Task.Delay(delayMs, timeoutCts.Token);
            }
            if (responseBytes.Length == 0 && lastEx != null) throw lastEx;

            string response = Encoding.UTF8.GetString(responseBytes);
            if (response.Contains('\uFFFD')) {
                response = Encoding.GetEncoding("ISO-8859-1").GetString(responseBytes);
            }

            response = Regex.Replace(
                response,
                "\r\n|\n|\r",
                "\n",
                RegexOptions.CultureInvariant | RegexOptions.Multiline);
            WhoisData = response;
            using (var _collector = AssessmentCollector.ForAnalysis(_logger!, this, category: "WHOIS", target: domain))
            {
                ParseWhoisData();
            }
            NormalizeExpiryDateInData();
            _logger?.WriteVerbose("WHOIS received {0} bytes; Registrar='{1}', Expiry='{2}'", responseBytes.Length, Registrar, ExpiryDate);

            // Follow registrar referrals when enabled
            if (FollowReferral && MaxReferralDepth > 0)
            {
                await FollowRegistrarReferralAsync(domain, response, whoisServer, timeoutCts.Token, cancellationToken).ConfigureAwait(false);
            }
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
            throw;
        } catch (Exception ex) {
            _logger.WriteErrorCode(
                WhoisCodes.QueryFailed,
                "Error querying WHOIS server {0} for domain {1}: {2}",
                whoisServer,
                domain,
                ex.Message);
        }
    }

    private string? ExtractReferralServer(string response)
    {
        var m1 = _referralServerRegex1.Match(response);
        if (m1.Success) return m1.Groups[1].Value.Trim();
        var m2 = _referralServerRegex2.Match(response);
        if (m2.Success) return m2.Groups[1].Value.Trim();
        var m3 = _referralServerRegex3.Match(response);
        if (m3.Success) return m3.Groups[1].Value.Trim();
        return null;
    }

    private async Task FollowRegistrarReferralAsync(string domain, string initialResponse, string initialServer, CancellationToken ct, CancellationToken callerCancellationToken)
    {
        string? current = ExtractReferralServer(initialResponse);
        int depth = 0;
        while (!string.IsNullOrWhiteSpace(current) && depth < MaxReferralDepth)
        {
            depth++;
            ReferralChain.Add(current!);
            _logger?.WriteVerbose("Following referral to WHOIS server: {0}", current);
            string? nextResponse = await QueryWhoisRawAsyncInternal(current!, domain, ct, callerCancellationToken).ConfigureAwait(false);
            if (nextResponse == null || string.IsNullOrWhiteSpace(nextResponse)) break;

            // Overwrite data with registrar WHOIS details
            WhoisServerUsed = current;
            WhoisLookupSource = "Referral";
            WhoisData = nextResponse;
            using (var _collector = AssessmentCollector.ForAnalysis(_logger!, this, category: "WHOIS", target: domain))
            {
                ParseWhoisData();
            }
            NormalizeExpiryDateInData();

            // Check if further referrals exist
            current = ExtractReferralServer(nextResponse);
        }
    }

    private Task<string?> QueryWhoisRawAsync(string server, string domain, CancellationToken ct)
    {
        return QueryWhoisRawAsyncInternal(server, domain, ct, ct);
    }

    private async Task<string?> QueryWhoisRawAsyncInternal(string server, string domain, CancellationToken ct, CancellationToken callerCancellationToken = default)
    {
        try
        {
            var serverParts = server.Split(':');
            var host = serverParts[0];
            var port = 43;
            if (serverParts.Length > 1 && int.TryParse(serverParts[1], out var customPort)) port = customPort;

            byte[] responseBytes = Array.Empty<byte>();
            Exception? lastEx = null;
            var retries = Math.Max(1, MaxQueryRetries);
            for (int attempt = 0; attempt < retries; attempt++)
            {
                try
                {
                    using var tcpClient = new TcpClient();
#if NET8_0_OR_GREATER
                    await tcpClient.ConnectAsync(host, port, ct).ConfigureAwait(false);
#else
                    await tcpClient.ConnectAsync(host, port).WaitWithCancellation(ct).ConfigureAwait(false);
#endif
                    using var networkStream = tcpClient.GetStream();
                    using (var writer = new StreamWriter(networkStream, Encoding.ASCII, 1024, leaveOpen: true) { NewLine = "\r\n" })
                    {
                        await writer.WriteLineAsync(domain).WaitWithCancellation(ct).ConfigureAwait(false);
                        await writer.FlushAsync().WaitWithCancellation(ct).ConfigureAwait(false);
                    }
                    await networkStream.FlushAsync().WaitWithCancellation(ct).ConfigureAwait(false);
                    using var ms = new MemoryStream();
                    await networkStream.CopyToAsync(ms, 81920, ct).ConfigureAwait(false);
                    responseBytes = ms.ToArray();
                    lastEx = null;
                    break;
                }
                catch (IOException ex) { lastEx = ex; }
                catch (SocketException ex) { lastEx = ex; }
                var baseMs = (int)Math.Max(0, RetryBackoffBase.TotalMilliseconds);
                var jitter = new Random().Next(0, Math.Max(0, RetryJitterMaxMs));
                var delayMs = baseMs * (int)Math.Pow(2, attempt) + jitter;
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
            }
            if (responseBytes.Length == 0 && lastEx != null) throw lastEx;
            var text = Encoding.UTF8.GetString(responseBytes);
            if (text.Contains('\uFFFD')) text = Encoding.GetEncoding("ISO-8859-1").GetString(responseBytes);
            text = Regex.Replace(text, "\r\n|\n|\r", "\n", RegexOptions.CultureInvariant | RegexOptions.Multiline);
            return text;
        }
        catch (OperationCanceledException) when (callerCancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Queries WHOIS servers for multiple domains in parallel.
    /// </summary>
    public async Task<List<WhoisAnalysis>> QueryWhoisServers(string[] domains, CancellationToken cancellationToken = default) {
        var tasks = domains.Select(async domain => {
            var analysis = new WhoisAnalysis { Timeout = Timeout };
            lock (_whoisServersLock) {
                foreach (var kvp in WhoisServers) {
                    if (!analysis.WhoisServers.ContainsKey(kvp.Key)) {
                        analysis.WhoisServers[kvp.Key] = kvp.Value;
                    }
                }
            }
            await analysis.QueryWhoisServer(domain, cancellationToken);
            return analysis;
        });
        return (await Task.WhenAll(tasks)).ToList();
    }

}

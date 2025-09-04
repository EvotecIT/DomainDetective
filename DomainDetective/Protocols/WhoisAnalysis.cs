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
public class WhoisAnalysis : IHasAssessments {
    /// <summary>DNS configuration used for auxiliary lookups (e.g., whois-servers.net).</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();
    private string TLD { get; set; }
    private string _domainName;

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
    public string Registrar { get; set; }

    /// <summary>Creation date string as returned by the server.</summary>
    public string CreationDate { get; set; }

    /// <summary>Expiry date string as returned by the server.</summary>
    public string ExpiryDate { get; set; }

    /// <summary>Last updated date string.</summary>
    public string LastUpdated { get; set; }

    /// <summary>Entity the domain is registered to.</summary>
    public string RegisteredTo { get; set; }

    /// <summary>Name servers listed in the response.</summary>
    public List<string> NameServers { get; set; } = new List<string>();

    /// <summary>Timeout applied when querying WHOIS servers.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Type of registrant if provided.</summary>
    public string RegistrantType { get; set; }

    /// <summary>Registrant country code.</summary>
    public string Country { get; set; }

    /// <summary>DNSSEC status string.</summary>
    public string DnsSec { get; set; }

    /// <summary>Raw DNS record returned, if any.</summary>
    public string DnsRecord { get; set; }

    /// <summary>Registrar address text.</summary>
    public string RegistrarAddress { get; set; }

    /// <summary>Registrar phone number.</summary>
    public string RegistrarTel { get; set; }

    /// <summary>Registrar website URL.</summary>
    public string RegistrarWebsite { get; set; }

    /// <summary>Registrar licence identifier.</summary>
    public string RegistrarLicense { get; set; }
    public string RegistrarEmail { get; set; }
    public string RegistrarAbuseEmail { get; set; }
    public string RegistrarAbusePhone { get; set; }
    public string WhoisData { get; set; }
    public bool ExpiresSoon { get; private set; }
    public bool IsExpired { get; private set; }
    public int? DaysUntilExpiration { get; private set; }
    public bool RegistrarLocked { get; private set; }
    public bool PrivacyProtected { get; private set; }
    public TimeSpan ExpirationWarningThreshold { get; set; } = TimeSpan.FromDays(30);
    public string? SnapshotDirectory { get; set; }
    public string RegistrarId { get; private set; }
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
                if (WhoisServers.TryGetValue(compoundTld, out string server)) {
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
            if (WhoisServers.TryGetValue(singleTld, out string server)) {
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
#if NETSTANDARD2_0 || NET472
                using var httpResponse = await SharedHttpClient.Instance.GetAsync($"https://www.iana.org/whois?q={tld}").ConfigureAwait(false);
                response = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
                response = await SharedHttpClient.Instance.GetStringAsync($"https://www.iana.org/whois?q={tld}").ConfigureAwait(false);
#endif
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
            Exception lastEx = null;
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
            using (var _collector = AssessmentCollector.ForAnalysis(_logger, this, category: "WHOIS", target: domain))
            {
                ParseWhoisData();
            }
            NormalizeExpiryDateInData();
            _logger?.WriteVerbose("WHOIS received {0} bytes; Registrar='{1}', Expiry='{2}'", responseBytes.Length, Registrar, ExpiryDate);
        } catch (Exception ex) {
            _logger.WriteErrorCode(
                WhoisCodes.QueryFailed,
                "Error querying WHOIS server {0} for domain {1}: {2}",
                whoisServer,
                domain,
                ex.Message);
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

    private void ParseWhoisData() {
        if (string.Equals(TLD, "xyz", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataXYZ();
        } else if (string.Equals(TLD, "pl", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataPL();
        } else if (string.Equals(TLD, "com", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(TLD, "net", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataCOM();
        } else if (string.Equals(TLD, "co.uk", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(TLD, "uk", StringComparison.OrdinalIgnoreCase)
                   || (DomainName?.EndsWith(".uk", StringComparison.OrdinalIgnoreCase) ?? false)) {
            ParseWhoisDataCOUK();
        } else if (string.Equals(TLD, "de", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataDE();
        } else if (string.Equals(TLD, "cz", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataCZ();
        } else if (string.Equals(TLD, "be", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataBE();
        } else if (string.Equals(TLD, "fr", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataFR();
        } else if (string.Equals(TLD, "es", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataES();
        } else if (string.Equals(TLD, "it", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataIT();
        } else if (string.Equals(TLD, "nl", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataNL();
        } else if (IsEuCctld(TLD)) {
            ParseWhoisDataEUGeneric();
        } else {
            ParseWhoisDataDefault();
        }
        UpdateExpiryFlags();
        UpdateRegistrarLock();
        UpdatePrivacyFlag();

        // Emit assessments after parsing flags
        using (var _collector = AssessmentCollector.ForAnalysis(_logger, this, category: "WHOIS", target: DomainName))
        {
            if (IsExpired)
            {
                _logger.WriteWarningCode(WhoisCodes.Expired, "Domain appears expired on {0}", ExpiryDate ?? "unknown");
            }
            else if (ExpiresSoon)
            {
                _logger.WriteWarningCode(WhoisCodes.ExpirySoon, "Domain expires in {0} days (on {1})", DaysUntilExpiration?.ToString() ?? "?", ExpiryDate ?? "unknown");
            }
            if (string.IsNullOrWhiteSpace(Registrar))
            {
                _logger.WriteWarningCode(WhoisCodes.NoRegistrar, "WHOIS registrar not identified");
            }
            if (!string.IsNullOrWhiteSpace(WhoisData) && string.IsNullOrWhiteSpace(ExpiryDate))
            {
                _logger.WriteInformationCode(WhoisCodes.ParseAnomaly, "WHOIS parse anomaly: expiry date not found");
            }
            if (!IsExpired && !ExpiresSoon && DaysUntilExpiration.HasValue && DaysUntilExpiration.Value > 365)
            {
                _logger.WriteInformationCode(
                    WhoisCodes.ExpiryFuture,
                    "Domain expires in {0} days (on {1})",
                    DaysUntilExpiration?.ToString() ?? "?",
                    ExpiryDate ?? "unknown");
            }
            if (!PrivacyProtected && (!string.IsNullOrWhiteSpace(RegisteredTo) || !string.IsNullOrWhiteSpace(RegistrarEmail)))
            {
                _logger.WriteInformationCode(WhoisCodes.ContactValid, "WHOIS contact data present");
            }
        }
    }

    private void ParseWhoisDataCOUK() {
        // Normalize line endings to \n
        WhoisData = Regex.Replace(
            WhoisData,
            "\r\n|\n|\r",
            "\n",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        string currentSection = null;
        foreach (var line in WhoisData.Split('\n')) {
            var trimmedLine = line.Trim();
            ParseRegistrarLicense(trimmedLine);
            if (trimmedLine.EndsWith(":")) {
                currentSection = trimmedLine.TrimEnd(':');
            } else if (!string.IsNullOrWhiteSpace(trimmedLine)) {
                switch (currentSection) {
                    case "Domain name":
                        DomainName = trimmedLine;
                        break;
                    case "Registrar":
                        if (Registrar == null) {
                            Registrar = trimmedLine;
                        } else if (trimmedLine.StartsWith("URL:")) {
                            RegistrarWebsite = trimmedLine.Substring("URL:".Length).Trim();
                        }
                        break;
                    case "Relevant dates":
                        if (trimmedLine.StartsWith("Registered on:")) {
                            CreationDate = trimmedLine.Substring("Registered on:".Length).Trim();
                        } else if (trimmedLine.StartsWith("Expiry date:")) {
                            SetExpiryDate(trimmedLine.Substring("Expiry date:".Length).Trim());
                        } else if (trimmedLine.StartsWith("Last updated:")) {
                            LastUpdated = trimmedLine.Substring("Last updated:".Length).Trim();
                        }
                        break;
                    case "Name servers":
                        NameServers.Add(trimmedLine);
                        break;
                }
            } else {
                currentSection = null; // Reset current section when encountering an empty line
            }
        }
    }

    private void ParseWhoisDataCZ1() {
        //domain:       evotec.cz
        // registrant:   OVH53D75C9A1TJC
        // admin-c:      OVH62C49158JLW8
        // nsset:        OVH60FA6C8B0BGVL1XZ29I766H1
        // keyset:       AUTO-S0TOTEZKRVB3CFV787RP8ZWIQ
        // registrar:    REG-OVH
        // registered:   29.07.2014 10:34:38
        // changed:      05.07.2022 21:30:33
        // expire:       29.07.2024
        // 
        // contact:      OVH53D75C9A1TJC
        // org:          Evotec Przemyslaw Klys
        // name:         Klys Przemek
        // address:      ul. Strzelców Bytomskich 23A/10
        // address:      Katowice
        // address:      40-308
        // address:      PL
        // registrar:    REG-OVH
        // created:      29.07.2014 10:34:35
        // changed:      06.07.2019 09:42:25
        // 
        // contact:      OVH62C49158JLW8
        // org:          Evotec Services Sp. z o.o.
        // name:         Przemyslaw Klys
        // address:      Drozdów 6
        // address:      Mikolów
        // address:      43-190
        // address:      PL
        // registrar:    REG-OVH
        // created:      05.07.2022 21:30:32
        // 
        // nsset:        OVH60FA6C8B0BGVL1XZ29I766H1
        // nserver:      gwen.ns.cloudflare.com
        // nserver:      pablo.ns.cloudflare.com
        // tech-c:       OVH-DEFAULT
        // registrar:    REG-OVH
        // created:      23.07.2021 09:15:23
        // 
        // contact:      OVH-DEFAULT
        // org:          OVH
        // name:         Octave Klaba
        // address:      2 rue Kellermann
        // address:      Roubaix
        // address:      59100
        // address:      FR
        // registrar:    REG-OVH
        // created:      17.11.2008 19:52:09
        // changed:      02.11.2022 13:03:23
        // 
        // keyset:       AUTO-S0TOTEZKRVB3CFV787RP8ZWIQ
        // dnskey:       257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
        // tech-c:       CZ-NIC
        // registrar:    REG-CZNIC
        // created:      07.02.2022 15:10:39
        // 
        // contact:      CZ-NIC
        // org:          CZ.NIC, z.s.p.o.
        // name:         CZ.NIC, z.s.p.o.
        // address:      Milesovska 1136/5
        // address:      Praha 3
        // address:      130 00
        // address:      CZ
        // registrar:    REG-CZNIC
        // created:      17.10.2008 12:08:21
        // changed:      15.05.2018 21:32:00
        // 

        // Normalize line endings to \n
        WhoisData = Regex.Replace(
            WhoisData,
            "\r\n|\n|\r",
            "\n",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        bool isParsingNameServers = false;

        foreach (var line in WhoisData.Split('\n')) {
            var trimmedLine = line.Trim();
            ParseRegistrarLicense(trimmedLine);

            if (trimmedLine.StartsWith("domain:")) {
                DomainName = trimmedLine.Substring("domain:".Length).Trim();
            } else if (trimmedLine.StartsWith("registered:")) {
                CreationDate = trimmedLine.Substring("registered:".Length).Trim();
            } else if (trimmedLine.StartsWith("expire:")) {
                SetExpiryDate(trimmedLine.Substring("expire:".Length).Trim());
            } else if (trimmedLine.StartsWith("registrar:")) {
                Registrar = trimmedLine.Substring("registrar:".Length).Trim();
            } else if (trimmedLine.StartsWith("nserver:")) {
                NameServers.Add(trimmedLine.Substring("nserver:".Length).Trim());
            } else if (trimmedLine.StartsWith("dnskey:")) {
                DnsSec = trimmedLine.Substring("dnskey:".Length).Trim();
            }
        }

    }

    private void ParseWhoisDataCZ() {
        // Normalize line endings to \n
        WhoisData = Regex.Replace(
            WhoisData,
            "\r\n|\n|\r",
            "\n",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        bool isParsingDomainSection = true;
        bool isParsingRegistrantSection = false;
        string registrantId = "";

        foreach (var line in WhoisData.Split('\n')) {
            var trimmedLine = line.Trim();
            ParseRegistrarLicense(trimmedLine);

            if (string.IsNullOrWhiteSpace(trimmedLine)) {
                isParsingDomainSection = false; // Stop parsing the domain section when encountering an empty line
                isParsingRegistrantSection = false; // Stop parsing the registrant section when encountering an empty line
            }

            if (isParsingDomainSection) {
                if (trimmedLine.StartsWith("domain:")) {
                    DomainName = trimmedLine.Substring("domain:".Length).Trim();
                } else if (trimmedLine.StartsWith("registered:")) {
                    CreationDate = trimmedLine.Substring("registered:".Length).Trim();
                } else if (trimmedLine.StartsWith("expire:")) {
                    SetExpiryDate(trimmedLine.Substring("expire:".Length).Trim());
                } else if (trimmedLine.StartsWith("registrar:")) {
                    Registrar = trimmedLine.Substring("registrar:".Length).Trim();
                } else if (trimmedLine.StartsWith("registrant:")) {
                    registrantId = trimmedLine.Substring("registrant:".Length).Trim();
                }
            } else if (trimmedLine.StartsWith("contact:") && trimmedLine.Substring("contact:".Length).Trim() == registrantId) {
                isParsingRegistrantSection = true;
            } else if (isParsingRegistrantSection) {
                if (trimmedLine.StartsWith("org:")) {
                    RegistrantType = trimmedLine.Substring("org:".Length).Trim();
                } else if (trimmedLine.StartsWith("name:")) {
                    RegisteredTo = trimmedLine.Substring("name:".Length).Trim();
                } else if (trimmedLine.StartsWith("address:")) {
                    RegistrarAddress = trimmedLine.Substring("address:".Length).Trim();
                }
            } else {
                if (trimmedLine.StartsWith("nserver:")) {
                    NameServers.Add(trimmedLine.Substring("nserver:".Length).Trim());
                } else if (trimmedLine.StartsWith("dnskey:")) {
                    DnsSec = trimmedLine.Substring("dnskey:".Length).Trim();
                }
            }
        }
    }


    private void ParseWhoisDataCOM() {
        // Normalize line endings to \n
        WhoisData = Regex.Replace(
            WhoisData,
            "\r\n|\n|\r",
            "\n",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        foreach (var line in WhoisData.Split('\n')) {
            ParseRegistrarLicense(line.Trim());
            if (line.StartsWith("   Domain Name:")) {
                DomainName = line.Substring("   Domain Name:".Length).Trim();
            } else if (line.StartsWith("   Registrar:")) {
                Registrar = line.Substring("   Registrar:".Length).Trim();
            } else if (line.StartsWith("   Creation Date:")) {
                CreationDate = line.Substring("   Creation Date:".Length).Trim();
            } else if (line.StartsWith("   Registry Expiry Date:")) {
                SetExpiryDate(line.Substring("   Registry Expiry Date:".Length).Trim());
            } else if (line.Contains("Updated Date:")) {
                LastUpdated = line.Substring("   Updated Date:".Length).Trim();
            } else if (line.StartsWith("   Name Server:")) {
                NameServers.Add(line.Substring("   Name Server:".Length).Trim());
            } else if (line.StartsWith("   Registrar Abuse Contact Email:")) {
                var value = line.Substring("   Registrar Abuse Contact Email:".Length).Trim();
                RegistrarEmail = value;
                RegistrarAbuseEmail = value;
            } else if (line.StartsWith("   Registrar Abuse Contact Phone:")) {
                var value = line.Substring("   Registrar Abuse Contact Phone:".Length).Trim();
                RegistrarTel = value;
                RegistrarAbusePhone = value;
            } else if (line.StartsWith("   DNSSEC:")) {
                DnsSec = line.Substring("   DNSSEC:".Length).Trim();
            }
        }
    }

    private void ParseWhoisDataDefault() {
        // Generic parser with common synonyms to cover most registries
        WhoisData = Regex.Replace(WhoisData, "\r\n|\n|\r", "\n", RegexOptions.CultureInvariant | RegexOptions.Multiline);

        static bool StartsWithI(string s, string prefix)
            => s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

        string[] domainKeys = { "Domain Name:", "Domain:", "domain:", "domain name:" };
        string[] registrarKeys = { "Registrar:", "Sponsoring Registrar:", "registrar:" };
        string[] createdKeys = { "Creation Date:", "Created:", "Created On:", "Created Date:", "registered:" };
        string[] updatedKeys = { "Updated Date:", "Last Updated On:", "Last Update:", "last-update:", "Modified:", "changed:" };
        string[] expiryKeys = { "Registry Expiry Date:", "Expiry Date:", "Expiration Date:", "expire-date:", "paid-till:", "expires:" };
        string[] nsLineKeys = { "Name Server:", "Nameserver:", "Name-Server:" };
        string[] nsBlockKeys = { "Name Servers:", "Nameservers:", "nserver:", "NSERVER:", "nameservers:", "Name servers:" };
        string[] dnssecKeys = { "DNSSEC:", "dnssec:" };

        bool inNsBlock = false;
        foreach (var raw in WhoisData.Split('\n')) {
            var line = raw.Trim();
            if (string.IsNullOrWhiteSpace(line)) { inNsBlock = false; continue; }
            ParseRegistrarLicense(line);

            // Domain
            foreach (var k in domainKeys) if (StartsWithI(line, k)) { DomainName = line.Substring(k.Length).Trim(); goto next; }

            // Registrar
            foreach (var k in registrarKeys) if (StartsWithI(line, k)) { Registrar = line.Substring(k.Length).Trim(); goto next; }

            // Created
            foreach (var k in createdKeys) if (StartsWithI(line, k)) { CreationDate = line.Substring(k.Length).Trim(); goto next; }

            // Updated
            foreach (var k in updatedKeys) if (StartsWithI(line, k)) { LastUpdated = line.Substring(k.Length).Trim(); goto next; }

            // Expiry
            foreach (var k in expiryKeys) if (StartsWithI(line, k)) { SetExpiryDate(line.Substring(k.Length).Trim()); goto next; }

            // Name server single-line
            foreach (var k in nsLineKeys) if (StartsWithI(line, k)) { NameServers.Add(line.Substring(k.Length).Trim()); goto next; }

            // Nameserver block
            foreach (var k in nsBlockKeys) if (StartsWithI(line, k)) { inNsBlock = true; var rest = line.Substring(k.Length).Trim(); if (!string.IsNullOrWhiteSpace(rest)) NameServers.Add(rest); goto next; }
            if (inNsBlock) {
                // Heuristic: hostname with a dot
                if (line.Contains('.')) NameServers.Add(line);
                goto next;
            }

            // Abuse contacts
            if (StartsWithI(line, "Registrar Abuse Contact Email:")) {
                var value = line.Substring("Registrar Abuse Contact Email:".Length).Trim();
                RegistrarEmail = value; RegistrarAbuseEmail = value; goto next;
            }
            if (StartsWithI(line, "Registrar Abuse Contact Phone:")) {
                var value = line.Substring("Registrar Abuse Contact Phone:".Length).Trim();
                RegistrarTel = value; RegistrarAbusePhone = value; goto next;
            }

            // Registrant
            if (StartsWithI(line, "Registrant Organization:")) { RegisteredTo = line.Substring("Registrant Organization:".Length).Trim(); goto next; }
            if (StartsWithI(line, "Registrant Country:")) { Country = line.Substring("Registrant Country:".Length).Trim(); goto next; }

            // DNSSEC
            foreach (var k in dnssecKeys) if (StartsWithI(line, k)) { DnsSec = line.Substring(k.Length).Trim(); goto next; }

            next: ;
        }
    }

    private static bool IsEuCctld(string tld)
        => string.Equals(tld, "eu", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "se", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "no", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "dk", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "fi", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "ie", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "pt", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "gr", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "lt", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "lv", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "ee", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "si", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "sk", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "ro", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "hu", StringComparison.OrdinalIgnoreCase)
           || string.Equals(tld, "pl", StringComparison.OrdinalIgnoreCase);

    private void ParseWhoisDataEUGeneric()
    {
        // Broad EU-style WHOIS parsing with common synonyms
        WhoisData = System.Text.RegularExpressions.Regex.Replace(WhoisData, "\r\n|\n|\r", "\n", System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.Multiline);
        static bool StartsWithI(string s, string prefix) => s.StartsWith(prefix, System.StringComparison.OrdinalIgnoreCase);
        foreach (var raw in WhoisData.Split('\n'))
        {
            var line = raw.Trim();
            if (string.IsNullOrEmpty(line)) continue;
            ParseRegistrarLicense(line);
            if (StartsWithI(line, "domain:")) { DomainName = line.Substring(7).Trim(); continue; }
            if (StartsWithI(line, "Domain:")) { DomainName = line.Substring(7).Trim(); continue; }
            if (StartsWithI(line, "nserver:") || StartsWithI(line, "name server:")) { var idx=line.IndexOf(':'); if (idx>0) NameServers.Add(line.Substring(idx+1).Trim()); continue; }
            if (StartsWithI(line, "expires:") || StartsWithI(line, "Expiry Date:") || StartsWithI(line, "Expiration Date:")) { var idx=line.IndexOf(':'); if (idx>0) SetExpiryDate(line.Substring(idx+1).Trim()); continue; }
            if (StartsWithI(line, "dnssec:")) { var idx=line.IndexOf(':'); if (idx>0) DnsSec = line.Substring(idx+1).Trim(); continue; }
            if (StartsWithI(line, "registrar:")) { var idx=line.IndexOf(':'); if (idx>0) Registrar = line.Substring(idx+1).Trim(); continue; }
        }
        UpdateExpiryFlags();
        UpdateRegistrarLock();
        UpdatePrivacyFlag();
    }

    private void ParseWhoisDataDE() {
        foreach (var raw in WhoisData.Split('\n')) {
            var line = raw.Trim();
            ParseRegistrarLicense(line);
            if (line.StartsWith("DOMAIN:", StringComparison.OrdinalIgnoreCase)) {
                var idx = line.IndexOf(':');
                DomainName = line.Substring(idx + 1).Trim();
            } else if (line.StartsWith("CHANGED:", StringComparison.OrdinalIgnoreCase)) {
                var idx = line.IndexOf(':');
                LastUpdated = line.Substring(idx + 1).Trim();
            } else if (line.StartsWith("NSERVER:", StringComparison.OrdinalIgnoreCase) || line.StartsWith("Nserver:", StringComparison.OrdinalIgnoreCase)) {
                var idx = line.IndexOf(':');
                NameServers.Add(line.Substring(idx + 1).Trim());
            }
        }
    }

    private void ParseWhoisDataXYZ() {
        // Normalize line endings to \n
        WhoisData = Regex.Replace(
            WhoisData,
            "\r\n|\n|\r",
            "\n",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        foreach (var line in WhoisData.Split('\n')) {
            var trimmedLine = line.Trim();
            ParseRegistrarLicense(trimmedLine);

            if (trimmedLine.StartsWith("Domain Name:")) {
                DomainName = trimmedLine.Substring("Domain Name:".Length).Trim();
            } else if (trimmedLine.StartsWith("Registrar:")) {
                Registrar = trimmedLine.Substring("Registrar:".Length).Trim();
            } else if (trimmedLine.StartsWith("Creation Date:")) {
                CreationDate = trimmedLine.Substring("Creation Date:".Length).Trim();
            } else if (trimmedLine.StartsWith("Registry Expiry Date:")) {
                SetExpiryDate(trimmedLine.Substring("Registry Expiry Date:".Length).Trim());
            } else if (trimmedLine.StartsWith("Updated Date:")) {
                LastUpdated = trimmedLine.Substring("Updated Date:".Length).Trim();
            } else if (trimmedLine.StartsWith("Name Server:")) {
                NameServers.Add(trimmedLine.Substring("Name Server:".Length).Trim());
            } else if (trimmedLine.StartsWith("Registrant Organization:")) {
                RegisteredTo = trimmedLine.Substring("Registrant Organization:".Length).Trim();
            } else if (trimmedLine.StartsWith("Registrant Country:")) {
                Country = trimmedLine.Substring("Registrant Country:".Length).Trim();
            } else if (trimmedLine.StartsWith("Registrar Abuse Contact Email:")) {
                var value = trimmedLine.Substring("Registrar Abuse Contact Email:".Length).Trim();
                RegistrarEmail = value;
                RegistrarAbuseEmail = value;
            } else if (trimmedLine.StartsWith("Registrar Abuse Contact Phone:")) {
                var value = trimmedLine.Substring("Registrar Abuse Contact Phone:".Length).Trim();
                RegistrarTel = value;
                RegistrarAbusePhone = value;
            }
        }
    }

    private void ParseWhoisDataPL() {
        // Parse WHOIS data for .pl domains
        WhoisData = Regex.Replace(
            WhoisData,
            "\r\n|\n|\r",
            "\n",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        bool isParsingNameServers = false;
        bool isParsingRegistrar = false;

        foreach (var line in WhoisData.Split('\n')) {
            var trimmedLine = line.Trim();
            ParseRegistrarLicense(trimmedLine);

            if (trimmedLine.StartsWith("DOMAIN NAME:")) {
                DomainName = trimmedLine.Substring("DOMAIN NAME:".Length).Trim();
            } else if (trimmedLine.StartsWith("created:")) {
                CreationDate = trimmedLine.Substring("created:".Length).Trim();
            } else if (trimmedLine.StartsWith("renewal date:")) {
                SetExpiryDate(trimmedLine.Substring("renewal date:".Length).Trim());
            } else if (trimmedLine.StartsWith("registrant type:")) {
                RegistrantType = trimmedLine.Substring("registrant type:".Length).Trim();
            } else if (trimmedLine.StartsWith("last modified:")) {
                LastUpdated = trimmedLine.Substring("last modified:".Length).Trim();
            } else if (trimmedLine.StartsWith("dnssec:")) {
                DnsSec = trimmedLine.Substring("dnssec:".Length).Trim();
            } else if (trimmedLine.StartsWith("DS:")) {
                DnsRecord = trimmedLine.Substring("DS:".Length).Trim();
            } else if (trimmedLine.StartsWith("nameservers:")) {
                isParsingNameServers = true;
                NameServers.Add(trimmedLine.Substring("nameservers:".Length).Trim());
            } else if (isParsingNameServers) {
                if (trimmedLine.EndsWith(".")) {
                    NameServers.Add(trimmedLine);
                } else {
                    isParsingNameServers = false;
                }
            } else if (trimmedLine.StartsWith("REGISTRAR:")) {
                isParsingRegistrar = true;
                Registrar = trimmedLine.Substring("REGISTRAR:".Length).Trim();
            } else if (isParsingRegistrar) {
                if (trimmedLine.StartsWith("Tel:")) {
                    RegistrarTel = trimmedLine.Substring("Tel:".Length).Trim();
                } else if (trimmedLine.StartsWith("https://")) {
                    RegistrarWebsite = trimmedLine;
                } else {
                    RegistrarAddress = trimmedLine;
                }
            }
        }
    }

    private void ParseWhoisDataBE() {
        // Normalize line endings to \n
        WhoisData = Regex.Replace(
            WhoisData,
            "\r\n|\n|\r",
            "\n",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        bool isParsingNameServers = false;
        bool isParsingRegistrar = false;

        foreach (var line in WhoisData.Split('\n')) {
            var trimmedLine = line.Trim();
            ParseRegistrarLicense(trimmedLine);

            if (trimmedLine.StartsWith("Domain:")) {
                DomainName = trimmedLine.Substring("Domain:".Length).Trim();
            } else if (trimmedLine.StartsWith("Registered:")) {
                CreationDate = trimmedLine.Substring("Registered:".Length).Trim();
            } else if (trimmedLine.StartsWith("Registrar:")) {
                isParsingRegistrar = true;
            } else if (isParsingRegistrar) {
                if (trimmedLine.StartsWith("Name:")) {
                    Registrar = trimmedLine.Substring("Name:".Length).Trim();
                } else if (trimmedLine.StartsWith("Website:")) {
                    RegistrarWebsite = trimmedLine.Substring("Website:".Length).Trim();
                } else {
                    isParsingRegistrar = false;
                }
            } else if (trimmedLine.StartsWith("Nameservers:")) {
                isParsingNameServers = true;
            } else if (isParsingNameServers) {
                if (!string.IsNullOrWhiteSpace(trimmedLine)) {
                    NameServers.Add(trimmedLine);
                } else {
                    isParsingNameServers = false;
                }
            } else if (trimmedLine.StartsWith("Flags:")) {
                DnsSec = trimmedLine.Substring("Flags:".Length).Trim();
            }
        }
    }

    private void ParseWhoisDataFR() {
        // AFNIC style
        WhoisData = Regex.Replace(WhoisData, "\r\n|\n|\r", "\n", RegexOptions.CultureInvariant | RegexOptions.Multiline);
        foreach (var line in WhoisData.Split('\n')) {
            var t = line.Trim();
            ParseRegistrarLicense(t);
            if (t.StartsWith("domain:", StringComparison.OrdinalIgnoreCase)) {
                DomainName = t.Substring(7).Trim();
            } else if (t.StartsWith("nserver:", StringComparison.OrdinalIgnoreCase)) {
                NameServers.Add(t.Substring(8).Trim());
            } else if (t.StartsWith("created:", StringComparison.OrdinalIgnoreCase)) {
                CreationDate = t.Substring(8).Trim();
            } else if (t.StartsWith("last-update:", StringComparison.OrdinalIgnoreCase)) {
                LastUpdated = t.Substring(12).Trim();
            } else if (t.StartsWith("Expiry Date:", StringComparison.OrdinalIgnoreCase) || t.StartsWith("expires:", StringComparison.OrdinalIgnoreCase)) {
                var v = t.IndexOf(':') >= 0 ? t.Substring(t.IndexOf(':') + 1).Trim() : t;
                SetExpiryDate(v);
            } else if (t.StartsWith("registrar:", StringComparison.OrdinalIgnoreCase)) {
                Registrar = t.Substring(10).Trim();
            }
        }
    }

    private void ParseWhoisDataES() {
        WhoisData = Regex.Replace(WhoisData, "\r\n|\n|\r", "\n", RegexOptions.CultureInvariant | RegexOptions.Multiline);
        foreach (var line in WhoisData.Split('\n')) {
            var t = line.Trim();
            ParseRegistrarLicense(t);
            if (t.StartsWith("Domain name:", StringComparison.OrdinalIgnoreCase)) {
                DomainName = t.Substring("Domain name:".Length).Trim();
            } else if (t.StartsWith("Creation date:", StringComparison.OrdinalIgnoreCase)) {
                CreationDate = t.Substring("Creation date:".Length).Trim();
            } else if (t.StartsWith("Expiration date:", StringComparison.OrdinalIgnoreCase) || t.StartsWith("Expiry Date:", StringComparison.OrdinalIgnoreCase)) {
                var v = t.Substring(t.IndexOf(':') + 1).Trim();
                SetExpiryDate(v);
            } else if (t.StartsWith("Name servers:", StringComparison.OrdinalIgnoreCase)) {
                // following lines until blank are ns
                continue;
            } else if (t.StartsWith("ns", StringComparison.OrdinalIgnoreCase) && t.Contains('.')) {
                NameServers.Add(t);
            }
        }
    }

    private void ParseWhoisDataIT() {
        WhoisData = Regex.Replace(WhoisData, "\r\n|\n|\r", "\n", RegexOptions.CultureInvariant | RegexOptions.Multiline);
        foreach (var line in WhoisData.Split('\n')) {
            var t = line.Trim();
            ParseRegistrarLicense(t);
            if (t.StartsWith("Domain:", StringComparison.OrdinalIgnoreCase)) {
                DomainName = t.Substring("Domain:".Length).Trim();
            } else if (t.StartsWith("Created:", StringComparison.OrdinalIgnoreCase)) {
                CreationDate = t.Substring("Created:".Length).Trim();
            } else if (t.StartsWith("Expire Date:", StringComparison.OrdinalIgnoreCase)) {
                SetExpiryDate(t.Substring("Expire Date:".Length).Trim());
            } else if (t.StartsWith("Updated:", StringComparison.OrdinalIgnoreCase)) {
                LastUpdated = t.Substring("Updated:".Length).Trim();
            } else if (t.StartsWith("Nameservers", StringComparison.OrdinalIgnoreCase)) {
                continue;
            } else if (t.EndsWith(".it", StringComparison.OrdinalIgnoreCase) && t.Contains('.')) {
                // rough capture of nameserver lines
                NameServers.Add(t);
            }
        }
    }

    private void ParseWhoisDataNL() {
        WhoisData = Regex.Replace(WhoisData, "\r\n|\n|\r", "\n", RegexOptions.CultureInvariant | RegexOptions.Multiline);
        foreach (var line in WhoisData.Split('\n')) {
            var t = line.Trim();
            ParseRegistrarLicense(t);
            if (t.StartsWith("Domain name:", StringComparison.OrdinalIgnoreCase)) {
                DomainName = t.Substring("Domain name:".Length).Trim();
            } else if (t.StartsWith("Registrar:", StringComparison.OrdinalIgnoreCase)) {
                Registrar = t.Substring("Registrar:".Length).Trim();
            } else if (t.StartsWith("DNSSEC:", StringComparison.OrdinalIgnoreCase)) {
                DnsSec = t.Substring("DNSSEC:".Length).Trim();
            } else if (t.StartsWith("Updated on:", StringComparison.OrdinalIgnoreCase)) {
                LastUpdated = t.Substring("Updated on:".Length).Trim();
            } else if (t.StartsWith("Nameservers:", StringComparison.OrdinalIgnoreCase)) {
                continue;
            } else if (t.Contains('.') && (t.StartsWith("ns", StringComparison.OrdinalIgnoreCase) || t.EndsWith("."))) {
                NameServers.Add(t);
            }
        }
    }

    private void UpdateExpiryFlags() {
        ExpiresSoon = false;
        IsExpired = false;
        DaysUntilExpiration = null;
        if (!string.IsNullOrWhiteSpace(ExpiryDate) &&
            DateTime.TryParse(ExpiryDate, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var expiry)) {
            var delta = expiry - DateTime.UtcNow;
            DaysUntilExpiration = delta >= TimeSpan.Zero
                ? (int)Math.Ceiling(delta.TotalDays)
                : (int)Math.Floor(delta.TotalDays);
            IsExpired = delta <= TimeSpan.Zero;
            ExpiresSoon = !IsExpired &&
                delta <= ExpirationWarningThreshold;
        }
    }

    private void UpdateRegistrarLock() {
        RegistrarLocked = false;
        foreach (var line in WhoisData.Split('\n')) {
            var trimmed = line.Trim();
            if (trimmed.IndexOf("transferprohibited", StringComparison.OrdinalIgnoreCase) >= 0 ||
                trimmed.IndexOf("status: locked", StringComparison.OrdinalIgnoreCase) >= 0) {
                RegistrarLocked = true;
                break;
            }
        }
    }

    private void UpdatePrivacyFlag() {
        PrivacyProtected = false;
        foreach (var line in WhoisData.Split('\n')) {
            var trimmed = line.Trim();
            foreach (var indicator in _privacyIndicators) {
                if (trimmed.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0) {
                    PrivacyProtected = true;
                    return;
                }
            }
        }
    }

    /// <summary>
    /// Queries ARIN, RIPE and APNIC WHOIS servers for IP information.
    /// </summary>
    /// <param name="ipAddress">IP address to query.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>Tuple containing allocation and ASN when available.</returns>
    public async Task<(string? Allocation, string? Asn)> QueryIpWhois(string ipAddress, CancellationToken cancellationToken = default) {
        if (!IPAddress.TryParse(ipAddress, out _)) {
            throw new ArgumentException("Invalid IP address", nameof(ipAddress));
        }

        string? allocation = null;
        string? asn = null;

        List<string> servers;
        lock (_ipWhoisServersLock) {
            servers = new List<string>(IpWhoisServers);
        }

        foreach (var server in servers) {
            using var client = new TcpClient();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            try {
                var parts = server.Split(':');
                var host = parts[0];
                var port = 43;
                if (parts.Length > 1 && int.TryParse(parts[1], out var customPort)) {
                    port = customPort;
                }

                await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);

                using NetworkStream stream = client.GetStream();
                using (var writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { NewLine = "\r\n" }) {
                    await writer.WriteLineAsync(ipAddress).WaitWithCancellation(timeoutCts.Token);
                    await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                }

                await stream.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                using var ms = new MemoryStream();
                await stream.CopyToAsync(ms, 81920, timeoutCts.Token);
                var bytes = ms.ToArray();
                var response = Encoding.UTF8.GetString(bytes);
                if (response.Contains('\uFFFD')) {
                    response = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
                }

                foreach (var line in response.Split('\n')) {
                    var trimmed = line.Trim();
                    if (allocation == null &&
                        (trimmed.StartsWith("inetnum:", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("NetRange:", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("route:", StringComparison.OrdinalIgnoreCase))) {
                        var lineParts = trimmed.Split(':');
                        if (lineParts.Length > 1) {
                            allocation = lineParts[1].Trim();
                        }
                    } else if (asn == null &&
                        (trimmed.StartsWith("origin", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("OriginAS", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("aut-num:", StringComparison.OrdinalIgnoreCase))) {
                        var match = Regex.Match(trimmed, "AS\\d+", RegexOptions.IgnoreCase);
                        if (match.Success) {
                            asn = match.Value.ToUpperInvariant();
                        }
                    }

                    if (allocation != null && asn != null) {
                        break;
                    }
                }

                if (allocation != null && asn != null) {
                    break;
                }
            } catch (Exception ex) {
                _logger.WriteErrorCode(WhoisCodes.IpQueryFailed, "Error querying IP WHOIS server: {0}", ex.Message);
            }
        }

        return (allocation, asn);
    }

    /// <summary>
    /// Queries IANA RDAP for registrar information.
    /// </summary>
    public async Task QueryIana(string domain, CancellationToken cancellationToken = default) {
        string json;
        if (IanaQueryOverride != null) {
            json = await IanaQueryOverride(domain).ConfigureAwait(false);
        } else {
            var client = SharedHttpClient.Instance;
            try {
#if NETSTANDARD2_0 || NET472
                using var response = await client.GetAsync($"https://rdap.iana.org/domain/{domain}", cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) {
                    // Gracefully ignore 404/NotFound and other non-success responses
                    return;
                }
                json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
                json = await client.GetStringAsync($"https://rdap.iana.org/domain/{domain}", cancellationToken).ConfigureAwait(false);
#endif
            } catch (HttpRequestException ex) {
                // Ignore IANA RDAP failures; WHOIS data may still be valid
#if NET6_0_OR_GREATER
                if (ex.StatusCode.HasValue) return;
#endif
                return;
            }
        }

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("entities", out var entities)) {
            foreach (var ent in entities.EnumerateArray()) {
                if (ent.TryGetProperty("roles", out var roles)) {
                    foreach (var role in roles.EnumerateArray()) {
                        if (string.Equals(role.GetString(), "registrar", StringComparison.OrdinalIgnoreCase)) {
                            if (ent.TryGetProperty("handle", out var handle)) {
                                RegistrarId = handle.GetString();
                            }
                        }
                    }
                }
            }
        }

        if (string.IsNullOrEmpty(CreationDate) && doc.RootElement.TryGetProperty("events", out var events)) {
            foreach (var ev in events.EnumerateArray()) {
                if (ev.TryGetProperty("eventAction", out var action) &&
                    string.Equals(action.GetString(), "registration", StringComparison.OrdinalIgnoreCase) &&
                    ev.TryGetProperty("eventDate", out var date)) {
                    CreationDate = date.GetString();
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Saves the current WHOIS data snapshot to <see cref="SnapshotDirectory"/>.
    /// </summary>
    public void SaveSnapshot() {
        if (string.IsNullOrEmpty(SnapshotDirectory) || string.IsNullOrEmpty(DomainName) || string.IsNullOrEmpty(WhoisData)) {
            return;
        }
        Directory.CreateDirectory(SnapshotDirectory);
        var file = Path.Combine(SnapshotDirectory, $"{DomainName}_{DateTime.UtcNow:yyyyMMddHHmmss}.whois");
        File.WriteAllText(file, WhoisData, Encoding.UTF8);
    }

    /// <summary>
    /// Returns line level differences between the current WHOIS data and the last saved snapshot.
    /// </summary>
    public IEnumerable<string> GetWhoisChanges() {
        if (string.IsNullOrEmpty(SnapshotDirectory) || string.IsNullOrEmpty(DomainName)) {
            return Array.Empty<string>();
        }
        var files = Directory.GetFiles(SnapshotDirectory, $"{DomainName}_*.whois");
        if (files.Length == 0) {
            return Array.Empty<string>();
        }
        var previousFile = files.OrderByDescending(f => f).First();
        var previousData = File.ReadAllText(previousFile);
        var previousLines = previousData.Split('\n');
        var currentLines = WhoisData.Split('\n');
        var changes = new List<string>();
        var max = Math.Max(previousLines.Length, currentLines.Length);
        for (var i = 0; i < max; i++) {
            var prev = i < previousLines.Length ? previousLines[i] : string.Empty;
            var curr = i < currentLines.Length ? currentLines[i] : string.Empty;
            if (!string.Equals(prev, curr, StringComparison.Ordinal)) {
                changes.Add("- " + prev);
                changes.Add("+ " + curr);
            }
        }
        return changes;
    }

}

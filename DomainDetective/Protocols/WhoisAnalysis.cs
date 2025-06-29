using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Queries WHOIS servers and parses registration details.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class WhoisAnalysis {
    private string TLD { get; set; }
    private string _domainName;
    public string DomainName {
        get => _domainName;
        set => _domainName = value;
    }
    public string Tld => TLD;
    public string Registrar { get; set; }
    public string CreationDate { get; set; }
    public string ExpiryDate { get; set; }
    public string LastUpdated { get; set; }
    public string RegisteredTo { get; set; }
    public List<string> NameServers { get; set; } = new List<string>();
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public string RegistrantType { get; set; }
    public string Country { get; set; }
    public string DnsSec { get; set; }
    public string DnsRecord { get; set; }
    public string RegistrarAddress { get; set; }
    public string RegistrarTel { get; set; }
    public string RegistrarWebsite { get; set; }
    public string RegistrarLicense { get; set; }
    public string RegistrarEmail { get; set; }
    public string RegistrarAbuseEmail { get; set; }
    public string RegistrarAbusePhone { get; set; }
    public string WhoisData { get; set; }
    public bool ExpiresSoon { get; private set; }
    public bool IsExpired { get; private set; }
    public bool RegistrarLocked { get; private set; }
    public bool PrivacyProtected { get; private set; }
    public TimeSpan ExpirationWarningThreshold { get; set; } = TimeSpan.FromDays(30);
    public string? SnapshotDirectory { get; set; }

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

    private string GetWhoisServer(string domain) {
        var domainParts = domain.Split('.');
        var tld = string.Join(".", domainParts.Skip(1));
        TLD = tld;

        lock (_whoisServersLock) {
            if (WhoisServers.TryGetValue(tld, out var server)) {
                return server;
            }
        }

        tld = domainParts.Last();
        TLD = tld;
        lock (_whoisServersLock) {
            return WhoisServers.TryGetValue(tld, out var server) ? server : null;
        }
    }

    /// <summary>
    /// Queries a single WHOIS server for the specified domain.
    /// </summary>
    public async Task QueryWhoisServer(string domain, CancellationToken cancellationToken = default) {
        DomainName = domain;
        if (string.IsNullOrWhiteSpace(domain) || !domain.Contains('.')) {
            throw new UnsupportedTldException(domain, domain);
        }
        var whoisServer = GetWhoisServer(domain);
        if (whoisServer == null) {
            throw new UnsupportedTldException(domain, TLD);
        }


        using TcpClient tcpClient = new TcpClient();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);
        try {
            var serverParts = whoisServer.Split(':');
            var host = serverParts[0];
            var port = 43;
            if (serverParts.Length > 1 && int.TryParse(serverParts[1], out var customPort)) {
                port = customPort;
            }

            await tcpClient.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);

            using NetworkStream networkStream = tcpClient.GetStream();
            using (var streamWriter = new StreamWriter(networkStream, Encoding.ASCII, 1024, leaveOpen: true)) {
                await streamWriter.WriteLineAsync(domain).WaitWithCancellation(timeoutCts.Token);
                await streamWriter.FlushAsync().WaitWithCancellation(timeoutCts.Token);
            }

            await networkStream.FlushAsync().WaitWithCancellation(timeoutCts.Token);
            using var memoryStream = new MemoryStream();
            await networkStream.CopyToAsync(memoryStream, 81920, timeoutCts.Token);
            var responseBytes = memoryStream.ToArray();

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
            ParseWhoisData();
        } catch (Exception ex) {
            _logger.WriteError("Error querying WHOIS server: {0}", ex.Message);
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
        } else if (string.Equals(TLD, "co.uk", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataCOUK();
        } else if (string.Equals(TLD, "de", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataDE();
        } else if (string.Equals(TLD, "cz", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataCZ();
        } else if (string.Equals(TLD, "be", StringComparison.OrdinalIgnoreCase)) {
            ParseWhoisDataBE();
        } else {
            ParseWhoisDataDefault();
        }
        UpdateExpiryFlags();
        UpdateRegistrarLock();
        UpdatePrivacyFlag();
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
                            ExpiryDate = trimmedLine.Substring("Expiry date:".Length).Trim();
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
                ExpiryDate = trimmedLine.Substring("expire:".Length).Trim();
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
                    ExpiryDate = trimmedLine.Substring("expire:".Length).Trim();
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
                ExpiryDate = line.Substring("   Registry Expiry Date:".Length).Trim();
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
        // Parse WHOIS data for most TLDs
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
                ExpiryDate = trimmedLine.Substring("Registry Expiry Date:".Length).Trim();
            } else if (trimmedLine.StartsWith("Updated Date:")) {
                LastUpdated = trimmedLine.Substring("Updated Date:".Length).Trim();
            } else if (trimmedLine.StartsWith("Name Server:")) {
                NameServers.Add(trimmedLine.Substring("Name Server:".Length).Trim());
            } else if (trimmedLine.StartsWith("Registrar Abuse Contact Email:")) {
                var value = trimmedLine.Substring("Registrar Abuse Contact Email:".Length).Trim();
                RegistrarEmail = value;
                RegistrarAbuseEmail = value;
            } else if (trimmedLine.StartsWith("Registrar Abuse Contact Phone:")) {
                var value = trimmedLine.Substring("Registrar Abuse Contact Phone:".Length).Trim();
                RegistrarTel = value;
                RegistrarAbusePhone = value;
            } else if (trimmedLine.StartsWith("Registrant Organization:")) {
                RegisteredTo = trimmedLine.Substring("Registrant Organization:".Length).Trim();
            } else if (trimmedLine.StartsWith("Registrant Country:")) {
                Country = trimmedLine.Substring("Registrant Country:".Length).Trim();
            } else if (trimmedLine.StartsWith("DNSSEC:")) {
                DnsSec = trimmedLine.Substring("DNSSEC:".Length).Trim();
            }
        }
    }

    private void ParseWhoisDataDE() {
        foreach (var line in WhoisData.Split('\n')) {
            ParseRegistrarLicense(line.Trim());
            if (line.StartsWith("DOMAIN:")) {
                DomainName = line.Substring("DOMAIN:".Length).Trim();
            } else if (line.StartsWith("CHANGED:")) {
                LastUpdated = line.Substring("CHANGED:".Length).Trim();
            } else if (line.StartsWith("NSERVER:")) {
                NameServers.Add(line.Substring("NSERVER:".Length).Trim());
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
                ExpiryDate = trimmedLine.Substring("Registry Expiry Date:".Length).Trim();
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
                ExpiryDate = trimmedLine.Substring("renewal date:".Length).Trim();
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

    private void UpdateExpiryFlags() {
        ExpiresSoon = false;
        IsExpired = false;
        if (!string.IsNullOrWhiteSpace(ExpiryDate) &&
            DateTime.TryParse(ExpiryDate, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var expiry)) {
            IsExpired = expiry <= DateTime.UtcNow;
            ExpiresSoon = !IsExpired &&
                expiry <= DateTime.UtcNow + ExpirationWarningThreshold;
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
                using (var writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true)) {
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
                _logger.WriteError("Error querying IP WHOIS server: {0}", ex.Message);
            }
        }

        return (allocation, asn);
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
        File.WriteAllText(file, WhoisData);
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

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

public partial class WhoisAnalysis : IHasAssessments {
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
        using (var _collector = AssessmentCollector.ForAnalysis(_logger!, this, category: "WHOIS", target: DomainName))
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
            if (!IsExpired && !ExpiresSoon && DaysUntilExpiration.HasValue &&
                DaysUntilExpiration.Value > ExpirationLongTermThreshold.TotalDays)
            {
                _logger.WriteInformationCode(
                    WhoisCodes.ExpiryFuture,
                    "Domain expires in {0} days (on {1})",
                    DaysUntilExpiration?.ToString() ?? "?",
                    ExpiryDate ?? "unknown");
            }
            if (!PrivacyProtected && (!string.IsNullOrWhiteSpace(RegisteredTo) || !string.IsNullOrWhiteSpace(RegistrarEmail)))
            {
                _logger.WriteInformationCode(
                    WhoisCodes.ContactValid,
                    "WHOIS contact data present for {0}",
                    DomainName ?? "(unknown)");
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

        string? currentSection = null;
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
            } else if (line.StartsWith("   Registrant Organization:")) {
                RegisteredTo = line.Substring("   Registrant Organization:".Length).Trim();
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

}

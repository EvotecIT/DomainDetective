---
Module Name: DomainDetective
Module Guid: a2986f0d-da11-43f5-a252-f9e1d1699776
Download Help Link: https://github.com/EvotecIT/DomainDetective
Help Version: 1.0.0
Locale: en-US
---
# DomainDetective Module
## Description
DomainDetective is a PowerShell module that provides features to work with domains, DNS, and other related information.

## DomainDetective Cmdlets
### [Add-DDDnsblProvider](Add-DDDnsblProvider.md)
Adds a DNSBL provider entry to an analysis object.

### [Clear-DDDnsblProviderList](Clear-DDDnsblProviderList.md)
Removes all DNSBL providers from an analysis object.

### [Export-DDSecurityReport](Export-DDSecurityReport.md)
Composes a security report (Word/HTML) from pipeline view objects (SPF/DKIM/DMARC).

### [Get-DDApexAddressInfo](Get-DDApexAddressInfo.md)
Gets apex A/AAAA analysis including PTR, FCrDNS, ASN and RPKI details.

### [Get-DDCertificateInventoryCtDiagnostics](Get-DDCertificateInventoryCtDiagnostics.md)
Queries persisted native CT ingestion diagnostics captured with certificate inventory snapshots.

### [Get-DDCertificateInventoryCtHealth](Get-DDCertificateInventoryCtHealth.md)
Builds CT diagnostics health timeline from persisted certificate inventory snapshots.

### [Get-DDCertificateInventoryDiff](Get-DDCertificateInventoryDiff.md)
Compares two persisted certificate inventory snapshots and returns endpoint deltas.

### [Get-DDCertificateInventoryDrift](Get-DDCertificateInventoryDrift.md)
Builds endpoint-level certificate drift from persisted inventory snapshots.

### [Get-DDCertificateInventoryPolicy](Get-DDCertificateInventoryPolicy.md)
Evaluates certificate inventory snapshots against baseline policy profiles.

### [Get-DDCertificateInventoryPolicyDrift](Get-DDCertificateInventoryPolicyDrift.md)
Builds endpoint-level certificate policy drift between two persisted inventory snapshots.

### [Get-DDCertificateInventoryQuery](Get-DDCertificateInventoryQuery.md)
Queries persisted certificate inventory snapshots using structured filters.

### [Get-DDCertificateInventoryReuse](Get-DDCertificateInventoryReuse.md)
Builds certificate reuse and endpoint assignment mapping from persisted inventory snapshots.

### [Get-DDCertificateInventoryRisk](Get-DDCertificateInventoryRisk.md)
Builds endpoint-level certificate risk posture from persisted inventory snapshots.

### [Get-DDCertificateInventorySnapshot](Get-DDCertificateInventorySnapshot.md)
Reads persisted certificate inventory snapshots from local storage.

### [Get-DDCertificateInventorySummary](Get-DDCertificateInventorySummary.md)
Builds a certificate inventory summary from persisted monitor snapshots.

### [Get-DDDmarcAggregateTimeSeries](Get-DDDmarcAggregateTimeSeries.md)
Builds a DMARC Aggregate (RUA) time-series view from stored snapshots.

### [Get-DDDomainFlattenedSpfIp](Get-DDDomainFlattenedSpfIp.md)
Retrieves flattened SPF IP analysis for a domain.

### [Get-DDDomainWhois](Get-DDDomainWhois.md)
Retrieves WHOIS information for the specified domain.

### [Get-DDEmailMessageHeaderInfo](Get-DDEmailMessageHeaderInfo.md)
Parses raw email message headers.

### [Get-DDIdpInfo](Get-DDIdpInfo.md)
Retrieves identity provider (IdP) information for the specified domain.

### [Get-DDRdap](Get-DDRdap.md)
Queries RDAP registration information.

### [Get-DDRdapObject](Get-DDRdapObject.md)
Retrieves RDAP objects from a specified service.

### [Get-DDRegistrationDrift](Get-DDRegistrationDrift.md)
Builds a structured WHOIS/RDAP drift view from stored registration snapshots.

### [Get-DDSearchEngineInfo](Get-DDSearchEngineInfo.md)
Queries search engines for information.

### [Get-DDTlsCertificateInfo](Get-DDTlsCertificateInfo.md)
Returns details about a certificate file.

### [Get-DDTlsRptReportsTimeSeries](Get-DDTlsRptReportsTimeSeries.md)
Builds a TLS-RPT Reports time-series view from stored snapshots.

### [Import-DDDmarcAggregateSnapshot](Import-DDDmarcAggregateSnapshot.md)
Imports DMARC aggregate reports into a time-series store.

### [Import-DDDmarcForensic](Import-DDDmarcForensic.md)
Parses zipped DMARC forensic reports.

### [Import-DDDmarcReport](Import-DDDmarcReport.md)
Parses zipped DMARC feedback reports.

### [Import-DDDnsblConfig](Import-DDDnsblConfig.md)
Imports DNSBL provider configuration from a file.

### [Import-DDEmailTlsRpt](Import-DDEmailTlsRpt.md)
Imports TLSRPT JSON reports.

### [Import-DDRegistrationSnapshot](Import-DDRegistrationSnapshot.md)
Captures a unified WHOIS/RDAP registration snapshot and stores it in a time-series store.

### [Import-DDTlsRptReportSnapshot](Import-DDTlsRptReportSnapshot.md)
Imports TLS-RPT JSON reports into a time-series store.

### [Invoke-DDCertificateInventory](Invoke-DDCertificateInventory.md)
Captures and optionally persists a certificate inventory snapshot from domains and discovered endpoints.

### [Invoke-DDDomainWizard](Invoke-DDDomainWizard.md)
Starts an interactive wizard to run domain checks.

### [New-DDDesiredState](New-DDDesiredState.md)
Creates a desired state configuration object for use with DomainDetective.

### [New-DDDesiredStateAgentReadiness](New-DDDesiredStateAgentReadiness.md)
Creates an agent readiness desired state policy fragment.

### [New-DDDesiredStateApexAddress](New-DDDesiredStateApexAddress.md)
Creates an apex address desired state policy fragment.

### [New-DDDesiredStateAssessmentPolicy](New-DDDesiredStateAssessmentPolicy.md)
Creates an assessment policy desired state fragment.

### [New-DDDesiredStateAutodiscover](New-DDDesiredStateAutodiscover.md)
Creates an Autodiscover desired state policy fragment.

### [New-DDDesiredStateBestPractices](New-DDDesiredStateBestPractices.md)
Creates best-practice settings for Desired State evaluation.

### [New-DDDesiredStateBimi](New-DDDesiredStateBimi.md)
Creates a BIMI desired state policy fragment.

### [New-DDDesiredStateCaa](New-DDDesiredStateCaa.md)
Creates a CAA desired state policy fragment.

### [New-DDDesiredStateCertificateInventory](New-DDDesiredStateCertificateInventory.md)
Creates a certificate inventory desired state policy fragment.

### [New-DDDesiredStateChecks](New-DDDesiredStateChecks.md)
Creates a desired state fragment that controls which checks are executed.

### [New-DDDesiredStateDane](New-DDDesiredStateDane.md)
Creates a DANE desired state policy fragment.

### [New-DDDesiredStateDanglingCname](New-DDDesiredStateDanglingCname.md)
Creates a dangling CNAME desired state policy fragment.

### [New-DDDesiredStateDelegation](New-DDDesiredStateDelegation.md)
Creates a delegation desired state policy fragment.

### [New-DDDesiredStateDkim](New-DDDesiredStateDkim.md)
Creates a DKIM desired state policy fragment.

### [New-DDDesiredStateDmarc](New-DDDesiredStateDmarc.md)
Creates a DMARC desired state policy fragment.

### [New-DDDesiredStateDnsbl](New-DDDesiredStateDnsbl.md)
Creates a DNSBL desired state policy fragment.

### [New-DDDesiredStateDnsHealth](New-DDDesiredStateDnsHealth.md)
Creates a DNS health desired state policy fragment.

### [New-DDDesiredStateDnsOverTls](New-DDDesiredStateDnsOverTls.md)
Creates a DNS over TLS desired state policy fragment.

### [New-DDDesiredStateDnssec](New-DDDesiredStateDnssec.md)
Creates a DNSSEC desired state policy fragment.

### [New-DDDesiredStateEdnsSupport](New-DDDesiredStateEdnsSupport.md)
Creates an EDNS support desired state policy fragment.

### [New-DDDesiredStateFcrDns](New-DDDesiredStateFcrDns.md)
Creates an FCrDNS desired state policy fragment.

### [New-DDDesiredStateFlatteningService](New-DDDesiredStateFlatteningService.md)
Creates a flattening service desired state policy fragment.

### [New-DDDesiredStateImapTls](New-DDDesiredStateImapTls.md)
Creates an IMAP TLS desired state policy fragment.

### [New-DDDesiredStateMailLatency](New-DDDesiredStateMailLatency.md)
Creates a mail latency desired state policy fragment.

### [New-DDDesiredStateMtasts](New-DDDesiredStateMtasts.md)
Creates an MTA-STS desired state policy fragment.

### [New-DDDesiredStateMx](New-DDDesiredStateMx.md)
Creates an MX desired state policy fragment.

### [New-DDDesiredStateNs](New-DDDesiredStateNs.md)
Creates an NS desired state policy fragment.

### [New-DDDesiredStateOpenRelay](New-DDDesiredStateOpenRelay.md)
Creates an open relay desired state policy fragment.

### [New-DDDesiredStateOpenResolver](New-DDDesiredStateOpenResolver.md)
Creates an open resolver desired state policy fragment.

### [New-DDDesiredStateOverride](New-DDDesiredStateOverride.md)
Creates a desired state override (domain and/or classification specific).

### [New-DDDesiredStatePop3Tls](New-DDDesiredStatePop3Tls.md)
Creates a POP3 TLS desired state policy fragment.

### [New-DDDesiredStateReverseDns](New-DDDesiredStateReverseDns.md)
Creates a reverse DNS desired state policy fragment.

### [New-DDDesiredStateRobots](New-DDDesiredStateRobots.md)
Creates a robots.txt desired state policy fragment.

### [New-DDDesiredStateRpki](New-DDDesiredStateRpki.md)
Creates an RPKI desired state policy fragment.

### [New-DDDesiredStateSecurityTxt](New-DDDesiredStateSecurityTxt.md)
Creates a security.txt desired state policy fragment.

### [New-DDDesiredStateSmtpAuth](New-DDDesiredStateSmtpAuth.md)
Creates an SMTP AUTH desired state policy fragment.

### [New-DDDesiredStateSmtpBanner](New-DDDesiredStateSmtpBanner.md)
Creates an SMTP banner desired state policy fragment.

### [New-DDDesiredStateSmtpTls](New-DDDesiredStateSmtpTls.md)
Creates an SMTP TLS desired state policy fragment.

### [New-DDDesiredStateSoa](New-DDDesiredStateSoa.md)
Creates an SOA desired state policy fragment.

### [New-DDDesiredStateSpf](New-DDDesiredStateSpf.md)
Creates an SPF desired state policy fragment.

### [New-DDDesiredStateStartTls](New-DDDesiredStateStartTls.md)
Creates a STARTTLS desired state policy fragment.

### [New-DDDesiredStateTlsRpt](New-DDDesiredStateTlsRpt.md)
Creates a TLS-RPT desired state policy fragment.

### [New-DDDesiredStateTtl](New-DDDesiredStateTtl.md)
Creates a DNS TTL desired state policy fragment.

### [New-DDDesiredStateWildcardDns](New-DDDesiredStateWildcardDns.md)
Creates a wildcard DNS desired state policy fragment.

### [New-DDDesiredStateZoneTransfer](New-DDDesiredStateZoneTransfer.md)
Creates a zone transfer desired state policy fragment.

### [New-DDDmarcRecord](New-DDDmarcRecord.md)
Builds a DMARC record string.

### [Remove-DDDnsblProvider](Remove-DDDnsblProvider.md)
Removes a DNSBL provider entry from an analysis object.

### [Set-DDExportOptions](Set-DDExportOptions.md)
Sets global export defaults for DomainDetective reports.

### [Set-DDPersona](Set-DDPersona.md)
Enables, configures, or disables narration personas.

### [Start-DDDnsPropagationMonitor](Start-DDDnsPropagationMonitor.md)
Starts background monitoring of DNS propagation.

### [Start-DDUptimeMonitor](Start-DDUptimeMonitor.md)
Starts background HTTP(S) uptime monitoring for one or more URLs.

### [Stop-DDDnsPropagationMonitor](Stop-DDDnsPropagationMonitor.md)
Stops a running DNS propagation monitor.

### [Stop-DDUptimeMonitor](Stop-DDUptimeMonitor.md)
Stops a running uptime monitor.

### [Test-DDAgentReadiness](Test-DDAgentReadiness.md)
Assesses whether a website exposes machine-readable resources useful to AI crawlers and agents.

### [Test-DDDesiredState](Test-DDDesiredState.md)
Validates domains against an organization-specific desired state baseline.

### [Test-DDDirectoryExposure](Test-DDDirectoryExposure.md)
Scans common web directories for exposure.

### [Test-DDDmarcAggregate](Test-DDDmarcAggregate.md)
Cmdlet to parse DMARC aggregate reports and summarize failures.

### [Test-DDDnsAmplification](Test-DDDnsAmplification.md)
Evaluates DNS amplification posture for a domain's authoritative name servers.

### [Test-DDDnsBlacklist](Test-DDDnsBlacklist.md)
Queries DNSBL providers to see if domains or IPs are listed.

### [Test-DDDnsCaaRecord](Test-DDDnsCaaRecord.md)
Validates CAA records for a domain.

### [Test-DDDnsDanglingCname](Test-DDDnsDanglingCname.md)
Checks for dangling CNAME records on a domain.

### [Test-DDDnsDelegation](Test-DDDnsDelegation.md)
Validates delegation records for a domain.

### [Test-DDDnsEdnsSupport](Test-DDDnsEdnsSupport.md)
Tests EDNS support on authoritative name servers.

### [Test-DDDnsForwardReverse](Test-DDDnsForwardReverse.md)
Validates forward-confirmed reverse DNS for MX hosts.

### [Test-DDDnsHealth](Test-DDDnsHealth.md)
Runs authoritative DNS health checks (SOA serial skew, apex A/AAAA consistency).

### [Test-DDDnsMxRecord](Test-DDDnsMxRecord.md)
Retrieves MX records for a domain.

### [Test-DDDnsNsRecord](Test-DDDnsNsRecord.md)
Retrieves NS records for a domain.

### [Test-DDDnsOpenResolver](Test-DDDnsOpenResolver.md)
Checks if a DNS server allows recursive queries.

### [Test-DDDnsOverTls](Test-DDDnsOverTls.md)
Detects DNS over TLS (DoT, RFC 7858) support on a domain's authoritative name servers.

### [Test-DDDnsPropagation](Test-DDDnsPropagation.md)
Checks how DNS records propagate across public resolvers.

### [Test-DDDnsReverseDns](Test-DDDnsReverseDns.md)
Validates PTR records for MX hosts.

### [Test-DDDnsSecStatus](Test-DDDnsSecStatus.md)
Validates DNSSEC configuration for a domain.

### [Test-DDDnsSmimeaRecord](Test-DDDnsSmimeaRecord.md)
Validates SMIMEA records for the given email address.

### [Test-DDDnsSoaRecord](Test-DDDnsSoaRecord.md)
Retrieves the SOA record for a domain.

### [Test-DDDnsTtl](Test-DDDnsTtl.md)
Analyzes DNS TTL values for a domain.

### [Test-DDDnsTunneling](Test-DDDnsTunneling.md)
Analyzes DNS logs for tunneling patterns.

### [Test-DDDnsWildcard](Test-DDDnsWildcard.md)
Detects wildcard DNS responses by querying random subdomains.

### [Test-DDDnsZoneTransfer](Test-DDDnsZoneTransfer.md)
Attempts zone transfers against authoritative name servers.

### [Test-DDDomainCertificate](Test-DDDomainCertificate.md)
Validates TLS certificate for a website.

### [Test-DDDomainContactRecord](Test-DDDomainContactRecord.md)
Retrieves contact TXT information for a domain.

### [Test-DDDomainOverallHealth](Test-DDDomainOverallHealth.md)
Runs multiple domain health checks and returns the results.

### [Test-DDDomainSecurityTxt](Test-DDDomainSecurityTxt.md)
Retrieves security.txt information for a domain.

### [Test-DDDomainThreatIntel](Test-DDDomainThreatIntel.md)
Queries reputation services for a domain or IP address.

### [Test-DDDomainTyposquatting](Test-DDDomainTyposquatting.md)
Generates and evaluates typosquatting candidates for a domain.

### [Test-DDEmailAddress](Test-DDEmailAddress.md)
Validates an email address using syntax, DNS, and optional SMTP checks.

### [Test-DDEmailArcRecord](Test-DDEmailArcRecord.md)
Validates ARC headers from raw input.

### [Test-DDEmailAutoDiscover](Test-DDEmailAutoDiscover.md)
Checks Autodiscover related DNS records.

### [Test-DDEmailBimiRecord](Test-DDEmailBimiRecord.md)
Validates BIMI record for the specified domain.

### [Test-DDEmailDkimRecord](Test-DDEmailDkimRecord.md)
Validates DKIM records for the specified selectors.

### [Test-DDEmailDmarcRecord](Test-DDEmailDmarcRecord.md)
Validates DMARC record for a domain.

### [Test-DDEmailImapTls](Test-DDEmailImapTls.md)
Checks TLS configuration for a specific IMAP host.

### [Test-DDEmailLatency](Test-DDEmailLatency.md)
Measures SMTP connection and banner latency.

### [Test-DDEmailMtaSts](Test-DDEmailMtaSts.md)
Verifies MTA-STS policy for one or more domains.

### [Test-DDEmailOpenRelay](Test-DDEmailOpenRelay.md)
Checks if an SMTP server is an open relay.

### [Test-DDEmailPop3Tls](Test-DDEmailPop3Tls.md)
Checks TLS configuration for a specific POP3 host.

### [Test-DDEmailProtocolTls](Test-DDEmailProtocolTls.md)
Checks SMTP/IMAP/POP3 TLS configuration for a domain.

### [Test-DDEmailSmtpAuth](Test-DDEmailSmtpAuth.md)
Enumerates SMTP AUTH mechanisms across MX hosts.

### [Test-DDEmailSmtpBanner](Test-DDEmailSmtpBanner.md)
Retrieves SMTP banner information from a host or across MX hosts.

### [Test-DDEmailSmtpTls](Test-DDEmailSmtpTls.md)
Checks TLS configuration for a specific SMTP host.

### [Test-DDEmailSpfRecord](Test-DDEmailSpfRecord.md)
Validates SPF record for a domain.

### [Test-DDEmailStartTls](Test-DDEmailStartTls.md)
Checks SMTP STARTTLS support for a domain.

### [Test-DDEmailTlsRptRecord](Test-DDEmailTlsRptRecord.md)
Validates TLS-RPT record for a domain.

### [Test-DDMailDomainClassification](Test-DDMailDomainClassification.md)
Classifies a domain's mail role based on DNS signals.

### [Test-DDNetworkIpNeighbor](Test-DDNetworkIpNeighbor.md)
Lists domains hosted on the same IP.

### [Test-DDNetworkPortAvailability](Test-DDNetworkPortAvailability.md)
Checks connectivity to common service ports on a host.

### [Test-DDNetworkPortScan](Test-DDNetworkPortScan.md)
Scans a host for open TCP/UDP ports.

### [Test-DDRpki](Test-DDRpki.md)
Validates RPKI origins for domain IPs.

### [Test-DDSitemap](Test-DDSitemap.md)
Validates sitemap XML and sitemap-listed URLs.

### [Test-DDSpfHost](Test-DDSpfHost.md)
Tests an IP/sender/HELO against a domain's SPF policy.

### [Test-DDTlsDaneRecord](Test-DDTlsDaneRecord.md)
Validates DANE TLSA records for the given domain.

### [Test-DDWebsite](Test-DDWebsite.md)
Runs both web certificate and HTTPS security checks.

### [Test-DDWebsiteSecurity](Test-DDWebsiteSecurity.md)
Checks HTTPS security headers and mixed content for a domain.

### [Test-DDWebsiteStaticScan](Test-DDWebsiteStaticScan.md)
Runs a static (non-browser) web scan for a URL.

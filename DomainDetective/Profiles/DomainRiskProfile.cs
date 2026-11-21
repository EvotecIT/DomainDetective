using System;
using System.Collections.Generic;

namespace DomainDetective.Profiles;

/// <summary>How risky a domain looks overall.</summary>
public enum DomainRiskLevel {
    /// <summary>No risk signals were observed.</summary>
    None,
    /// <summary>Score above 0 and below 30.</summary>
    Low,
    /// <summary>Score from 30 to 54.</summary>
    Medium,
    /// <summary>Score from 55 to 74, or a live listing on a phishing or malware feed.</summary>
    High,
    /// <summary>Score of 75 or more.</summary>
    Critical
}

/// <summary>How much of the evidence a profile needs was actually seen.</summary>
public enum EvidenceConfidence {
    /// <summary>Below 0.50.</summary>
    Low,
    /// <summary>From 0.50 to 0.74, or capped because the level rests on one source.</summary>
    Medium,
    /// <summary>0.75 or more.</summary>
    High
}

/// <summary>State of one piece of evidence.</summary>
public enum EvidenceState {
    /// <summary>A value was returned.</summary>
    Observed,
    /// <summary>The source answered and found nothing. A negative answer is still evidence.</summary>
    Clean,
    /// <summary>Part of it came back, or the value is approximate.</summary>
    Partial,
    /// <summary>The source was queried but failed.</summary>
    Failed,
    /// <summary>The source was not queried: the check was not selected, or a key is missing.</summary>
    NotQueried,
    /// <summary>DomainDetective has no source for this.</summary>
    NotAvailable
}

/// <summary>A group of related evidence in a profile.</summary>
public enum ProfileFacetKind {
    /// <summary>Threat feeds and blocklists.</summary>
    Reputation,
    /// <summary>Registration data from RDAP and WHOIS.</summary>
    Registration,
    /// <summary>Certificate transparency history.</summary>
    Certificates,
    /// <summary>DNS records, DNSSEC and reverse DNS.</summary>
    Dns,
    /// <summary>Addresses, networks and hosting providers.</summary>
    Network,
    /// <summary>Website technologies.</summary>
    Web,
    /// <summary>Resolution history (passive DNS). Not collected by DomainDetective.</summary>
    History
}

/// <summary>
/// One domain's risk profile: what was observed about the domain, combined into a risk score, and a separate
/// confidence value for how much of the needed evidence was seen. Missing evidence lowers the confidence, never the
/// score. Configuration quality is graded separately by the assessment score.
/// </summary>
public sealed class DomainRiskProfile {
    /// <summary>Domain the profile describes.</summary>
    public string Domain { get; set; } = string.Empty;
    /// <summary>When the profile was evaluated.</summary>
    public DateTimeOffset EvaluatedAtUtc { get; set; }
    /// <summary>Version of the scoring rules. Scores compare only within one version.</summary>
    public string RuleVersion { get; set; } = string.Empty;
    /// <summary>Risk from 0 to 100, counting observed signals only.</summary>
    public int RiskScore { get; set; }
    /// <summary>Risk level from the score and any decisive signal.</summary>
    public DomainRiskLevel RiskLevel { get; set; }
    /// <summary>False when confidence is below 0.25: too little evidence to give a level.</summary>
    public bool Rated { get; set; }
    /// <summary>Confidence from 0 to 1, after any cap.</summary>
    public double ConfidenceScore { get; set; }
    /// <summary>Confidence from the evidence alone, before the single-source cap or the corroboration bonus.</summary>
    public double EvidenceScore { get; set; }
    /// <summary>Confidence level.</summary>
    public EvidenceConfidence Confidence { get; set; }
    /// <summary>When the level depends on one source alone, that source; confidence is then capped at Medium.</summary>
    public string? RestsOn { get; set; }
    /// <summary>True when the level holds without any single source.</summary>
    public bool Corroborated { get; set; }
    /// <summary>Everything that moved the score, largest first.</summary>
    public List<RiskSignal> Signals { get; set; } = new();
    /// <summary>Evidence grouped by facet.</summary>
    public List<ProfileFacet> Facets { get; set; } = new();
    /// <summary>What would raise confidence, largest gain first.</summary>
    public List<EvidenceGap> Gaps { get; set; } = new();
    /// <summary>
    /// Things worth watching that are not evidence against the domain itself, such as lookalike domains that imitate it.
    /// They never change the score.
    /// </summary>
    public List<string> Watch { get; set; } = new();
    /// <summary>Addresses behind the domain with network and hosting attribution.</summary>
    public List<ProfileAddress> Addresses { get; set; } = new();
    /// <summary>Website technologies detected, when the web scan ran.</summary>
    public List<string> Technologies { get; set; } = new();
    /// <summary>Certificate issuers seen in CT, most certificates first.</summary>
    public List<string> CertificateIssuers { get; set; } = new();
    /// <summary>Earliest CT entry for the domain or its subdomains.</summary>
    public DateTimeOffset? CtFirstSeenUtc { get; set; }
    /// <summary>Source of the CT history: <c>ddct-api</c>, <c>crt.sh</c> or <c>certspotter</c>.</summary>
    public string CtSource { get; set; } = string.Empty;
    /// <summary>Domain creation date from RDAP or WHOIS.</summary>
    public DateTimeOffset? RegisteredUtc { get; set; }
    /// <summary>Registrar name.</summary>
    public string Registrar { get; set; } = string.Empty;
}

/// <summary>One group of evidence and the risk points it contributed.</summary>
public sealed class ProfileFacet {
    /// <summary>Facet.</summary>
    public ProfileFacetKind Kind { get; set; }
    /// <summary>Core facets always count toward confidence; optional ones only when their source ran.</summary>
    public bool Core { get; set; }
    /// <summary>True when the facet counts toward confidence in this profile.</summary>
    public bool Counted { get; set; }
    /// <summary>Share of confidence.</summary>
    public double Weight { get; set; }
    /// <summary>How much of the facet's evidence was seen, 0 to 1.</summary>
    public double Coverage { get; set; }
    /// <summary>Risk points after the facet cap.</summary>
    public int RiskPoints { get; set; }
    /// <summary>The facet's evidence.</summary>
    public List<EvidenceItem> Evidence { get; set; } = new();
    /// <summary>Context shown with the facet but never scored.</summary>
    public List<ProfileFact> Facts { get; set; } = new();
}

/// <summary>One piece of evidence.</summary>
public sealed class EvidenceItem {
    /// <summary>Stable identifier, for example <c>reputation.gsb</c>.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Label.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>State.</summary>
    public EvidenceState State { get; set; }
    /// <summary>Weight inside its facet.</summary>
    public double Weight { get; set; }
    /// <summary>Source that supplied it, for example "RDAP" or "Google Safe Browsing".</summary>
    public string Source { get; set; } = string.Empty;
    /// <summary>Assessment check that holds the underlying evidence.</summary>
    public string? CheckKey { get; set; }
    /// <summary>Short qualifier, for example "registration country".</summary>
    public string? Note { get; set; }
}

/// <summary>Context shown with a facet.</summary>
public sealed class ProfileFact {
    /// <summary>Label.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>Value.</summary>
    public string Value { get; set; } = string.Empty;
    /// <summary>Qualifier, for example "registration country, not server location".</summary>
    public string? Note { get; set; }
}

/// <summary>Something observed that moved the risk score.</summary>
public sealed class RiskSignal {
    /// <summary>Stable identifier, for example <c>registration.age.under30d</c>.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Facet.</summary>
    public ProfileFacetKind Facet { get; set; }
    /// <summary>Points: positive raises risk, negative is a trust signal.</summary>
    public int Points { get; set; }
    /// <summary>A decisive signal holds the level at High or above.</summary>
    public bool Decisive { get; set; }
    /// <summary>Why, in plain words.</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>Source of the evidence, used to test whether the level rests on one source.</summary>
    public string Source { get; set; } = string.Empty;
    /// <summary>Assessment check that holds the evidence.</summary>
    public string? CheckKey { get; set; }
}

/// <summary>Evidence that was missing, and what seeing it would add to confidence.</summary>
public sealed class EvidenceGap {
    /// <summary>Evidence identifier.</summary>
    public string EvidenceId { get; set; } = string.Empty;
    /// <summary>Its state.</summary>
    public EvidenceState State { get; set; }
    /// <summary>How much the evidence score would rise if it were observed.</summary>
    public double ConfidenceGain { get; set; }
    /// <summary>What to do about it.</summary>
    public string Action { get; set; } = string.Empty;
}

/// <summary>An address behind the domain.</summary>
public sealed class ProfileAddress {
    /// <summary>Address.</summary>
    public string IpAddress { get; set; } = string.Empty;
    /// <summary>Where it was found: apex, MX or NS.</summary>
    public string SourceKind { get; set; } = string.Empty;
    /// <summary>Host name it was found through.</summary>
    public string SourceHost { get; set; } = string.Empty;
    /// <summary>Autonomous system number.</summary>
    public int? Asn { get; set; }
    /// <summary>Autonomous system or network name.</summary>
    public string AsName { get; set; } = string.Empty;
    /// <summary>Network in CIDR notation.</summary>
    public string Cidr { get; set; } = string.Empty;
    /// <summary>Country code.</summary>
    public string Country { get; set; } = string.Empty;
    /// <summary>Where the country came from.</summary>
    public IpCountrySource CountrySource { get; set; }
    /// <summary>Hosting or CDN provider.</summary>
    public string HostingProvider { get; set; } = string.Empty;
    /// <summary>Provider services and region.</summary>
    public string HostingService { get; set; } = string.Empty;
    /// <summary>Published range or network the provider was matched by.</summary>
    public string HostingMatchedBy { get; set; } = string.Empty;
    /// <summary>True for a CDN or edge proxy.</summary>
    public bool IsCdn { get; set; }
}

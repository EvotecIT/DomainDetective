using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DomainDetective;

/// <summary>
/// Preferred first escalation route for a typosquatting campaign.
/// </summary>
public enum TyposquattingInfrastructureCampaignEscalationRoute
{
    /// <summary>Provides typosquatting infrastructure campaign escalation bundle functionality.</summary>
    None,
    /// <summary>Provides typosquatting infrastructure campaign escalation bundle functionality.</summary>
    Abuse,
    /// <summary>Provides typosquatting infrastructure campaign escalation bundle functionality.</summary>
    Registrar,
    /// <summary>Provides typosquatting infrastructure campaign escalation bundle functionality.</summary>
    Hosting,
    /// <summary>Provides typosquatting infrastructure campaign escalation bundle functionality.</summary>
    Internal
}

/// <summary>
/// Reusable escalation bundle for campaign-based analyst handoff and takedown prep.
/// </summary>
public sealed class TyposquattingInfrastructureCampaignEscalationBundle
{
    /// <summary>Gets or sets the case id value.</summary>
    public string CaseId { get; init; } = string.Empty;
    /// <summary>Gets or sets the case fingerprint value.</summary>
    public string CaseFingerprint { get; init; } = string.Empty;
    /// <summary>Gets or sets the tracking summary value.</summary>
    public string TrackingSummary { get; init; } = string.Empty;
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; init; } = string.Empty;
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; init; } = string.Empty;
    /// <summary>Gets or sets the evidence summary value.</summary>
    public string EvidenceSummary { get; init; } = string.Empty;
    /// <summary>Gets or sets the draft body value.</summary>
    public string DraftBody { get; init; } = string.Empty;
    /// <summary>Gets or sets the draft preview value.</summary>
    public string DraftPreview { get; init; } = string.Empty;
    /// <summary>Gets or sets the primary route value.</summary>
    public TyposquattingInfrastructureCampaignEscalationRoute PrimaryRoute { get; init; }
    /// <summary>Gets or sets the primary contact value.</summary>
    public string PrimaryContact { get; init; } = string.Empty;
    /// <summary>Gets or sets the contacts value.</summary>
    public IReadOnlyList<string> Contacts { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the domains value.</summary>
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the evidence points value.</summary>
    public IReadOnlyList<string> EvidencePoints { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the action checklist value.</summary>
    public IReadOnlyList<string> ActionChecklist { get; init; } = Array.Empty<string>();
    /// <summary>Represents the ready to escalate value.</summary>
    public bool ReadyToEscalate => Contacts.Count > 0;
}

/// <summary>
/// Builds structured escalation bundles from shared typosquatting campaign metadata.
/// </summary>
public static class TyposquattingInfrastructureCampaignEscalationBuilder
{
    /// <summary>Executes the build operation.</summary>
    public static TyposquattingInfrastructureCampaignEscalationBundle Build(
        string label,
        IReadOnlyList<TyposquattingCandidate> members,
        TyposquattingInfrastructureCampaignSeverity severity,
        TyposquattingInfrastructureCampaignActionability actionability,
        IReadOnlyList<string> abuseContacts,
        IReadOnlyList<string> registrarContacts,
        IReadOnlyList<string> hostingProviders,
        string? primaryAbuseContact,
        string? primaryRegistrar,
        string? primaryHostingProvider,
        string? primaryCountry,
        IReadOnlyList<string> sharedSignals)
    {
        var topDomains = members
            .OrderByDescending(static candidate => candidate.RiskScore)
            .ThenBy(static candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .Select(static candidate => candidate.Domain)
            .ToArray();
        var contacts = abuseContacts
            .Concat(registrarContacts)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToArray();
        var likelyMaliciousCount = members.Count(static candidate => candidate.Disposition == TyposquattingDisposition.LikelyMalicious);
        var likelyImpersonationCount = members.Count(static candidate => candidate.Disposition == TyposquattingDisposition.LikelyImpersonation);
        var threatListedCount = members.Count(static candidate => candidate.Enrichment?.ThreatIntel?.Listings?.Any(listing => listing.IsListed) == true);
        var activeCount = members.Count(static candidate => candidate.Resolves);
        var reachableWebCount = members.Count(static candidate => candidate.Enrichment?.Http?.IsReachable == true);
        var contentLookalikes = members.Count(static candidate => candidate.ContentSimilarity?.LikelyImpersonating == true);
        var visualClones = members.Count(static candidate => candidate.VisualSimilarity?.LikelyClone == true);
        var mailAccepting = members.Count(static candidate => candidate.Enrichment?.SmtpRecipientAcceptance?.ServerResults?.Any(result => result.Value?.Accepted == true) == true);
        var evidencePoints = BuildEvidencePoints(
            members,
            likelyMaliciousCount,
            likelyImpersonationCount,
            threatListedCount,
            activeCount,
            reachableWebCount,
            contentLookalikes,
            visualClones,
            mailAccepting,
            primaryRegistrar,
            primaryHostingProvider,
            primaryCountry,
            sharedSignals);
        var primaryRoute = ResolvePrimaryRoute(primaryAbuseContact, primaryRegistrar, primaryHostingProvider);
        var primaryContact = ResolvePrimaryContact(primaryRoute, primaryAbuseContact, registrarContacts, primaryHostingProvider);
        var actionChecklist = BuildChecklist(primaryRoute, topDomains, contacts, evidencePoints);
        var caseFingerprint = BuildCaseFingerprint(primaryRoute, topDomains, contacts, evidencePoints, sharedSignals);
        var caseId = BuildCaseId(caseFingerprint);
        var subject = BuildSubject(label, severity, actionability, topDomains, primaryRoute, primaryContact);
        var summary = BuildSummary(label, members.Count, primaryRoute, primaryContact, topDomains, likelyMaliciousCount, likelyImpersonationCount);
        var draftBody = BuildDraftBody(
            label,
            severity,
            actionability,
            primaryRoute,
            primaryContact,
            topDomains,
            contacts,
            evidencePoints,
            actionChecklist);

        return new TyposquattingInfrastructureCampaignEscalationBundle
        {
            CaseId = caseId,
            CaseFingerprint = caseFingerprint,
            TrackingSummary = BuildTrackingSummary(caseId, primaryRoute, topDomains, primaryContact),
            Subject = subject,
            Summary = summary,
            EvidenceSummary = evidencePoints.Count > 0 ? string.Join("; ", evidencePoints.Take(4)) : "No escalation evidence package generated",
            DraftBody = draftBody,
            DraftPreview = BuildDraftPreview(draftBody),
            PrimaryRoute = primaryRoute,
            PrimaryContact = primaryContact,
            Contacts = contacts,
            Domains = topDomains,
            EvidencePoints = evidencePoints,
            ActionChecklist = actionChecklist
        };
    }

    private static IReadOnlyList<string> BuildEvidencePoints(
        IReadOnlyList<TyposquattingCandidate> members,
        int likelyMaliciousCount,
        int likelyImpersonationCount,
        int threatListedCount,
        int activeCount,
        int reachableWebCount,
        int contentLookalikes,
        int visualClones,
        int mailAccepting,
        string? primaryRegistrar,
        string? primaryHostingProvider,
        string? primaryCountry,
        IReadOnlyList<string> sharedSignals)
    {
        var evidence = new List<string>();
        if (likelyMaliciousCount > 0)
        {
            evidence.Add(likelyMaliciousCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains are classified as likely malicious");
        }

        if (likelyImpersonationCount > 0)
        {
            evidence.Add(likelyImpersonationCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains are classified as likely impersonation");
        }

        if (threatListedCount > 0)
        {
            evidence.Add(threatListedCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains are already threat listed");
        }

        if (mailAccepting > 0)
        {
            evidence.Add(mailAccepting.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains accept mail for the lookalike domain");
        }

        if (contentLookalikes > 0)
        {
            evidence.Add(contentLookalikes.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains show strong source-content similarity");
        }

        if (visualClones > 0)
        {
            evidence.Add(visualClones.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains show visual similarity to the source");
        }

        if (activeCount > 0)
        {
            evidence.Add(activeCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains resolve in DNS");
        }

        if (reachableWebCount > 0)
        {
            evidence.Add(reachableWebCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains are reachable over HTTP or HTTPS");
        }

        if (!string.IsNullOrWhiteSpace(primaryRegistrar))
        {
            evidence.Add("shared registrar: " + primaryRegistrar);
        }

        if (!string.IsNullOrWhiteSpace(primaryHostingProvider))
        {
            evidence.Add("shared hosting provider: " + primaryHostingProvider);
        }

        if (!string.IsNullOrWhiteSpace(primaryCountry))
        {
            evidence.Add("shared country signal: " + primaryCountry);
        }

        if (sharedSignals != null && sharedSignals.Count > 0)
        {
            evidence.Add("shared infrastructure: " + string.Join(", ", sharedSignals));
        }

        var strongestDomain = members
            .OrderByDescending(static candidate => candidate.RiskScore)
            .ThenBy(static candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (strongestDomain != null)
        {
            evidence.Add("top domain " + strongestDomain.Domain + " is scored " + strongestDomain.RiskLevel + " (" + strongestDomain.RiskScore.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")");
        }

        return evidence;
    }

    private static TyposquattingInfrastructureCampaignEscalationRoute ResolvePrimaryRoute(
        string? primaryAbuseContact,
        string? primaryRegistrar,
        string? primaryHostingProvider)
    {
        if (!string.IsNullOrWhiteSpace(primaryAbuseContact))
        {
            return TyposquattingInfrastructureCampaignEscalationRoute.Abuse;
        }

        if (!string.IsNullOrWhiteSpace(primaryRegistrar))
        {
            return TyposquattingInfrastructureCampaignEscalationRoute.Registrar;
        }

        if (!string.IsNullOrWhiteSpace(primaryHostingProvider))
        {
            return TyposquattingInfrastructureCampaignEscalationRoute.Hosting;
        }

        return TyposquattingInfrastructureCampaignEscalationRoute.Internal;
    }

    private static string ResolvePrimaryContact(
        TyposquattingInfrastructureCampaignEscalationRoute route,
        string? primaryAbuseContact,
        IReadOnlyList<string> registrarContacts,
        string? primaryHostingProvider)
    {
        return route switch
        {
            TyposquattingInfrastructureCampaignEscalationRoute.Abuse => primaryAbuseContact?.Trim() ?? string.Empty,
            TyposquattingInfrastructureCampaignEscalationRoute.Registrar => registrarContacts.FirstOrDefault() ?? string.Empty,
            TyposquattingInfrastructureCampaignEscalationRoute.Hosting => primaryHostingProvider?.Trim() ?? string.Empty,
            _ => string.Empty
        };
    }

    private static IReadOnlyList<string> BuildChecklist(
        TyposquattingInfrastructureCampaignEscalationRoute route,
        IReadOnlyList<string> topDomains,
        IReadOnlyList<string> contacts,
        IReadOnlyList<string> evidencePoints)
    {
        var checklist = new List<string>
        {
            "Confirm the top campaign domains: " + (topDomains.Count > 0 ? string.Join(", ", topDomains) : "none selected"),
            "Attach the strongest evidence: " + (evidencePoints.Count > 0 ? evidencePoints[0] : "risk summary only")
        };

        if (contacts.Count > 0)
        {
            checklist.Add("Prepare outreach targets: " + string.Join(", ", contacts.Take(3)));
        }

        checklist.Add(route switch
        {
            TyposquattingInfrastructureCampaignEscalationRoute.Abuse => "Send the first escalation through the abuse contact path",
            TyposquattingInfrastructureCampaignEscalationRoute.Registrar => "Send the first escalation through the registrar contact path",
            TyposquattingInfrastructureCampaignEscalationRoute.Hosting => "Prepare hosting-provider outreach and abuse references",
            _ => "Escalate internally and prepare an evidence bundle for manual takedown research"
        });

        return checklist;
    }

    private static string BuildSubject(
        string label,
        TyposquattingInfrastructureCampaignSeverity severity,
        TyposquattingInfrastructureCampaignActionability actionability,
        IReadOnlyList<string> topDomains,
        TyposquattingInfrastructureCampaignEscalationRoute route,
        string primaryContact)
    {
        var suffix = route switch
        {
            TyposquattingInfrastructureCampaignEscalationRoute.Abuse => string.IsNullOrWhiteSpace(primaryContact) ? "abuse escalation" : "abuse escalation via " + primaryContact,
            TyposquattingInfrastructureCampaignEscalationRoute.Registrar => string.IsNullOrWhiteSpace(primaryContact) ? "registrar escalation" : "registrar escalation via " + primaryContact,
            TyposquattingInfrastructureCampaignEscalationRoute.Hosting => string.IsNullOrWhiteSpace(primaryContact) ? "hosting escalation" : "hosting escalation via " + primaryContact,
            _ => "internal analyst escalation"
        };
        var domainLead = topDomains.Count > 0 ? topDomains[0] : label;
        return "[" + severity + "/" + actionability + "] Typosquatting campaign " + domainLead + " - " + suffix;
    }

    private static string BuildSummary(
        string label,
        int candidateCount,
        TyposquattingInfrastructureCampaignEscalationRoute route,
        string primaryContact,
        IReadOnlyList<string> topDomains,
        int likelyMaliciousCount,
        int likelyImpersonationCount)
    {
        var contactText = string.IsNullOrWhiteSpace(primaryContact)
            ? "no direct external contact identified"
            : primaryContact;
        var dispositionText = likelyMaliciousCount > 0
            ? likelyMaliciousCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " likely malicious"
            : likelyImpersonationCount > 0
                ? likelyImpersonationCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " likely impersonation"
                : "analyst review required";
        var domainsText = topDomains.Count > 0 ? string.Join(", ", topDomains) : label;
        return "Escalation bundle ready for " + candidateCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + " campaign domains via " + route.ToString() + " route using " + contactText
            + ". Top domains: " + domainsText + ". Current triage: " + dispositionText + ".";
    }

    private static string BuildCaseFingerprint(
        TyposquattingInfrastructureCampaignEscalationRoute route,
        IReadOnlyList<string> topDomains,
        IReadOnlyList<string> contacts,
        IReadOnlyList<string> evidencePoints,
        IReadOnlyList<string> sharedSignals)
    {
        var parts = new List<string>
        {
            route.ToString().ToLowerInvariant()
        };
        parts.AddRange(topDomains
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim().ToLowerInvariant())
            .OrderBy(static value => value, StringComparer.Ordinal));
        parts.AddRange(contacts
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim().ToLowerInvariant())
            .OrderBy(static value => value, StringComparer.Ordinal));
        parts.AddRange(sharedSignals
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim().ToLowerInvariant())
            .OrderBy(static value => value, StringComparer.Ordinal));
        parts.AddRange(evidencePoints
            .Take(4)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim().ToLowerInvariant()));

        var input = string.Join("|", parts);
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(bytes).Replace("-", string.Empty).Substring(0, 16);
    }

    private static string BuildCaseId(string caseFingerprint)
    {
        return "DD-TYPO-" + caseFingerprint;
    }

    private static string BuildTrackingSummary(
        string caseId,
        TyposquattingInfrastructureCampaignEscalationRoute route,
        IReadOnlyList<string> topDomains,
        string primaryContact)
    {
        var domainLead = topDomains.Count > 0 ? topDomains[0] : "no-domain";
        var contactText = string.IsNullOrWhiteSpace(primaryContact) ? "no direct contact" : primaryContact;
        return caseId + " tracks " + domainLead + " via " + route + " route using " + contactText + ".";
    }

    private static string BuildDraftBody(
        string label,
        TyposquattingInfrastructureCampaignSeverity severity,
        TyposquattingInfrastructureCampaignActionability actionability,
        TyposquattingInfrastructureCampaignEscalationRoute route,
        string primaryContact,
        IReadOnlyList<string> topDomains,
        IReadOnlyList<string> contacts,
        IReadOnlyList<string> evidencePoints,
        IReadOnlyList<string> actionChecklist)
    {
        var lines = new List<string>
        {
            "Hello,",
            string.Empty,
            BuildOpening(route, label, severity, actionability, primaryContact),
            string.Empty
        };

        if (topDomains.Count > 0)
        {
            lines.Add("Domains involved:");
            foreach (var domain in topDomains)
            {
                lines.Add("- " + domain);
            }
            lines.Add(string.Empty);
        }

        if (evidencePoints.Count > 0)
        {
            lines.Add("Supporting evidence:");
            foreach (var evidencePoint in evidencePoints.Take(6))
            {
                lines.Add("- " + evidencePoint);
            }
            lines.Add(string.Empty);
        }

        lines.Add("Requested action:");
        lines.Add("- Review the reported domains and associated infrastructure for abuse or policy violations.");
        lines.Add("- Investigate suspension, takedown, or other abuse-response steps where appropriate.");
        if (route == TyposquattingInfrastructureCampaignEscalationRoute.Internal)
        {
            lines.Add("- Route this bundle to the appropriate analyst or abuse-handling owner for manual escalation.");
        }
        lines.Add(string.Empty);

        if (contacts.Count > 0)
        {
            lines.Add("Known contacts or pivots:");
            foreach (var contact in contacts.Take(4))
            {
                lines.Add("- " + contact);
            }
            lines.Add(string.Empty);
        }

        if (actionChecklist.Count > 0)
        {
            lines.Add("Analyst checklist:");
            foreach (var checklistItem in actionChecklist.Take(4))
            {
                lines.Add("- " + checklistItem);
            }
            lines.Add(string.Empty);
        }

        lines.Add("Regards,");
        lines.Add("DomainDetective");
        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildOpening(
        TyposquattingInfrastructureCampaignEscalationRoute route,
        string label,
        TyposquattingInfrastructureCampaignSeverity severity,
        TyposquattingInfrastructureCampaignActionability actionability,
        string primaryContact)
    {
        var routeLabel = route switch
        {
            TyposquattingInfrastructureCampaignEscalationRoute.Abuse => "abuse",
            TyposquattingInfrastructureCampaignEscalationRoute.Registrar => "registrar",
            TyposquattingInfrastructureCampaignEscalationRoute.Hosting => "hosting",
            _ => "security"
        };
        var contactPart = string.IsNullOrWhiteSpace(primaryContact) ? string.Empty : " using contact " + primaryContact;
        return "We are reporting a suspected typosquatting campaign linked to " + label
            + ". This case is currently assessed as " + severity + " severity with " + actionability + " actionability"
            + " and is prepared for " + routeLabel + " escalation" + contactPart + ".";
    }

    private static string BuildDraftPreview(string draftBody)
    {
        if (string.IsNullOrWhiteSpace(draftBody))
        {
            return string.Empty;
        }

        var firstLine = draftBody
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Skip(1)
            .FirstOrDefault(static line => !string.IsNullOrWhiteSpace(line));
        if (string.IsNullOrWhiteSpace(firstLine))
        {
            return string.Empty;
        }

        return firstLine.Length <= 160 ? firstLine : firstLine.Substring(0, 157) + "...";
    }
}

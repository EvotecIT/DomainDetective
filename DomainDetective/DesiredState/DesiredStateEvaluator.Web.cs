using System;
using System.Linq;
using DomainDetective.Definitions;
using DomainDetective.Helpers;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static void EvaluateAutodiscover(string domain, AutodiscoverAnalysis autodiscover, DesiredStateAutodiscoverPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireSrvRecord == true && !autodiscover.SrvRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.AutodiscoverSrvMissingRecord,
                Message = "Desired state requires an Autodiscover SRV record (_autodiscover._tcp), but none was found."
            });
        }

        if (desired.RequireAutodiscoverCname == true && !autodiscover.AutodiscoverCnameExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.AutodiscoverCnameMissingRecord,
                Message = "Desired state requires an Autodiscover CNAME record (autodiscover.<domain>), but none was found."
            });
        }

        if (desired.RequireAutoconfigCname == true && !autodiscover.AutoconfigCnameExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.AutoconfigCnameMissingRecord,
                Message = "Desired state requires an Autoconfig CNAME record (autoconfig.<domain>), but none was found."
            });
        }

        if (autodiscover.SrvRecordExists && desired.AllowedSrvTargetSuffixes != null && desired.AllowedSrvTargetSuffixes.Length > 0) {
            var target = (autodiscover.SrvTarget ?? string.Empty).Trim().Trim('.');
            var allowed = desired.AllowedSrvTargetSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (allowed.Length > 0 && (target.Length == 0 || !allowed.Any(s => DomainHelper.IsDomainOrSubdomainOf(target, s)))) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.AutodiscoverSrvTargetNotAllowed,
                    Message = $"Desired state requires Autodiscover SRV target to end with [{string.Join(", ", allowed)}], but found '{target}'."
                });
            }
        }

        if (autodiscover.AutodiscoverCnameExists && desired.AllowedAutodiscoverCnameTargetSuffixes != null && desired.AllowedAutodiscoverCnameTargetSuffixes.Length > 0) {
            var target = (autodiscover.AutodiscoverTarget ?? string.Empty).Trim().Trim('.');
            var allowed = desired.AllowedAutodiscoverCnameTargetSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (allowed.Length > 0 && (target.Length == 0 || !allowed.Any(s => DomainHelper.IsDomainOrSubdomainOf(target, s)))) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.AutodiscoverCnameTargetNotAllowed,
                    Message = $"Desired state requires Autodiscover CNAME target to end with [{string.Join(", ", allowed)}], but found '{target}'."
                });
            }
        }

        if (autodiscover.AutoconfigCnameExists && desired.AllowedAutoconfigCnameTargetSuffixes != null && desired.AllowedAutoconfigCnameTargetSuffixes.Length > 0) {
            var target = (autodiscover.AutoconfigTarget ?? string.Empty).Trim().Trim('.');
            var allowed = desired.AllowedAutoconfigCnameTargetSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (allowed.Length > 0 && (target.Length == 0 || !allowed.Any(s => DomainHelper.IsDomainOrSubdomainOf(target, s)))) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.AutoconfigCnameTargetNotAllowed,
                    Message = $"Desired state requires Autoconfig CNAME target to end with [{string.Join(", ", allowed)}], but found '{target}'."
                });
            }
        }

        if (desired.RequireAnyValidEndpoint == true) {
            var anyValid = autodiscover.Endpoints != null && autodiscover.Endpoints.Any(e => e != null && (e.XmlValid || e.JsonValid));
            if (!anyValid) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.AutodiscoverNoValidEndpoint,
                    Message = "Desired state requires at least one valid Autodiscover endpoint (XML/JSON), but none were detected."
                });
            }
        }

        if (desired.AllowedValidEndpointHostSuffixes != null && desired.AllowedValidEndpointHostSuffixes.Length > 0) {
            var allowed = desired.AllowedValidEndpointHostSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (allowed.Length > 0 && autodiscover.Endpoints != null) {
                foreach (var e in autodiscover.Endpoints) {
                    if (e == null || (!e.XmlValid && !e.JsonValid)) continue;
                    var host = (e.FinalHost ?? TryGetHost(e.FinalUrl) ?? TryGetHost(e.Url) ?? string.Empty).Trim().Trim('.');
                    if (host.Length == 0) continue;
                    if (!allowed.Any(s => DomainHelper.IsDomainOrSubdomainOf(host, s))) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.AutodiscoverValidEndpointHostNotAllowed,
                            Message = $"Desired state requires valid Autodiscover endpoint hosts to end with [{string.Join(", ", allowed)}], but found '{host}'."
                        });
                    }
                }
            }
        }
    }

    private static void EvaluateSecurityTxt(string domain, SecurityTXTAnalysis securityTxt, DesiredStateSecurityTxtPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !securityTxt.RecordPresent) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SecurityTxtMissingRecord,
                Message = "Desired state requires a security.txt record, but none was found."
            });
            return;
        }

        if (!securityTxt.RecordPresent) {
            return;
        }

        if (desired.RequireValid == true && !securityTxt.RecordValid) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SecurityTxtInvalidRecord,
                Message = "Desired state requires a valid security.txt record, but it failed validation."
            });
        }

        if (desired.DisallowFallback == true && securityTxt.FallbackUsed) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SecurityTxtFallbackNotAllowed,
                Message = "Desired state disallows security.txt HTTP fallback, but fallback was used."
            });
        }

        if (desired.RequirePgpSigned == true && !securityTxt.PGPSigned) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SecurityTxtPgpSignedRequired,
                Message = "Desired state requires security.txt to be PGP signed, but it was not."
            });
        }

        if (desired.RequireContactEmail == true) {
            var count = securityTxt.ContactEmail?.Count ?? 0;
            if (count == 0) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SecurityTxtContactEmailMissing,
                    Message = "Desired state requires security.txt to include at least one Contact email address, but none were found."
                });
            }
        }

        if (desired.AllowedContactEmailDomainSuffixes != null && desired.AllowedContactEmailDomainSuffixes.Length > 0) {
            var allowed = desired.AllowedContactEmailDomainSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (allowed.Length > 0 && securityTxt.ContactEmail != null) {
                foreach (var email in securityTxt.ContactEmail) {
                    if (string.IsNullOrWhiteSpace(email)) continue;
                    var at = email.IndexOf('@');
                    if (at < 0 || at >= email.Length - 1) continue;
                    var emailDomain = email.Substring(at + 1).Trim().Trim('.');
                    if (emailDomain.Length == 0) continue;
                    if (!allowed.Any(s => DomainHelper.IsDomainOrSubdomainOf(emailDomain, s))) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.SecurityTxtContactEmailDomainNotAllowed,
                            Message = $"Desired state requires security.txt Contact email domains to end with [{string.Join(", ", allowed)}], but found '{emailDomain}'."
                        });
                    }
                }
            }
        }
    }

    private static void EvaluateRobots(string domain, RobotsTxtAnalysis robots, DesiredStateRobotsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !robots.RecordPresent) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.RobotsMissingRecord,
                Message = "Desired state requires robots.txt to be present, but none was found."
            });
            return;
        }

        if (!robots.RecordPresent) {
            return;
        }

        if (desired.DisallowFallback == true && robots.FallbackUsed) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.RobotsFallbackNotAllowed,
                Message = "Desired state disallows robots.txt HTTP fallback, but fallback was used."
            });
        }

        if (desired.RequireAiBotRules == true && !robots.HasAiBotRules) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.RobotsAiBotRulesRequired,
                Message = "Desired state requires robots.txt AI bot directives, but none were found."
            });
        }

        if (desired.RequireSitemap == true) {
            var sitemapCount = robots.Robots?.Sitemaps?.Count ?? 0;
            if (sitemapCount == 0) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.RobotsSitemapRequired,
                    Message = "Desired state requires robots.txt to declare at least one sitemap, but none were found."
                });
            }
        }
    }

    private static void EvaluateAgentReadiness(string domain, AgentReadinessAnalysis agentReadiness, DesiredStateAgentReadinessPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (agentReadiness == null ||
            (agentReadiness.Checks.Count == 0 && agentReadiness.MainPageStatusCode == null && string.IsNullOrWhiteSpace(agentReadiness.Subject))) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessNoResults,
                "Desired state requires agent readiness results, but the AGENTREADINESS check has not produced results.");
            return;
        }

        if (desired.MinimumScore.HasValue && agentReadiness.Score < desired.MinimumScore.Value) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessScoreTooLow,
                $"Desired state requires agent readiness score >= {desired.MinimumScore.Value}, but found {agentReadiness.Score:0.##}.");
        }

        if (desired.RequireRobotsTxt == true && !agentReadiness.RobotsPresent) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessRobotsMissing,
                "Desired state requires robots.txt discovery for agent readiness, but none was found.");
        }

        if (desired.RequireSitemap == true && (agentReadiness.Robots?.Sitemaps?.Count ?? 0) == 0) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessSitemapMissing,
                "Desired state requires robots.txt to declare at least one sitemap for agent discovery, but none was found.");
        }

        if (desired.RequireLinkHeaders == true && agentReadiness.LinkRelations.Count == 0) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessLinkHeadersMissing,
                "Desired state requires agent-facing RFC 8288 Link headers, but none were found.");
        }

        if (desired.RequireLlmsTxt == true && !AgentEndpointPresent(agentReadiness, "llms.txt")) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessLlmsTxtMissing,
                "Desired state requires llms.txt, but no usable llms.txt endpoint was found.");
        }

        if (desired.RequireMarkdown == true &&
            !agentReadiness.Markdown.DirectMarkdown &&
            string.IsNullOrWhiteSpace(agentReadiness.Markdown.AlternateMarkdownUrl)) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessMarkdownMissing,
                "Desired state requires direct markdown negotiation or a markdown alternate, but neither was found.");
        }

        if (desired.RequireContentSignals == true && agentReadiness.ContentSignals.Count == 0) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessContentSignalsMissing,
                "Desired state requires Content-Signal policy, but none was found.");
        }

        if (desired.RequireAiBotRules == true && !AgentReadinessCheckPassed(agentReadiness, "ai-bot-policy")) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessAiBotRulesMissing,
                "Desired state requires AI bot directives in robots.txt, but none were found.");
        }

        if (desired.RequireApiCatalog == true && !AgentEndpointUsable(agentReadiness, "api-catalog")) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessApiCatalogMissing,
                "Desired state requires RFC 9727 API Catalog discovery, but no usable endpoint was found.");
        }

        if (desired.RequireAgentSkills == true && !AgentEndpointUsable(agentReadiness, "agent-skills")) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessAgentSkillsMissing,
                "Desired state requires Agent Skills discovery, but no usable endpoint was found.");
        }

        if (desired.RequireAgentsJson == true && !AgentEndpointUsable(agentReadiness, "agents-json")) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessAgentsJsonMissing,
                "Desired state requires agents.json discovery, but no usable endpoint was found.");
        }

        if (desired.RequireOpenApi == true && !AgentEndpointUsable(agentReadiness, "openapi")) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessOpenApiMissing,
                "Desired state requires OpenAPI discovery, but no usable endpoint was found.");
        }

        if (desired.RequireHttps == true && !agentReadiness.HttpsUsed) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessHttpsRequired,
                "Desired state requires HTTPS for agent readiness probing, but HTTP fallback was used.");
        }

        if (desired.MinTrustHeaders.HasValue && agentReadiness.TrustHeaderCount < desired.MinTrustHeaders.Value) {
            AddAgentReadinessDrift(
                sink,
                domain,
                DesiredStateCodes.AgentReadinessTrustHeadersTooFew,
                $"Desired state requires at least {desired.MinTrustHeaders.Value} trust headers, but found {agentReadiness.TrustHeaderCount}.");
        }
    }

    private static void AddAgentReadinessDrift(DesiredStateAnalysis sink, string domain, string code, string message) {
        sink.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "DesiredState",
            Target = domain,
            Code = code,
            Message = message
        });
    }

    private static bool AgentReadinessCheckPassed(AgentReadinessAnalysis analysis, string id) {
        return analysis.Checks.Any(check =>
            check.Id.Equals(id, StringComparison.OrdinalIgnoreCase) &&
            check.Status == AgentReadinessCheckStatus.Pass);
    }

    private static bool AgentEndpointPresent(AgentReadinessAnalysis analysis, string kind) {
        return analysis.EndpointProbes.Any(probe =>
            probe.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase) &&
            probe.Present);
    }

    private static bool AgentEndpointUsable(AgentReadinessAnalysis analysis, string kind) {
        return analysis.EndpointProbes.Any(probe =>
            probe.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase) &&
            probe.Present &&
            (!AgentEndpointRequiresShapeValidation(kind) || probe.ShapeValid));
    }

    private static bool AgentEndpointRequiresShapeValidation(string kind) {
        return kind.Equals("api-catalog", StringComparison.OrdinalIgnoreCase) ||
               kind.Equals("agent-skills", StringComparison.OrdinalIgnoreCase) ||
               kind.Equals("agents-json", StringComparison.OrdinalIgnoreCase) ||
               kind.Equals("openapi", StringComparison.OrdinalIgnoreCase);
    }
}

using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestTyposquattingAnalysis {
        [Fact]
        public async Task DetectsActiveVariant() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                    }
                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Contains("examp1e.com", analysis.Variants);
            Assert.Contains("examp1e.com", analysis.ActiveDomains);
            Assert.Contains(analysis.Candidates, candidate => candidate.Domain == "examp1e.com" && candidate.Resolves);
        }

        [Fact]
        public async Task HealthCheckRunsTyposquatting() {
            var hc = new DomainHealthCheck();
            hc.TyposquattingEnableContentSimilarity = false;
            hc.TyposquattingAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>());
            await hc.VerifyTyposquatting("example.com");
            Assert.NotEmpty(hc.TyposquattingAnalysis.Variants);
        }

        [Fact]
        public async Task UsesPublicSuffixForMultiLabelTld() {
            var hc = new DomainHealthCheck();
            hc.TyposquattingAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>());

            await hc.TyposquattingAnalysis.Analyze("foo.example.co.uk", new InternalLogger());

            Assert.Contains("foo.examp1e.co.uk", hc.TyposquattingAnalysis.Variants);
        }

        [Fact]
        public async Task LevenshteinThresholdLimitsVariants() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                LevenshteinThreshold = 0
            };

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Empty(analysis.Variants);
        }

        [Fact]
        public async Task DetectsHomoglyphCharacters() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                DetectHomoglyphs = true
            };

            await analysis.Analyze("ex\u0430mple.com", new InternalLogger());

            Assert.True(analysis.ContainsHomoglyphs);
        }

        [Fact]
        public async Task DetectsBrandImpersonation() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "paypal-example.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.2.3.4" } });
                    }
                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.BrandKeywords.Add("paypal");

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Contains("paypal-example.com", analysis.Variants);
            Assert.Contains("paypal-example.com", analysis.ActiveDomains);
        }

        [Fact]
        public async Task GeneratesTranspositionAndHyphenationCandidates() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                LevenshteinThreshold = 2,
                QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>())
            };

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Contains(analysis.Candidates, candidate => candidate.Kind == TyposquattingVariantKind.Transposition);
            Assert.Contains(analysis.Candidates, candidate => candidate.Kind == TyposquattingVariantKind.Hyphenation);
        }

        [Fact]
        public async Task GeneratesDictionaryAndTldSwapCandidates() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>())
            };
            analysis.DictionaryWords.Add("secure");
            analysis.AlternativeTlds.Add("net");

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Contains(analysis.Candidates, candidate => candidate.Domain == "secure-example.com" && candidate.Kind == TyposquattingVariantKind.Dictionary);
            Assert.Contains(analysis.Candidates, candidate => candidate.Domain == "example.net" && candidate.Kind == TyposquattingVariantKind.TldSwap);
        }

        [Fact]
        public async Task RecordsRegisteredCandidatesFromMxAndNsFootprint() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.MX) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "10 mail.examp1e.com", Type = DnsRecordType.MX } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.examp1e.com", Type = DnsRecordType.NS } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.True(candidate.AppearsRegistered);
            Assert.False(candidate.Resolves);
            Assert.Contains("examp1e.com", analysis.RegisteredDomains);
            Assert.DoesNotContain("examp1e.com", analysis.ActiveDomains);
        }

        [Fact]
        public async Task EnrichesCandidatesUsingReusableAnalysisPipeline() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeWhois = true;
            analysis.EnrichmentOptions.IncludeHttp = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = true;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Contoso Registrar"
            });
            analysis.EnrichmentOptions.ThreatIntelOverride = (domain, _) => {
                var threat = new ThreatIntelAnalysis {
                    Subject = domain
                };
                threat.Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.UrlHaus, IsListed = true });
                return Task.FromResult<ThreatIntelAnalysis?>(threat);
            };

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(candidate.Enrichment);
            Assert.Equal("Contoso Registrar", candidate.Enrichment!.Whois!.Registrar);
            Assert.Contains(candidate.Enrichment.ThreatIntel!.Listings, listing => listing.Source == ThreatIntelSource.UrlHaus && listing.IsListed);

            var view = DomainDetective.Views.Converters.Convert(analysis);
            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.Equal("Contoso Registrar", viewCandidate.Registrar);
            Assert.True(viewCandidate.ThreatListed);
            Assert.Equal(1, view.EnrichedCandidateCount);
        }

        [Fact]
        public void ScoresActiveThreatListedCandidateHigherThanPassiveVariant() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            var passive = new TyposquattingCandidate {
                Domain = "examp1e.net",
                Kind = TyposquattingVariantKind.TldSwap,
                EditDistance = 1,
                NsRecords = new[] { "ns1.examp1e.net" }
            };
            var activeThreat = new TyposquattingCandidate {
                Domain = "examp1e.com",
                Kind = TyposquattingVariantKind.Homoglyph,
                EditDistance = 1,
                ARecords = new[] { "1.2.3.4" },
                Enrichment = new TyposquattingCandidateEnrichment {
                    Domain = "examp1e.com",
                    Http = new HttpAnalysis(),
                    ThreatIntel = new ThreatIntelAnalysis()
                }
            };
            activeThreat.Enrichment.Http.Subject = "https://examp1e.com";
            SetAutoProperty(activeThreat.Enrichment.Http, "IsReachable", true);
            SetAutoProperty(activeThreat.Enrichment.Http, "StatusCode", 200);
            activeThreat.Enrichment.ThreatIntel.Subject = "examp1e.com";
            activeThreat.Enrichment.ThreatIntel.Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.UrlHaus, IsListed = true });
            SetAutoProperty(activeThreat.Enrichment.ThreatIntel, "Severity", "High");

            TyposquattingCandidateScorer.ScoreCandidates(new[] { passive, activeThreat });

            Assert.True(activeThreat.RiskScore > passive.RiskScore);
            Assert.Equal(TyposquattingRiskLevel.Critical, activeThreat.RiskLevel);
            Assert.Contains(activeThreat.RiskReasons, reason => reason.Contains("threat", System.StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task OwnershipOverlapMarksCandidateAsLikelyOwnedAndLowersRisk() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static IpEnrichmentAnalysis BuildIpEnrichmentWithAsn(int asn) {
                var analysis = new IpEnrichmentAnalysis();
                IReadOnlyDictionary<int, int> asnCounts = new Dictionary<int, int> {
                    [asn] = 1
                };
                IReadOnlyList<IpEnrichmentRow> rows = new[]
                {
                    new IpEnrichmentRow
                    {
                        IpAddress = asn == 64500 ? "1.1.1.1" : "9.9.9.9",
                        Asn = asn,
                        AsName = asn == 64500 ? "Contoso Networks" : "Evil Hosting",
                        Country = asn == 64500 ? "US" : "NL",
                        Region = asn == 64500 ? "Virginia" : "Amsterdam"
                    }
                };
                SetAutoProperty(analysis, "UniqueIpCount", 1);
                SetAutoProperty(analysis, "AsnCounts", asnCounts);
                SetAutoProperty(analysis, "Rows", rows);
                return analysis;
            }

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "example.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
                    }

                    if (name == "example.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeWhois = true;
            analysis.EnrichmentOptions.IncludeIpEnrichment = true;
            analysis.EnrichmentOptions.IncludeHttp = false;
            analysis.EnrichmentOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Contoso Registrar"
            });
            analysis.EnrichmentOptions.IpEnrichmentOverride = (_, _) => Task.FromResult<IpEnrichmentAnalysis?>(BuildIpEnrichmentWithAsn(64500));

            analysis.OwnershipProfileOptions.Enabled = true;
            analysis.OwnershipProfileOptions.IncludeWhois = true;
            analysis.OwnershipProfileOptions.IncludeIpEnrichment = true;
            analysis.OwnershipProfileOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Contoso Registrar"
            });
            analysis.OwnershipProfileOptions.IpEnrichmentOverride = (_, _) => Task.FromResult<IpEnrichmentAnalysis?>(BuildIpEnrichmentWithAsn(64500));

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.NotNull(analysis.SourceOwnershipProfile);
            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(candidate.Ownership);
            Assert.True(candidate.Ownership!.LikelyOwned);
            Assert.True(candidate.Ownership.ConfidenceScore >= 45);

            var unownedReference = new TyposquattingCandidate {
                Domain = candidate.Domain,
                Kind = candidate.Kind,
                EditDistance = candidate.EditDistance,
                ARecords = candidate.ARecords,
                AaaaRecords = candidate.AaaaRecords,
                NsRecords = candidate.NsRecords,
                MxRecords = candidate.MxRecords,
                Enrichment = candidate.Enrichment
            };
            TyposquattingCandidateScorer.ScoreCandidate(unownedReference);

            Assert.True(candidate.RiskScore < unownedReference.RiskScore);
            Assert.Contains(candidate.RiskReasons, reason => reason.Contains("ownership", System.StringComparison.OrdinalIgnoreCase));

            var view = DomainDetective.Views.Converters.Convert(analysis);
            Assert.True(view.OwnershipProfileBuilt);
            Assert.Equal(1, view.LikelyOwnedCount);

            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.True(viewCandidate.LikelyOwned);
            Assert.Contains("shares", viewCandidate.OwnershipSummary, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task DistinctInfrastructureMarksCandidateAsLikelyExternalAndRaisesRisk() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static IpEnrichmentAnalysis BuildIpEnrichmentWithAsn(int asn) {
                var analysis = new IpEnrichmentAnalysis();
                IReadOnlyDictionary<int, int> asnCounts = new Dictionary<int, int> {
                    [asn] = 1
                };
                IReadOnlyList<IpEnrichmentRow> rows = new[]
                {
                    new IpEnrichmentRow
                    {
                        IpAddress = asn == 64500 ? "1.1.1.1" : "9.9.9.9",
                        Asn = asn,
                        AsName = asn == 64500 ? "Contoso Networks" : "Evil Hosting",
                        Country = asn == 64500 ? "US" : "NL",
                        Region = asn == 64500 ? "Virginia" : "Amsterdam"
                    }
                };
                SetAutoProperty(analysis, "UniqueIpCount", 1);
                SetAutoProperty(analysis, "AsnCounts", asnCounts);
                SetAutoProperty(analysis, "Rows", rows);
                return analysis;
            }

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "example.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
                    }

                    if (name == "example.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.typo-host.net", Type = DnsRecordType.NS } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeWhois = true;
            analysis.EnrichmentOptions.IncludeIpEnrichment = true;
            analysis.EnrichmentOptions.IncludeHttp = false;
            analysis.EnrichmentOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Evil Registrar"
            });
            analysis.EnrichmentOptions.IpEnrichmentOverride = (_, _) => Task.FromResult<IpEnrichmentAnalysis?>(BuildIpEnrichmentWithAsn(64599));

            analysis.OwnershipProfileOptions.Enabled = true;
            analysis.OwnershipProfileOptions.IncludeWhois = true;
            analysis.OwnershipProfileOptions.IncludeIpEnrichment = true;
            analysis.OwnershipProfileOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Contoso Registrar"
            });
            analysis.OwnershipProfileOptions.IpEnrichmentOverride = (_, _) => Task.FromResult<IpEnrichmentAnalysis?>(BuildIpEnrichmentWithAsn(64500));

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(candidate.Ownership);
            Assert.False(candidate.Ownership!.LikelyOwned);
            Assert.True(candidate.Ownership.LikelyExternal);
            Assert.True(candidate.Ownership.ExternalConfidenceScore >= 35);

            var referenceCandidate = new TyposquattingCandidate {
                Domain = candidate.Domain,
                Kind = candidate.Kind,
                EditDistance = candidate.EditDistance,
                ARecords = candidate.ARecords,
                AaaaRecords = candidate.AaaaRecords,
                NsRecords = candidate.NsRecords,
                MxRecords = candidate.MxRecords,
                Enrichment = candidate.Enrichment
            };
            TyposquattingCandidateScorer.ScoreCandidate(referenceCandidate);

            Assert.True(candidate.RiskScore > referenceCandidate.RiskScore);
            Assert.Contains(candidate.RiskReasons, reason => reason.Contains("distinct", System.StringComparison.OrdinalIgnoreCase));

            var view = DomainDetective.Views.Converters.Convert(analysis);
            Assert.Equal(1, view.LikelyExternalCount);

            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.True(viewCandidate.LikelyExternal);
            Assert.Contains("different", viewCandidate.ExternalSummary, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task MatchingSourceContentMarksCandidateAsLikelyImpersonatingAndRaisesRisk() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static HttpAnalysis BuildHttp(string url, string bodySha256, int bodyLength, string body, params string[] visitedUrls) {
                var analysis = new HttpAnalysis {
                    Subject = url
                };
                SetAutoProperty(analysis, "IsReachable", true);
                SetAutoProperty(analysis, "StatusCode", 200);
                SetAutoProperty(analysis, "BodySha256", bodySha256);
                SetAutoProperty(analysis, "BodyLength", bodyLength);
                SetAutoProperty(analysis, "Body", body);
                foreach (var visitedUrl in visitedUrls) {
                    analysis.VisitedUrls.Add(visitedUrl);
                }
                return analysis;
            }

            var sourceBody = "<html><head><title>Example Portal</title></head><body>hello</body></html>";
            var candidateBody = "<html><head><title>Example Portal</title></head><body>hello</body></html>";
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeHttp = true;
            analysis.EnrichmentOptions.IncludeWhois = false;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.HttpOverride = (domain, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                "https://" + domain,
                "abc123",
                sourceBody.Length,
                candidateBody,
                "https://www.example.com/login"));

            analysis.ContentSimilarityOptions.Enabled = true;
            analysis.ContentSimilarityOptions.HttpOverride = (url, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                url,
                "abc123",
                sourceBody.Length,
                sourceBody,
                "https://www.example.com/login"));

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.NotNull(analysis.SourceContentProfile);
            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(candidate.ContentSimilarity);
            Assert.True(candidate.ContentSimilarity!.LikelyImpersonating);
            Assert.True(candidate.ContentSimilarity.Score >= 35);
            Assert.Contains(candidate.ContentSimilarity.Signals, signal => signal.Contains("body hash", System.StringComparison.OrdinalIgnoreCase));

            var referenceCandidate = new TyposquattingCandidate {
                Domain = candidate.Domain,
                Kind = candidate.Kind,
                EditDistance = candidate.EditDistance,
                ARecords = candidate.ARecords,
                AaaaRecords = candidate.AaaaRecords,
                NsRecords = candidate.NsRecords,
                MxRecords = candidate.MxRecords,
                Enrichment = candidate.Enrichment
            };
            TyposquattingCandidateScorer.ScoreCandidate(referenceCandidate);

            Assert.True(candidate.RiskScore > referenceCandidate.RiskScore);

            var view = DomainDetective.Views.Converters.Convert(analysis);
            Assert.True(view.ContentProfileBuilt);
            Assert.Equal(1, view.LikelyImpersonatingCount);

            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.True(viewCandidate.LikelyImpersonating);
            Assert.True(viewCandidate.ContentSimilarityScore >= 35);
            Assert.Contains("body hash", viewCandidate.ContentSimilaritySummary, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task NearCloneContentUsesFuzzyFingerprintWhenExactBodyHashDiffers() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static HttpAnalysis BuildHttp(string url, string bodySha256, string body) {
                var analysis = new HttpAnalysis {
                    Subject = url
                };
                SetAutoProperty(analysis, "IsReachable", true);
                SetAutoProperty(analysis, "StatusCode", 200);
                SetAutoProperty(analysis, "BodySha256", bodySha256);
                SetAutoProperty(analysis, "BodyLength", body.Length);
                SetAutoProperty(analysis, "Body", body);
                analysis.VisitedUrls.Add(url);
                return analysis;
            }

            const string sourceBody = "<html><head><title>Example Portal</title></head><body><h1>Welcome to Example</h1><p>Use your corporate account to sign in to the secure example portal and review invoices payroll approvals and profile tasks.</p><p>Multi factor verification keeps your example workspace protected.</p></body></html>";
            const string candidateBody = "<html><head><title>Example Workspace</title></head><body><h1>Welcome to Example Workspace</h1><p>Use your company account to sign in to the secure example portal and review invoices payroll approvals plus profile tasks.</p><p>Multi factor verification keeps your workspace protected and connected.</p></body></html>";

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeHttp = true;
            analysis.EnrichmentOptions.IncludeWhois = false;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.HttpOverride = (domain, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                "https://" + domain,
                "candidate-body",
                candidateBody));

            analysis.ContentSimilarityOptions.Enabled = true;
            analysis.ContentSimilarityOptions.StrongFuzzyBodyFingerprintThreshold = 76;
            analysis.ContentSimilarityOptions.ModerateFuzzyBodyFingerprintThreshold = 64;
            analysis.ContentSimilarityOptions.HttpOverride = (url, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                url,
                "source-body",
                sourceBody));

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(candidate.ContentSimilarity);
            Assert.True(candidate.ContentSimilarity!.Score >= 18);
            Assert.DoesNotContain(candidate.ContentSimilarity.Signals, signal => signal.Contains("body hash", System.StringComparison.OrdinalIgnoreCase));
            Assert.Contains(candidate.ContentSimilarity.Signals, signal => signal.Contains("fuzzy page-text fingerprint", System.StringComparison.OrdinalIgnoreCase));
            Assert.True(candidate.ContentSimilarity.FuzzyFingerprintSimilarity >= 64);

            var referenceCandidate = new TyposquattingCandidate {
                Domain = candidate.Domain,
                Kind = candidate.Kind,
                EditDistance = candidate.EditDistance,
                ARecords = candidate.ARecords,
                AaaaRecords = candidate.AaaaRecords,
                NsRecords = candidate.NsRecords,
                MxRecords = candidate.MxRecords,
                Enrichment = candidate.Enrichment
            };
            TyposquattingCandidateScorer.ScoreCandidate(referenceCandidate);

            Assert.True(candidate.RiskScore > referenceCandidate.RiskScore);

            var view = DomainDetective.Views.Converters.Convert(analysis);
            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.True(viewCandidate.ContentFingerprintSimilarity >= 64);
            Assert.Contains("fuzzy page-text fingerprint", viewCandidate.ContentSimilaritySummary, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task MatchingVisualFingerprintMarksCandidateAsLikelyCloneAndRaisesRisk() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeHttp = true;
            analysis.EnrichmentOptions.IncludeWhois = false;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.HttpOverride = (domain, _) => Task.FromResult<HttpAnalysis?>(new HttpAnalysis {
                Subject = "https://" + domain
            });

            analysis.VisualSimilarityOptions.Enabled = true;
            analysis.VisualSimilarityOptions.CaptureOverride = (url, _) => Task.FromResult<TyposquattingVisualArtifact?>(new TyposquattingVisualArtifact {
                FingerprintHex = url.Contains("examp1e", System.StringComparison.OrdinalIgnoreCase)
                    ? "0f0f0f0f0f0f0f0f"
                    : "0f0f0f0f0f0f0f0f"
            });

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.NotNull(analysis.SourceVisualProfile);
            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(candidate.VisualSimilarity);
            Assert.True(candidate.VisualSimilarity!.LikelyClone);
            Assert.True(candidate.VisualSimilarity.Score >= 80);
            Assert.Contains("closely matches", candidate.VisualSimilarity.Summary, System.StringComparison.OrdinalIgnoreCase);

            var referenceCandidate = new TyposquattingCandidate {
                Domain = candidate.Domain,
                Kind = candidate.Kind,
                EditDistance = candidate.EditDistance,
                ARecords = candidate.ARecords,
                AaaaRecords = candidate.AaaaRecords,
                NsRecords = candidate.NsRecords,
                MxRecords = candidate.MxRecords,
                Enrichment = candidate.Enrichment
            };
            TyposquattingCandidateScorer.ScoreCandidate(referenceCandidate);

            Assert.True(candidate.RiskScore > referenceCandidate.RiskScore);
            Assert.Contains(candidate.RiskReasons, reason => reason.Contains("visual appearance", System.StringComparison.OrdinalIgnoreCase));

            var view = DomainDetective.Views.Converters.Convert(analysis);
            Assert.True(view.VisualProfileBuilt);
            Assert.Equal(1, view.LikelyVisualCloneCount);

            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.True(viewCandidate.LikelyVisualClone);
            Assert.True(viewCandidate.VisualSimilarityScore >= 80);
        }

        [Fact]
        public async Task StaticVisualAssetCaptureParsesIconsAndReusesCandidateHttp() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static HttpAnalysis BuildHttp(string url, string body, params string[] visitedUrls) {
                var analysis = new HttpAnalysis {
                    Subject = url
                };
                SetAutoProperty(analysis, "IsReachable", true);
                SetAutoProperty(analysis, "StatusCode", 200);
                SetAutoProperty(analysis, "Body", body);
                SetAutoProperty(analysis, "BodyLength", body.Length);
                foreach (var visitedUrl in visitedUrls) {
                    analysis.VisitedUrls.Add(visitedUrl);
                }
                return analysis;
            }

            var sourcePageCalls = 0;
            var requestedAssets = new List<string>();
            const string sharedFingerprint = "0f0f0f0f0f0f0f0f";
            const string sourceBody = "<html><head><link rel=\"icon\" href=\"/favicon.png\"></head><body>source</body></html>";
            const string candidateBody = "<html><head><link rel=\"icon\" href=\"/favicon.png\"></head><body>clone</body></html>";

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeHttp = true;
            analysis.EnrichmentOptions.IncludeWhois = false;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.HttpOverride = (domain, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                "https://" + domain,
                candidateBody,
                "https://" + domain + "/login"));

            analysis.VisualSimilarityOptions.Enabled = true;
            analysis.VisualSimilarityOptions.MaxAssetsPerPage = 1;
            analysis.VisualSimilarityOptions.PageHttpOverride = (url, _) => {
                sourcePageCalls++;
                return Task.FromResult<HttpAnalysis?>(BuildHttp(
                    url,
                    sourceBody,
                    "https://example.com/login"));
            };
            analysis.VisualSimilarityOptions.AssetDownloadOverride = (assetUrl, _) => {
                requestedAssets.Add(assetUrl);
                return Task.FromResult<TyposquattingVisualArtifact?>(new TyposquattingVisualArtifact {
                    FingerprintHex = sharedFingerprint
                });
            };

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(analysis.SourceVisualProfile);
            Assert.NotNull(candidate.VisualSimilarity);
            Assert.True(candidate.VisualSimilarity!.LikelyClone);
            Assert.Equal(1, sourcePageCalls);
            Assert.Equal(2, requestedAssets.Count);
            Assert.Contains("https://example.com/favicon.png", requestedAssets);
            Assert.Contains("https://examp1e.com/favicon.png", requestedAssets);
        }

        [Fact]
        public async Task VisualSimilarityChoosesBestMatchAcrossMultipleAssets() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static HttpAnalysis BuildHttp(string url, string body, params string[] visitedUrls) {
                var analysis = new HttpAnalysis {
                    Subject = url
                };
                SetAutoProperty(analysis, "IsReachable", true);
                SetAutoProperty(analysis, "StatusCode", 200);
                SetAutoProperty(analysis, "Body", body);
                SetAutoProperty(analysis, "BodyLength", body.Length);
                foreach (var visitedUrl in visitedUrls) {
                    analysis.VisitedUrls.Add(visitedUrl);
                }
                return analysis;
            }

            const string sourceBody = "<html><head><link rel=\"icon\" href=\"/favicon.png\"><meta property=\"og:image\" content=\"/social.png\"></head><body>source</body></html>";
            const string candidateBody = "<html><head><link rel=\"icon\" href=\"/favicon.png\"><meta property=\"og:image\" content=\"/social.png\"></head><body>clone</body></html>";

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeHttp = true;
            analysis.EnrichmentOptions.IncludeWhois = false;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.HttpOverride = (domain, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                "https://" + domain,
                candidateBody,
                "https://" + domain + "/login"));

            analysis.VisualSimilarityOptions.Enabled = true;
            analysis.VisualSimilarityOptions.MaxAssetsPerPage = 2;
            analysis.VisualSimilarityOptions.PageHttpOverride = (url, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                url,
                sourceBody,
                "https://example.com/login"));
            analysis.VisualSimilarityOptions.AssetDownloadOverride = (assetUrl, _) => {
                var fingerprint = assetUrl switch {
                    "https://example.com/favicon.png" => "1111111111111111",
                    "https://example.com/social.png" => "aaaaaaaaaaaaaaaa",
                    "https://examp1e.com/favicon.png" => "2222222222222222",
                    "https://examp1e.com/social.png" => "aaaaaaaaaaaaaaaa",
                    _ => "ffffffffffffffff"
                };

                return Task.FromResult<TyposquattingVisualArtifact?>(new TyposquattingVisualArtifact {
                    FingerprintHex = fingerprint
                });
            };

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.NotNull(candidate.VisualSimilarity);
            Assert.True(candidate.VisualSimilarity!.LikelyClone);
            Assert.Equal(TyposquattingVisualArtifactKind.OpenGraphImage, candidate.VisualSimilarity.MatchedArtifactKind);
            Assert.Contains("og:image", candidate.VisualSimilarity.Summary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains(candidate.RiskReasons, reason => reason.Contains("social preview", System.StringComparison.OrdinalIgnoreCase));

            var view = DomainDetective.Views.Converters.Convert(analysis);
            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.Equal(nameof(TyposquattingVisualArtifactKind.OpenGraphImage), viewCandidate.VisualMatchKind);
            Assert.Equal("https://example.com/social.png", viewCandidate.VisualMatchedSourceUrl);
            Assert.Equal("https://examp1e.com/social.png", viewCandidate.VisualCandidateArtifactUrl);
        }

        [Fact]
        public void SocialVisualCloneScoresHigherThanFaviconClone() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            var faviconCandidate = new TyposquattingCandidate {
                Domain = "examp1e-favicon.com",
                Kind = TyposquattingVariantKind.Homoglyph,
                EditDistance = 1
            };
            SetAutoProperty(faviconCandidate, "ARecords", (System.Collections.Generic.IReadOnlyList<string>)new[] { "1.1.1.1" });
            SetAutoProperty(faviconCandidate, "VisualSimilarity", new TyposquattingVisualSimilarityMatch {
                Score = 100,
                HammingDistance = 0,
                LikelyClone = true,
                MatchedArtifactKind = TyposquattingVisualArtifactKind.Favicon,
                Summary = "visual fingerprint closely matches the source favicon (distance 0)"
            });

            var socialCandidate = new TyposquattingCandidate {
                Domain = "examp1e-social.com",
                Kind = TyposquattingVariantKind.Homoglyph,
                EditDistance = 1
            };
            SetAutoProperty(socialCandidate, "ARecords", (System.Collections.Generic.IReadOnlyList<string>)new[] { "1.1.1.1" });
            SetAutoProperty(socialCandidate, "VisualSimilarity", new TyposquattingVisualSimilarityMatch {
                Score = 100,
                HammingDistance = 0,
                LikelyClone = true,
                MatchedArtifactKind = TyposquattingVisualArtifactKind.OpenGraphImage,
                Summary = "visual fingerprint closely matches the source og:image (distance 0)"
            });

            TyposquattingCandidateScorer.ScoreCandidates(new[] { faviconCandidate, socialCandidate });

            Assert.True(socialCandidate.RiskScore > faviconCandidate.RiskScore);
            Assert.Contains(socialCandidate.RiskReasons, reason => reason.Contains("social preview", System.StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task ExternalLookalikeWithThreatAndImpersonationBecomesLikelyMalicious() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static HttpAnalysis BuildHttp(string url, string bodySha256, int bodyLength, string body, params string[] visitedUrls) {
                var analysis = new HttpAnalysis {
                    Subject = url
                };
                SetAutoProperty(analysis, "IsReachable", true);
                SetAutoProperty(analysis, "StatusCode", 200);
                SetAutoProperty(analysis, "BodySha256", bodySha256);
                SetAutoProperty(analysis, "BodyLength", bodyLength);
                SetAutoProperty(analysis, "Body", body);
                foreach (var visitedUrl in visitedUrls) {
                    analysis.VisitedUrls.Add(visitedUrl);
                }
                return analysis;
            }

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "example.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
                    }

                    if (name == "example.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.typo-host.net", Type = DnsRecordType.NS } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 5;
            analysis.EnrichmentOptions.IncludeWhois = true;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeHttp = true;
            analysis.EnrichmentOptions.IncludeThreatIntel = true;
            analysis.EnrichmentOptions.HttpOverride = (domain, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                "https://" + domain,
                "abc123",
                120,
                "<html><head><title>Example Portal</title></head><body>hello</body></html>",
                "https://www.example.com/login"));
            analysis.EnrichmentOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Evil Registrar"
            });
            analysis.EnrichmentOptions.ThreatIntelOverride = (domain, _) => {
                var threat = new ThreatIntelAnalysis {
                    Subject = domain
                };
                threat.Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.UrlHaus, IsListed = true });
                SetAutoProperty(threat, "Severity", "High");
                return Task.FromResult<ThreatIntelAnalysis?>(threat);
            };

            analysis.OwnershipProfileOptions.Enabled = true;
            analysis.OwnershipProfileOptions.IncludeWhois = true;
            analysis.OwnershipProfileOptions.IncludeIpEnrichment = false;
            analysis.OwnershipProfileOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Contoso Registrar"
            });

            analysis.ContentSimilarityOptions.Enabled = true;
            analysis.ContentSimilarityOptions.HttpOverride = (url, _) => Task.FromResult<HttpAnalysis?>(BuildHttp(
                url,
                "abc123",
                120,
                "<html><head><title>Example Portal</title></head><body>hello</body></html>",
                "https://www.example.com/login"));

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.Equal(TyposquattingDisposition.LikelyMalicious, candidate.Disposition);
            Assert.Contains(candidate.DispositionReasons, reason => reason.Contains("threat intelligence", System.StringComparison.OrdinalIgnoreCase));

            var view = DomainDetective.Views.Converters.Convert(analysis);
            Assert.Equal(1, view.LikelyMaliciousCount);
            Assert.True(view.AvailableCount > 0);

            var viewCandidate = Assert.Single(view.Candidates, entry => entry.Domain == "examp1e.com");
            Assert.Equal(TyposquattingDisposition.LikelyMalicious.ToString(), viewCandidate.Disposition);
            Assert.Contains(viewCandidate.DispositionReasons, reason => reason.Contains("threat intelligence", System.StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task SharedExternalInfrastructureClustersCandidatesAndRefreshesFinalRiskMetadata() {
            static void SetAutoProperty<T>(object target, string propertyName, T value) {
                var field = target.GetType().GetField($"<{propertyName}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(field);
                field!.SetValue(target, value);
            }

            static IpEnrichmentAnalysis BuildIpEnrichmentWithAsn(int asn) {
                var analysis = new IpEnrichmentAnalysis();
                SetAutoProperty(analysis, "UniqueIpCount", 1);
                SetAutoProperty(analysis, "AsnCounts", (System.Collections.Generic.IReadOnlyDictionary<int, int>)new System.Collections.Generic.Dictionary<int, int> {
                    [asn] = 1
                });
                SetAutoProperty(analysis, "Rows", (System.Collections.Generic.IReadOnlyList<IpEnrichmentRow>)new[] {
                    new IpEnrichmentRow {
                        AsName = asn == 64500 ? "Contoso Networks" : "Evil Hosting",
                        Country = asn == 64500 ? "US" : "NL",
                        Region = asn == 64500 ? "Virginia" : "Amsterdam"
                    }
                });
                return analysis;
            }

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "example.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
                    }

                    if (name == "example.com" && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } });
                    }

                    if ((name == "examp1e.com" || name == "exampl3.com") && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    if ((name == "examp1e.com" || name == "exampl3.com") && type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.typo-host.net", Type = DnsRecordType.NS } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 10;
            analysis.EnrichmentOptions.IncludeWhois = true;
            analysis.EnrichmentOptions.IncludeIpEnrichment = true;
            analysis.EnrichmentOptions.IncludeHttp = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = domain == "example.com" ? "Contoso Registrar" : "Evil Registrar",
                RegistrarAbuseEmail = domain == "example.com" ? "abuse@contoso.test" : "abuse@evil-registrar.test",
                RegistrarEmail = domain == "example.com" ? "help@contoso.test" : "ops@evil-registrar.test"
            });
            analysis.EnrichmentOptions.IpEnrichmentOverride = (domain, _) => Task.FromResult<IpEnrichmentAnalysis?>(BuildIpEnrichmentWithAsn(
                domain == "example.com" ? 64500 : 64599));

            analysis.OwnershipProfileOptions.Enabled = true;
            analysis.OwnershipProfileOptions.IncludeWhois = true;
            analysis.OwnershipProfileOptions.IncludeIpEnrichment = true;
            analysis.OwnershipProfileOptions.WhoisOverride = (domain, _) => Task.FromResult<WhoisAnalysis?>(new WhoisAnalysis {
                DomainName = domain,
                Registrar = "Contoso Registrar"
            });
            analysis.OwnershipProfileOptions.IpEnrichmentOverride = (_, _) => Task.FromResult<IpEnrichmentAnalysis?>(BuildIpEnrichmentWithAsn(64500));

            await analysis.Analyze("example.com", new InternalLogger());

            var examp1e = Assert.Single(analysis.Candidates, candidate => candidate.Domain == "examp1e.com");
            var exampl3 = Assert.Single(analysis.Candidates, candidate => candidate.Domain == "exampl3.com");
            var sharedCluster = Assert.Single(analysis.InfrastructureClusters, cluster => cluster.HasMultipleCandidates);
            var campaign = Assert.Single(analysis.InfrastructureCampaigns);

            Assert.Equal(2, sharedCluster.Domains.Count);
            Assert.Contains("examp1e.com", sharedCluster.Domains);
            Assert.Contains("exampl3.com", sharedCluster.Domains);
            Assert.Equal(sharedCluster.Id, examp1e.InfrastructureCluster?.Id);
            Assert.Equal(sharedCluster.Id, exampl3.InfrastructureCluster?.Id);
            Assert.Equal(System.Math.Max(examp1e.RiskScore, exampl3.RiskScore), sharedCluster.HighestRiskScore);
            Assert.Contains(examp1e.RiskReasons, reason => reason.Contains("shares external infrastructure", System.StringComparison.OrdinalIgnoreCase));
            Assert.Contains(exampl3.RiskReasons, reason => reason.Contains("shares external infrastructure", System.StringComparison.OrdinalIgnoreCase));
            Assert.Equal(sharedCluster.Id, campaign.ClusterId);
            Assert.Equal(TyposquattingInfrastructureCampaignSeverity.High, campaign.Severity);
            Assert.True(campaign.RequiresUrgentReview);
            Assert.Equal(2, campaign.CandidateCount);
            Assert.Equal(2, campaign.ActiveCount);
            Assert.Equal(System.Math.Max(examp1e.RiskScore, exampl3.RiskScore), campaign.HighestRiskScore);
            Assert.Equal("examp1e.com", campaign.TopCandidateDomain);
            Assert.Contains("shared", campaign.Summary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Evil Registrar", campaign.PrimaryRegistrar);
            Assert.Equal("abuse@evil-registrar.test", campaign.PrimaryAbuseContact);
            Assert.Equal("Evil Hosting", campaign.PrimaryHostingProvider);
            Assert.Equal("NL", campaign.PrimaryCountry);
            Assert.Equal(TyposquattingInfrastructureCampaignActionability.Immediate, campaign.Actionability);
            Assert.True(campaign.ActionabilityScore >= 70);
            Assert.Contains("abuse contact ready", campaign.ActionabilitySummary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("registrar Evil Registrar", campaign.PivotSummary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("abuse@evil-registrar.test", campaign.RecommendedAction, System.StringComparison.OrdinalIgnoreCase);
            Assert.Equal(TyposquattingInfrastructureCampaignEscalationRoute.Abuse, campaign.EscalationBundle.PrimaryRoute);
            Assert.Equal("abuse@evil-registrar.test", campaign.EscalationBundle.PrimaryContact);
            Assert.True(campaign.EscalationBundle.ReadyToEscalate);
            Assert.StartsWith("DD-TYPO-", campaign.EscalationBundle.CaseId, System.StringComparison.Ordinal);
            Assert.False(string.IsNullOrWhiteSpace(campaign.EscalationBundle.CaseFingerprint));
            Assert.Contains(campaign.EscalationBundle.CaseId, campaign.EscalationBundle.TrackingSummary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("examp1e.com", campaign.EscalationBundle.Domains);
            Assert.Contains("shared registrar", campaign.EscalationBundle.EvidenceSummary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("abuse escalation", campaign.EscalationBundle.Subject, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("We are reporting a suspected typosquatting campaign", campaign.EscalationBundle.DraftBody, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("reported domains", campaign.EscalationBundle.DraftBody, System.StringComparison.OrdinalIgnoreCase);
            Assert.False(string.IsNullOrWhiteSpace(campaign.EscalationBundle.DraftPreview));

            var view = DomainDetective.Views.Converters.Convert(analysis);
            Assert.Equal(1, view.InfrastructureClusterCount);
            Assert.Equal(1, view.MultiCandidateInfrastructureClusterCount);
            Assert.Equal(2, view.ClusteredCandidateCount);
            Assert.Equal(2, view.LargestInfrastructureClusterSize);
            Assert.Equal(1, view.HighPriorityCampaignCount);
            Assert.Equal(0, view.CriticalCampaignCount);
            Assert.NotNull(view.TopResponsePack);
            Assert.Equal("examp1e.com", view.TopResponsePack!.TopDomain);
            Assert.StartsWith("DD-TYPO-", view.TopResponsePack.CaseId, System.StringComparison.Ordinal);
            Assert.Contains("abuse@evil-registrar.test", view.TopResponsePack.TrackingSummary, System.StringComparison.OrdinalIgnoreCase);

            var viewCandidate = Assert.Single(view.Candidates, candidate => candidate.Domain == "examp1e.com");
            Assert.Equal(sharedCluster.Label, viewCandidate.InfrastructureClusterLabel);
            Assert.Equal(2, viewCandidate.InfrastructureClusterSize);
            Assert.Contains("shared", viewCandidate.InfrastructureClusterSummary, System.StringComparison.OrdinalIgnoreCase);

            var viewCampaign = Assert.Single(view.Campaigns);
            Assert.Equal(campaign.Label, viewCampaign.Label);
            Assert.Equal(TyposquattingInfrastructureCampaignSeverity.High.ToString(), viewCampaign.Severity);
            Assert.Equal(2, viewCampaign.CandidateCount);
            Assert.Equal("examp1e.com", viewCampaign.TopCandidateDomain);
            Assert.Equal("Evil Registrar", viewCampaign.PrimaryRegistrar);
            Assert.Equal("abuse@evil-registrar.test", viewCampaign.PrimaryAbuseContact);
            Assert.Equal("Evil Hosting", viewCampaign.PrimaryHostingProvider);
            Assert.Equal("NL", viewCampaign.PrimaryCountry);
            Assert.Equal(TyposquattingInfrastructureCampaignActionability.Immediate.ToString(), viewCampaign.Actionability);
            Assert.True(viewCampaign.ActionabilityScore >= 70);
            Assert.Equal(TyposquattingInfrastructureCampaignEscalationRoute.Abuse.ToString(), viewCampaign.EscalationPrimaryRoute);
            Assert.Equal("abuse@evil-registrar.test", viewCampaign.EscalationPrimaryContact);
            Assert.StartsWith("DD-TYPO-", viewCampaign.EscalationCaseId, System.StringComparison.Ordinal);
            Assert.False(string.IsNullOrWhiteSpace(viewCampaign.EscalationCaseFingerprint));
            Assert.Contains(viewCampaign.EscalationCaseId, viewCampaign.EscalationTrackingSummary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Escalation bundle ready", viewCampaign.EscalationSummary, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("typosquatting campaign", viewCampaign.EscalationDraftPreview, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Domains involved:", viewCampaign.EscalationDraftBody, System.StringComparison.OrdinalIgnoreCase);

            var section = DomainDetective.Reports.SectionProjectors.BuildTyposquatting(view);
            Assert.NotNull(section);
            Assert.NotNull(section!.TopResponsePack);
            Assert.Equal(viewCampaign.EscalationCaseId, section.TopResponsePack!.CaseId);
            Assert.Equal(viewCampaign.TopCandidateDomain, section.TopResponsePack.TopDomain);
            Assert.Contains("abuse@evil-registrar.test", section.TopResponsePack.TrackingSummary, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task DistinctResponsiveMxInfrastructureRaisesMailRiskSignals() {
            static SMTPBannerAnalysis BuildBanner(string host) {
                var analysis = new SMTPBannerAnalysis {
                    Subject = host
                };
                analysis.ServerResults[host + ":25"] = new SMTPBannerAnalysis.BannerResult {
                    Host = host,
                    Port = 25,
                    Banner = "220 " + host + " ESMTP",
                    StartsWith220 = true,
                    ContainsDomain = true,
                    ValidFormat = true,
                    ServerDomain = host
                };
                return analysis;
            }

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "example.com" && type == DnsRecordType.MX) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "10 mail.example.com", Type = DnsRecordType.MX } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.MX) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "10 mx.typo.test", Type = DnsRecordType.MX } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 10;
            analysis.EnrichmentOptions.IncludeWhois = false;
            analysis.EnrichmentOptions.IncludeHttp = false;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.IncludeWebStaticScan = false;
            analysis.EnrichmentOptions.IncludeSmtpBanner = true;
            analysis.EnrichmentOptions.SmtpBannerOverride = (_, mxHosts, _) => Task.FromResult<SMTPBannerAnalysis?>(BuildBanner(mxHosts[0]));

            analysis.OwnershipProfileOptions.Enabled = true;
            analysis.OwnershipProfileOptions.IncludeWhois = false;
            analysis.OwnershipProfileOptions.IncludeIpEnrichment = false;
            analysis.OwnershipProfileOptions.IncludeMx = true;

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, x => x.Domain == "examp1e.com");
            Assert.NotNull(candidate.Enrichment?.SmtpBanner);
            Assert.Contains(candidate.RiskReasons, reason => reason.Contains("mail exchanger responds over SMTP", System.StringComparison.OrdinalIgnoreCase));
            Assert.Contains(candidate.Ownership?.ExternalSignals ?? System.Array.Empty<string>(), reason => reason.Contains("different mail exchangers", System.StringComparison.OrdinalIgnoreCase));

            var view = DomainDetective.Views.Converters.Convert(analysis);
            var viewCandidate = Assert.Single(view.Candidates, x => x.Domain == "examp1e.com");
            Assert.True(viewCandidate.SmtpBannerReachable);
            Assert.Equal("mx.typo.test", viewCandidate.PrimaryMxHost);
            Assert.Contains("SMTP", viewCandidate.Enrichment?.Summary ?? string.Empty, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task ExternalMxThatAcceptsRecipientRaisesInterceptionSignals() {
            static SmtpRecipientAcceptanceAnalysis BuildAcceptance(string host, string recipient) {
                var analysis = new SmtpRecipientAcceptanceAnalysis {
                    Subject = host
                };
                analysis.ServerResults[host + ":25"] = new SmtpRecipientAcceptanceAnalysis.RecipientAcceptanceResult {
                    Host = host,
                    Port = 25,
                    Recipient = recipient,
                    Accepted = true,
                    MailFromStatusCode = 250,
                    RecipientStatusCode = 250,
                    MailFromResponse = "250 OK",
                    RecipientResponse = "250 Accepted"
                };
                return analysis;
            }

            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "example.com" && type == DnsRecordType.MX) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "10 mail.example.com", Type = DnsRecordType.MX } });
                    }

                    if (name == "examp1e.com" && type == DnsRecordType.MX) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "10 mx.typo.test", Type = DnsRecordType.MX } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.EnrichmentOptions.MaxCandidates = 10;
            analysis.EnrichmentOptions.IncludeWhois = false;
            analysis.EnrichmentOptions.IncludeHttp = false;
            analysis.EnrichmentOptions.IncludeIpEnrichment = false;
            analysis.EnrichmentOptions.IncludeThreatIntel = false;
            analysis.EnrichmentOptions.IncludeWebStaticScan = false;
            analysis.EnrichmentOptions.IncludeSmtpRecipientAcceptance = true;
            analysis.EnrichmentOptions.SmtpRecipientAcceptanceOverride = (domain, mxHosts, _) =>
                Task.FromResult<SmtpRecipientAcceptanceAnalysis?>(BuildAcceptance(mxHosts[0], "postmaster@" + domain));

            analysis.OwnershipProfileOptions.Enabled = true;
            analysis.OwnershipProfileOptions.IncludeWhois = false;
            analysis.OwnershipProfileOptions.IncludeIpEnrichment = false;
            analysis.OwnershipProfileOptions.IncludeMx = true;

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, x => x.Domain == "examp1e.com");
            Assert.NotNull(candidate.Enrichment?.SmtpRecipientAcceptance);
            Assert.Contains(candidate.RiskReasons, reason => reason.Contains("accepts recipients", System.StringComparison.OrdinalIgnoreCase));
            Assert.Equal(TyposquattingDisposition.LikelyMalicious, candidate.Disposition);

            var view = DomainDetective.Views.Converters.Convert(analysis);
            var viewCandidate = Assert.Single(view.Candidates, x => x.Domain == "examp1e.com");
            Assert.True(viewCandidate.SmtpRecipientAccepted);
            Assert.Contains("SMTP-RCPT", viewCandidate.Enrichment?.Summary ?? string.Empty, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("accepted postmaster@examp1e.com", viewCandidate.SmtpRecipientAcceptanceSummary, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task BrowserScreenshotOverrideProducesRenderedVisualMatch() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } });
                    }

                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            analysis.VisualSimilarityOptions.Enabled = true;
            analysis.VisualSimilarityOptions.EnableBrowserCapture = true;
            analysis.VisualSimilarityOptions.EnableStaticAssetCapture = false;
            analysis.VisualSimilarityOptions.BrowserCaptureOverride = (url, _) => Task.FromResult<TyposquattingVisualArtifact?>(new TyposquattingVisualArtifact {
                Kind = TyposquattingVisualArtifactKind.Screenshot,
                FingerprintHex = "0123456789abcdef",
                SourceUrl = url
            });

            await analysis.Analyze("example.com", new InternalLogger());

            var candidate = Assert.Single(analysis.Candidates, x => x.Domain == "examp1e.com");
            Assert.NotNull(candidate.VisualSimilarity);
            Assert.True(candidate.VisualSimilarity!.LikelyClone);
            Assert.Equal(TyposquattingVisualArtifactKind.Screenshot, candidate.VisualSimilarity.MatchedArtifactKind);
            Assert.Contains("rendered screenshot", candidate.VisualSimilarity.Summary, System.StringComparison.OrdinalIgnoreCase);
        }
    }
}

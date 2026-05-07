using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestDomainPortfolioSnapshot {
        [Fact]
        public void BuildCreatesStorageFreeSectionWithAssessmentsAndFacts() {
            var capturedAt = new DateTimeOffset(2026, 5, 5, 12, 0, 0, TimeSpan.Zero);
            var healthCheck = new DomainHealthCheck();
            healthCheck.DmarcAnalysis.Subject = "example.com";
            healthCheck.DmarcAnalysis.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DMARC",
                Code = "DMARC.Policy.Weak",
                Message = "Weak policy"
            });

            var snapshot = healthCheck.ToPortfolioSnapshot(
                "example.com",
                new[] { HealthCheckType.DMARC },
                capturedAt);

            Assert.Equal("example.com", snapshot.Subject);
            Assert.Equal(1, snapshot.SchemaVersion);
            Assert.Equal(capturedAt, snapshot.CapturedAtUtc);
            Assert.Single(snapshot.Sections);
            Assert.Single(snapshot.Assessments);

            var section = snapshot.Sections[0];
            Assert.Equal("DMARC", section.Key);
            Assert.Equal("Mail", section.Area);
            Assert.Equal("Warning", section.Status);
            Assert.Equal(1, section.WarningCount);
            Assert.Contains(section.Facts, fact => fact.Key == "Subject" && fact.Value == "example.com");
        }

        [Fact]
        public void BuildRejectsInvalidArguments() {
            var healthCheck = new DomainHealthCheck();

            Assert.Throws<ArgumentException>(() => DomainPortfolioSnapshotBuilder.Build("", healthCheck));
            Assert.Throws<ArgumentException>(() => DomainPortfolioSnapshotBuilder.Build("   ", healthCheck));
            Assert.Throws<ArgumentNullException>(() => DomainPortfolioSnapshotBuilder.Build("example.com", null!));
        }

        [Theory]
        [InlineData(HealthCheckType.DELEGATION, "DNS")]
        [InlineData(HealthCheckType.WHOIS, "Registration")]
        [InlineData(HealthCheckType.RDAP, "Registration")]
        [InlineData(HealthCheckType.ROBOTS, "Web")]
        [InlineData(HealthCheckType.HPKP, "Web")]
        [InlineData(HealthCheckType.CONTACT, "Identity")]
        [InlineData(HealthCheckType.MESSAGEHEADER, "Mail")]
        [InlineData(HealthCheckType.OPENRESOLVER, "Security")]
        [InlineData(HealthCheckType.DANGLINGCNAME, "Security")]
        [InlineData(HealthCheckType.SNMP, "Security")]
        [InlineData(HealthCheckType.NTP, "Security")]
        [InlineData(HealthCheckType.TYPOSQUATTING, "Security")]
        [InlineData(HealthCheckType.FLATTENINGSERVICE, "Mail")]
        [InlineData((HealthCheckType)int.MaxValue, "General")]
        public void BuildMapsKnownPortfolioAreas(HealthCheckType check, string expectedArea) {
            Assert.Equal(expectedArea, DomainPortfolioSnapshotBuilder.ResolveArea(check));
        }

        [Fact]
        public void BuildMapsEveryCurrentHealthCheckToSpecificPortfolioArea() {
            // New checks should choose an explicit portfolio area instead of drifting into General.
            var mapped = Enum.GetValues(typeof(HealthCheckType))
                .Cast<HealthCheckType>()
                .Where(check => DomainPortfolioSnapshotBuilder.ResolveArea(check) == "General")
                .Select(static check => check.ToString())
                .ToList();

            Assert.Empty(mapped);
        }

        [Fact]
        public void BuildSkipsDateSentinelsAndNormalizesUnspecifiedDateTimeAsUtc() {
            var facts = DomainPortfolioSnapshotBuilder.ExtractFacts(new FactExtractionFixture()).ToList();

            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.DefaultDate));
            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.DefaultOffset));
            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.Assessments));
            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.Metadata));
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.UnspecifiedUtc) &&
                fact.Value == "2026-05-07T12:00:00.0000000Z" &&
                fact.Kind == DomainPortfolioFactKind.DateTime);
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.LocalTime) &&
                fact.Value == FactExtractionFixture.ExpectedLocalTimeUtc &&
                fact.Kind == DomainPortfolioFactKind.DateTime);
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.PositiveDuration) &&
                fact.Value == "00:00:00.0250000" &&
                fact.Kind == DomainPortfolioFactKind.Duration);
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.Endpoints) &&
                fact.Value == "https://example.com/a|https://example.com/b" &&
                fact.Kind == DomainPortfolioFactKind.Collection);
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.Statuses) &&
                fact.Value == @"active\|pending|server\\hold" &&
                fact.Kind == DomainPortfolioFactKind.Collection);
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.Durations) &&
                fact.Value == "01:00:00" &&
                fact.Kind == DomainPortfolioFactKind.Collection);
            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.DefaultDuration));
            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.Unreadable));
        }

        [Fact]
        public void BuildSkipsKnownNoisyAnalysisProperties() {
            var facts = DomainPortfolioSnapshotBuilder.ExtractFacts(new DmarcAnalysis {
                Subject = "example.com"
            }).ToList();

            Assert.DoesNotContain(facts, fact => fact.Key == "Assessments");
            Assert.DoesNotContain(facts, fact => fact.Key == "Recommendations");
            Assert.DoesNotContain(facts, fact => fact.Key == "DnsConfiguration");
            Assert.DoesNotContain(facts, fact => fact.Key == "QueryDnsOverride");
        }

        [Fact]
        public void BuildFormatsAcronymLabels() {
            Assert.Equal("IPv4 Addresses", DomainPortfolioSnapshotBuilder.ToDisplayLabel("IPv4Addresses"));
            Assert.Equal("SPF Record", DomainPortfolioSnapshotBuilder.ToDisplayLabel("SPFRecord"));
            Assert.Equal("DNSSEC Enabled", DomainPortfolioSnapshotBuilder.ToDisplayLabel("DNSSECEnabled"));
            Assert.Equal("MX Hosts", DomainPortfolioSnapshotBuilder.ToDisplayLabel("MXHosts"));
        }

        [Fact]
        public void BuildFiltersRequestedChecksAndPopulatesEvaluatorVersion() {
            var capturedAt = new DateTimeOffset(2026, 5, 5, 12, 0, 0, TimeSpan.Zero);
            var healthCheck = new DomainHealthCheck();
            healthCheck.DmarcAnalysis.Subject = "example.com";
            healthCheck.SpfAnalysis.Subject = "example.com";

            var snapshot = DomainPortfolioSnapshotBuilder.Build(
                "example.com",
                healthCheck,
                new[] { HealthCheckType.DMARC },
                capturedAt);

            Assert.NotEmpty(snapshot.EvaluatorVersion);
            Assert.Single(snapshot.Sections);
            Assert.Equal("DMARC", snapshot.Sections[0].Key);
        }

        [Fact]
        public void BuildWithNullCheckFilterIncludesPopulatedChecks() {
            var capturedAt = new DateTimeOffset(2026, 5, 5, 12, 0, 0, TimeSpan.Zero);
            var healthCheck = new DomainHealthCheck();
            healthCheck.DmarcAnalysis.Subject = "example.com";
            healthCheck.SpfAnalysis.Subject = "example.com";

            var snapshot = DomainPortfolioSnapshotBuilder.Build(
                "example.com",
                healthCheck,
                null,
                capturedAt);

            Assert.Contains(snapshot.Sections, section => section.Key == "DMARC");
            Assert.Contains(snapshot.Sections, section => section.Key == "SPF");
        }

        [Fact]
        public void BuildWithEmptyCheckFilterProducesEmptySnapshot() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.DmarcAnalysis.Subject = "example.com";

            var snapshot = DomainPortfolioSnapshotBuilder.Build(
                "example.com",
                healthCheck,
                Array.Empty<HealthCheckType>(),
                new DateTimeOffset(2026, 5, 5, 12, 0, 0, TimeSpan.Zero));

            Assert.Empty(snapshot.Sections);
            Assert.Empty(snapshot.Assessments);
        }

        [Fact]
        public void BuildSummariesRoundTripsEscapedCollectionFacts() {
            var snapshot = new DomainPortfolioSnapshot {
                Subject = "example.com",
                Sections = new List<DomainPortfolioSection> {
                    new() {
                        Key = "WHOIS",
                        Facts = new List<DomainPortfolioFact> {
                            new() {
                                Key = "NameServers",
                                Value = @"ns1.example.com\|backup|ns2.example.com",
                                Kind = DomainPortfolioFactKind.Collection
                            }
                        }
                    }
                }
            };

            var summaries = DomainPortfolioSnapshotBuilder.BuildSummaries(snapshot);

            Assert.Equal(new[] { "ns1.example.com|backup", "ns2.example.com" }, summaries.Registration.NameServers);
        }

        [Fact]
        public void BuildSummariesDoesNotSplitPlainStringFactsContainingSeparator() {
            var snapshot = new DomainPortfolioSnapshot {
                Subject = "example.com",
                Sections = new List<DomainPortfolioSection> {
                    new() {
                        Key = "WHOIS",
                        Facts = new List<DomainPortfolioFact> {
                            new() {
                                Key = "Status",
                                Value = "clientTransferProhibited|serverHold",
                                Kind = DomainPortfolioFactKind.String
                            }
                        }
                    }
                }
            };

            var summaries = DomainPortfolioSnapshotBuilder.BuildSummaries(snapshot);

            Assert.Equal(new[] { "clientTransferProhibited|serverHold" }, summaries.Registration.Statuses);
        }

        [Fact]
        public void BuildSummariesProjectsTypedPortfolioFields() {
            var capturedAt = new DateTimeOffset(2026, 5, 7, 0, 0, 0, TimeSpan.Zero);
            var snapshot = new DomainPortfolioSnapshot {
                Subject = "example.com",
                CapturedAtUtc = capturedAt,
                Sections = new List<DomainPortfolioSection> {
                    new() {
                        Key = "WHOIS",
                        Facts = new List<DomainPortfolioFact> {
                            new() { Key = "Registrar", Value = "Example Registrar" },
                            new() { Key = "ExpirationDate", Value = "2026-05-17T00:00:00.0000000Z", Kind = DomainPortfolioFactKind.DateTime },
                            new() { Key = "Status", Value = "clientTransferProhibited|serverTransferProhibited", Kind = DomainPortfolioFactKind.Collection }
                        }
                    },
                    new() {
                        Key = "MX",
                        Facts = new List<DomainPortfolioFact> {
                            new() { Key = "Hosts", Value = "mx1.example.net|mx2.example.net", Kind = DomainPortfolioFactKind.Collection },
                            new() { Key = "ProviderPrimary", Value = "Example Mail" }
                        }
                    },
                    new() {
                        Key = "DMARC",
                        Facts = new List<DomainPortfolioFact> {
                            new() { Key = "DmarcRecord", Value = "v=DMARC1; p=reject" },
                            new() { Key = "PolicyShort", Value = "reject" }
                        }
                    },
                    new() {
                        Key = "CERT",
                        Facts = new List<DomainPortfolioFact> {
                            new() { Key = "Thumbprint", Value = "ABC123" },
                            new() { Key = "Issuer", Value = "Example CA" },
                            new() { Key = "NotAfter", Value = "2026-06-06T00:00:00.0000000Z", Kind = DomainPortfolioFactKind.DateTime },
                            new() { Key = "Valid", Value = "true", Kind = DomainPortfolioFactKind.Boolean }
                        }
                    }
                }
            };

            var summaries = DomainPortfolioSnapshotBuilder.BuildSummaries(snapshot);

            Assert.Equal("Example Registrar", summaries.Registration.Registrar);
            Assert.Equal(10, summaries.Registration.DaysToExpiry);
            Assert.Equal(2, summaries.Registration.Statuses.Count);
            Assert.Equal(new[] { "mx1.example.net", "mx2.example.net" }, summaries.Dns.MxHosts);
            Assert.Equal("Example Mail", summaries.Mail.Provider);
            Assert.Equal("reject", summaries.Mail.DmarcPolicy);
            Assert.Equal("ABC123", summaries.Certificate.Fingerprint);
            Assert.Equal("Example CA", summaries.Certificate.Issuer);
            Assert.Equal(30, summaries.Certificate.DaysToExpiry);
            Assert.True(summaries.Certificate.Valid);
        }

        [Fact]
        public void BuildSummariesPreservesNegativeDaysToExpiry() {
            var capturedAt = new DateTimeOffset(2026, 5, 7, 0, 0, 0, TimeSpan.Zero);
            var snapshot = new DomainPortfolioSnapshot {
                Subject = "example.com",
                CapturedAtUtc = capturedAt,
                Sections = new List<DomainPortfolioSection> {
                    new() {
                        Key = "WHOIS",
                        Facts = new List<DomainPortfolioFact> {
                            new() { Key = "ExpirationDate", Value = "2026-05-02T00:00:00.0000000Z", Kind = DomainPortfolioFactKind.DateTime }
                        }
                    },
                    new() {
                        Key = "CERT",
                        Facts = new List<DomainPortfolioFact> {
                            new() { Key = "NotAfter", Value = "2026-05-05T00:00:00.0000000Z", Kind = DomainPortfolioFactKind.DateTime }
                        }
                    }
                }
            };

            var summaries = DomainPortfolioSnapshotBuilder.BuildSummaries(snapshot);

            Assert.Equal(-5, summaries.Registration.DaysToExpiry);
            Assert.Equal(-2, summaries.Certificate.DaysToExpiry);
        }

        [Fact]
        public void BuildSummariesWithoutMatchingSectionsReturnsEmptySummaries() {
            var snapshot = new DomainPortfolioSnapshot {
                Subject = "example.com",
                CapturedAtUtc = new DateTimeOffset(2026, 5, 7, 0, 0, 0, TimeSpan.Zero),
                Sections = new List<DomainPortfolioSection> {
                    new() {
                        Key = "UNKNOWN",
                        Area = "General",
                        Facts = new List<DomainPortfolioFact> {
                            new() { Key = "OtherValue", Value = "value" }
                        }
                    }
                }
            };

            var summaries = DomainPortfolioSnapshotBuilder.BuildSummaries(snapshot);

            Assert.Null(summaries.Registration.Registrar);
            Assert.Empty(summaries.Registration.Statuses);
            Assert.Empty(summaries.Dns.NameServers);
            Assert.Null(summaries.Certificate.Fingerprint);
            Assert.Null(summaries.Mail.Provider);
            Assert.Null(summaries.Website.StatusCode);
        }

        [Fact]
        public void BuildSummariesNormalizesNullSummariesAssignment() {
            var snapshot = new DomainPortfolioSnapshot {
                Summaries = null!
            };

            Assert.NotNull(snapshot.Summaries);
            Assert.NotNull(snapshot.Summaries.Registration);
        }

        [Fact]
        public void CompareDetectsAddedRemovedAndChangedFacts() {
            var previous = CreateSnapshot(
                "example.com",
                new DomainPortfolioFact { Key = "Registrar", Value = "Registrar A", Kind = DomainPortfolioFactKind.String },
                new DomainPortfolioFact { Key = "Expiry", Value = "2026-06-01", Kind = DomainPortfolioFactKind.DateTime },
                new DomainPortfolioFact { Key = "NameServers", Value = "ns1.example.net|ns2.example.net", Kind = DomainPortfolioFactKind.Collection });
            var current = CreateSnapshot(
                "example.com",
                new DomainPortfolioFact { Key = "Registrar", Value = "Registrar B", Kind = DomainPortfolioFactKind.String },
                new DomainPortfolioFact { Key = "NameServers", Value = "ns1.example.net|ns3.example.net", Kind = DomainPortfolioFactKind.Collection },
                new DomainPortfolioFact { Key = "Locked", Value = "true", Kind = DomainPortfolioFactKind.Boolean });

            var changes = DomainPortfolioSnapshotDiffer.Compare(previous, current);

            Assert.Equal("example.com", changes.Subject);
            Assert.Equal(4, changes.Changes.Count);
            Assert.Contains(changes.Changes, change =>
                change.Kind == DomainPortfolioChangeKind.Changed &&
                change.SectionKey == "WHOIS" &&
                change.FactKey == "Registrar" &&
                change.PreviousValue == "Registrar A" &&
                change.CurrentValue == "Registrar B");
            Assert.Contains(changes.Changes, change =>
                change.Kind == DomainPortfolioChangeKind.Removed &&
                change.FactKey == "Expiry");
            Assert.Contains(changes.Changes, change =>
                change.Kind == DomainPortfolioChangeKind.Added &&
                change.FactKey == "Locked");
            Assert.Contains(changes.Changes, change =>
                change.Kind == DomainPortfolioChangeKind.Changed &&
                change.FactKey == "NameServers");
        }

        [Fact]
        public void CompareReportsSectionStatusChanges() {
            var previous = CreateSnapshot("example.com");
            previous.Sections[0].Status = "OK";
            var current = CreateSnapshot("example.com");
            current.Sections[0].Status = "Error";

            var changes = DomainPortfolioSnapshotDiffer.Compare(previous, current);

            Assert.Contains(changes.Changes, change =>
                change.Key == "section:WHOIS:status" &&
                change.Kind == DomainPortfolioChangeKind.Changed &&
                change.PreviousValue == "OK" &&
                change.CurrentValue == "Error");
        }

        [Fact]
        public void CompareDetectsEntireAddedAndRemovedSectionsWithFacts() {
            var empty = new DomainPortfolioSnapshot {
                Subject = "example.com"
            };
            var populated = CreateSnapshot(
                "example.com",
                new DomainPortfolioFact { Key = "Registrar", Value = "Example Registrar", Kind = DomainPortfolioFactKind.String },
                new DomainPortfolioFact { Key = "Locked", Value = "true", Kind = DomainPortfolioFactKind.Boolean });

            var added = DomainPortfolioSnapshotDiffer.Compare(empty, populated);
            var removed = DomainPortfolioSnapshotDiffer.Compare(populated, empty);

            Assert.Contains(added.Changes, change =>
                change.Key == "section:WHOIS:status" &&
                change.Kind == DomainPortfolioChangeKind.Added &&
                change.CurrentValue == "OK");
            Assert.Contains(added.Changes, change =>
                change.Key == "fact:WHOIS:Registrar" &&
                change.Kind == DomainPortfolioChangeKind.Added &&
                change.CurrentValue == "Example Registrar");
            Assert.Contains(removed.Changes, change =>
                change.Key == "section:WHOIS:status" &&
                change.Kind == DomainPortfolioChangeKind.Removed &&
                change.PreviousValue == "OK");
            Assert.Contains(removed.Changes, change =>
                change.Key == "fact:WHOIS:Locked" &&
                change.Kind == DomainPortfolioChangeKind.Removed &&
                change.PreviousValue == "true");
        }

        [Fact]
        public void CompareRejectsDuplicatePortfolioKeys() {
            var previous = CreateSnapshot("example.com");
            var duplicateSection = CreateSnapshot("example.com");
            duplicateSection.Sections.Add(new DomainPortfolioSection {
                Key = "WHOIS",
                Status = "OK"
            });
            var duplicateFact = CreateSnapshot(
                "example.com",
                new DomainPortfolioFact { Key = "Registrar", Value = "A" },
                new DomainPortfolioFact { Key = "Registrar", Value = "B" });

            Assert.Throws<InvalidOperationException>(() => DomainPortfolioSnapshotDiffer.Compare(previous, duplicateSection));
            Assert.Throws<InvalidOperationException>(() => DomainPortfolioSnapshotDiffer.Compare(previous, duplicateFact));
            Assert.Throws<InvalidOperationException>(() => DomainPortfolioSnapshotBuilder.BuildSummaries(duplicateSection));
            Assert.Throws<InvalidOperationException>(() => DomainPortfolioSnapshotBuilder.BuildSummaries(duplicateFact));
        }

        [Fact]
        public void CompareEmptySnapshotsProducesNoChanges() {
            var previous = new DomainPortfolioSnapshot {
                Subject = "example.com"
            };
            var current = new DomainPortfolioSnapshot {
                Subject = "example.com"
            };

            var changes = DomainPortfolioSnapshotDiffer.Compare(previous, current);

            Assert.Empty(changes.Changes);
        }

        [Fact]
        public void CompareRejectsInvalidArguments() {
            var snapshot = CreateSnapshot("example.com");

            Assert.Throws<ArgumentNullException>(() => DomainPortfolioSnapshotDiffer.Compare(null!, snapshot));
            Assert.Throws<ArgumentNullException>(() => DomainPortfolioSnapshotDiffer.Compare(snapshot, null!));
        }

        [Fact]
        public void CompareRejectsDifferentSubjects() {
            var previous = CreateSnapshot("example.com");
            var current = CreateSnapshot("contoso.com");

            Assert.Throws<ArgumentException>(() => DomainPortfolioSnapshotDiffer.Compare(previous, current));
        }

        [Fact]
        public void CompareRejectsUnsupportedSchemaVersions() {
            var previous = CreateSnapshot("example.com");
            var current = CreateSnapshot("example.com");
            current.SchemaVersion = 2;

            Assert.Throws<NotSupportedException>(() => DomainPortfolioSnapshotDiffer.Compare(previous, current));
        }

        private static DomainPortfolioSnapshot CreateSnapshot(string subject, params DomainPortfolioFact[] facts)
            => new() {
                Subject = subject,
                CapturedAtUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
                Sections = new List<DomainPortfolioSection> {
                    new() {
                        Key = "WHOIS",
                        DisplayName = "WHOIS",
                        Area = "Registration",
                        Status = "OK",
                        Facts = facts.ToList()
                    }
                }
            };

        private sealed class FactExtractionFixture {
            public DateTime DefaultDate { get; set; }

            public DateTimeOffset DefaultOffset { get; set; }

            public DateTime UnspecifiedUtc { get; set; } = new(2026, 5, 7, 12, 0, 0, DateTimeKind.Unspecified);

            public DateTime LocalTime { get; set; } = new(2026, 5, 7, 12, 0, 0, DateTimeKind.Local);

            // Expected value uses the runtime local offset so the test stays stable across CI time zones.
            public static string ExpectedLocalTimeUtc => new DateTime(2026, 5, 7, 12, 0, 0, DateTimeKind.Local)
                .ToUniversalTime()
                .ToString("O", System.Globalization.CultureInfo.InvariantCulture);

            public TimeSpan DefaultDuration { get; set; }

            public TimeSpan PositiveDuration { get; set; } = TimeSpan.FromMilliseconds(25);

            public List<Uri> Endpoints { get; set; } = new() {
                // Intentionally out of order to pin deterministic collection sorting.
                new("https://example.com/b"),
                new("https://example.com/a")
            };

            public List<string> Statuses { get; set; } = new() {
                "active|pending",
                @"server\hold",
                "active|pending"
            };

            public List<TimeSpan> Durations { get; set; } = new() {
                TimeSpan.Zero,
                TimeSpan.FromHours(1)
            };

            public List<string> Assessments { get; set; } = new() {
                "ignore-me"
            };

            public Dictionary<string, string> Metadata { get; set; } = new() {
                ["key"] = "value"
            };

            public string Unreadable => throw new NotSupportedException("Synthetic unreadable property.");
        }
    }
}

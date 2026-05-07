using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

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
            Assert.Throws<ArgumentNullException>(() => DomainPortfolioSnapshotBuilder.Build("example.com", null!));
        }

        [Fact]
        public void BuildMapsKnownPortfolioAreas() {
            Assert.Equal("DNS", ResolveArea(HealthCheckType.DELEGATION));
            Assert.Equal("Web", ResolveArea(HealthCheckType.ROBOTS));
            Assert.Equal("Web", ResolveArea(HealthCheckType.HPKP));
            Assert.Equal("Mail", ResolveArea(HealthCheckType.MESSAGEHEADER));
            Assert.Equal("Security", ResolveArea(HealthCheckType.OPENRESOLVER));
            Assert.Equal("Security", ResolveArea(HealthCheckType.DANGLINGCNAME));
            Assert.Equal("Security", ResolveArea(HealthCheckType.SNMP));
            Assert.Equal("Security", ResolveArea(HealthCheckType.NTP));
            Assert.Equal("Security", ResolveArea(HealthCheckType.TYPOSQUATTING));
            Assert.Equal("Security", ResolveArea(HealthCheckType.FLATTENINGSERVICE));
            Assert.Equal("General", ResolveArea((HealthCheckType)int.MaxValue));
        }

        [Fact]
        public void BuildSkipsDateSentinelsAndNormalizesUnspecifiedDateTimeAsUtc() {
            var facts = ExtractFactsFor(new FactExtractionFixture());

            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.DefaultDate));
            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.DefaultOffset));
            Assert.DoesNotContain(facts, fact => fact.Key == nameof(FactExtractionFixture.Assessments));
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.UnspecifiedUtc) &&
                fact.Value == "2026-05-07T12:00:00.0000000Z" &&
                fact.Kind == DomainPortfolioFactKind.DateTime);
            Assert.Contains(facts, fact =>
                fact.Key == nameof(FactExtractionFixture.Endpoints) &&
                fact.Value == "https://example.com/a|https://example.com/b" &&
                fact.Kind == DomainPortfolioFactKind.Collection);
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

        private static DomainPortfolioSnapshot CreateSnapshot(string subject, params DomainPortfolioFact[] facts)
            => new() {
                Subject = subject,
                CapturedAtUtc = DateTimeOffset.UtcNow,
                Sections = new List<DomainPortfolioSection> {
                    new() {
                        Key = "WHOIS",
                        DisplayName = "WHOIS",
                        Area = "Security",
                        Status = "OK",
                        Facts = facts.ToList()
                    }
                }
            };

        private static string ResolveArea(HealthCheckType check) {
            var method = typeof(DomainPortfolioSnapshotBuilder).GetMethod("ResolveArea", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);
            return (string)method!.Invoke(null, new object[] { check })!;
        }

        private static List<DomainPortfolioFact> ExtractFactsFor(object analysis) {
            var method = typeof(DomainPortfolioSnapshotBuilder).GetMethod("ExtractFacts", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);
            return ((IEnumerable<DomainPortfolioFact>)method!.Invoke(null, new[] { analysis })!).ToList();
        }

        private sealed class FactExtractionFixture {
            public DateTime DefaultDate { get; set; }

            public DateTimeOffset DefaultOffset { get; set; }

            public DateTime UnspecifiedUtc { get; set; } = new(2026, 5, 7, 12, 0, 0, DateTimeKind.Unspecified);

            public List<Uri> Endpoints { get; set; } = new() {
                new("https://example.com/b"),
                new("https://example.com/a")
            };

            public List<string> Assessments { get; set; } = new() {
                "ignore-me"
            };
        }
    }
}

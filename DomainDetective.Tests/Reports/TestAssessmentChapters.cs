using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports {
    public class TestAssessmentChapters {
        [Fact]
        public void EveryCheckHasAChapterInItsOwnArea() {
            foreach (HealthCheckType check in (HealthCheckType[])Enum.GetValues(typeof(HealthCheckType))) {
                AnalysisArea area = Converters.AreaForKind(check);
                AssessmentChapter chapter = DomainAssessmentCatalog.ChapterFor(check, area);
                Assert.True(chapter.Area == area, $"{check} is in area {area} but its chapter '{chapter.Key}' is in {chapter.Area}.");
            }
        }

        [Fact]
        public void ChapterKeysAreUniqueAndEveryAreaHasOne() {
            List<string> keys = DomainAssessmentCatalog.Chapters.Select(static c => c.Key).ToList();
            Assert.Equal(keys.Count, keys.Distinct(StringComparer.Ordinal).Count());
            foreach (AnalysisArea area in DomainAssessmentCatalog.AreaOrder) {
                Assert.Contains(DomainAssessmentCatalog.Chapters, c => c.Area == area);
            }
        }

        [Fact]
        public void ChaptersOfAnAreaAreListedTogether() {
            var seen = new HashSet<AnalysisArea>();
            AnalysisArea? previous = null;
            foreach (AssessmentChapter chapter in DomainAssessmentCatalog.Chapters) {
                if (chapter.Area != previous) {
                    Assert.True(seen.Add(chapter.Area), $"Chapters of {chapter.Area} are split by another area.");
                    previous = chapter.Area;
                }
            }
        }

        [Fact]
        public void ResultWithoutACheckGoesToTheFirstChapterOfItsArea() {
            Assert.Equal("name-servers", DomainAssessmentCatalog.ChapterFor(null, AnalysisArea.DNS).Key);
            Assert.Equal("general", DomainAssessmentCatalog.ChapterFor(null, AnalysisArea.General).Key);
        }

        [Fact]
        public void CombinedScoreWeighsScoredChecksOnly() {
            var checks = new[] {
                new CheckAssessment { Scored = true, Score = 100, Weight = 3 },
                new CheckAssessment { Scored = true, Score = 40, Weight = 1 },
                new CheckAssessment { Scored = false, Score = 0, Weight = 5 }
            };
            Assert.Equal(85, DomainAssessmentCatalog.CombinedScore(checks));
            Assert.Null(DomainAssessmentCatalog.CombinedScore(new[] { new CheckAssessment { Scored = false } }));
        }
    }
}

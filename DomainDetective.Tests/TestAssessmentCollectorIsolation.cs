using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestAssessmentCollectorIsolation {
        private sealed class FakeAnalysis : IHasAssessments {
            public List<Assessment> Assessments { get; } = new();
        }

        [Fact]
        public async Task ConcurrentCollectorsOnOneLoggerOnlyRecordTheirOwnEvents() {
            var logger = new InternalLogger();
            var mx = new FakeAnalysis();
            var http = new FakeAnalysis();
            using var bothRunning = new Barrier(2);

            async Task Run(FakeAnalysis analysis, string category, string message) {
                await Task.Yield();
                using var collector = AssessmentCollector.ForAnalysis(logger, analysis, category);
                bothRunning.SignalAndWait();
                logger.WriteWarning(message);
                bothRunning.SignalAndWait();
            }

            await Task.WhenAll(
                Task.Run(() => Run(mx, "MX", "mx warning")),
                Task.Run(() => Run(http, "HTTP", "http warning")));

            Assert.Equal(new[] { "mx warning" }, mx.Assessments.Select(static a => a.Message));
            Assert.Equal(new[] { "http warning" }, http.Assessments.Select(static a => a.Message));
        }

        [Fact]
        public async Task RepeatedMessagesStillReachEachAnalysis() {
            // One health check verifying two domains logs "No DMARC record found." twice; the logger shows it once,
            // but both analyses must record the finding, or the second domain would pass.
            var logger = new InternalLogger();
            var first = new DmarcAnalysis();
            var second = new DmarcAnalysis();

            await first.AnalyzeDmarcRecords(new List<DnsClientX.DnsAnswer>(), logger, "one.example");
            await second.AnalyzeDmarcRecords(new List<DnsClientX.DnsAnswer>(), logger, "two.example");

            Assert.Contains(first.Assessments, static a => a.Code == DmarcCodes.MissingRecord);
            Assert.Contains(second.Assessments, static a => a.Code == DmarcCodes.MissingRecord);
        }

        [Fact]
        public void RepeatedMessagesOutsideAnAnalysisAreRaisedOnce() {
            var logger = new InternalLogger();
            int raised = 0;
            logger.OnWarningMessage += (_, _) => raised++;

            logger.WriteWarning("same");
            logger.WriteWarning("same");

            Assert.Equal(1, raised);
        }

        [Fact]
        public async Task NestedCollectorEventsReachTheEnclosingCollector() {
            var logger = new InternalLogger();
            var outer = new FakeAnalysis();
            var inner = new FakeAnalysis();

            using (AssessmentCollector.ForAnalysis(logger, outer, "OUTER")) {
                await Task.Run(() => {
                    using var nested = AssessmentCollector.ForAnalysis(logger, inner, "INNER");
                    logger.WriteWarning("nested warning");
                });
                logger.WriteWarning("outer warning");
            }
            logger.WriteWarning("after dispose");

            Assert.Equal(new[] { "nested warning", "outer warning" }, outer.Assessments.Select(static a => a.Message));
            Assert.Equal(new[] { "nested warning" }, inner.Assessments.Select(static a => a.Message));
        }
    }
}

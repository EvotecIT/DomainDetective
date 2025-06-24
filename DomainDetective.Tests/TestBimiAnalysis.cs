using DnsClientX;

namespace DomainDetective.Tests {
    public class TestBimiAnalysis {
        [Fact]
        public async Task ParseBimiRecord() {
            var record = "v=BIMI1; l=https://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg";
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = record,
                    Type = DnsRecordType.TXT
                }
            };
            var analysis = new BimiAnalysis();
            await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

            Assert.True(analysis.BimiRecordExists);
            Assert.True(analysis.StartsCorrectly);
            Assert.Equal("https://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg", analysis.Location);
            Assert.True(analysis.LocationUsesHttps);
            Assert.True(analysis.SvgFetched);
            Assert.True(analysis.SvgValid);
        }

        [Fact]
        public async Task ParseBimiRecordHttp() {
            var record = "v=BIMI1; l=http://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg";
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = record,
                    Type = DnsRecordType.TXT
                }
            };
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var analysis = new BimiAnalysis();
            await analysis.AnalyzeBimiRecords(answers, logger);

            Assert.True(analysis.BimiRecordExists);
            Assert.True(analysis.StartsCorrectly);
            Assert.Equal("http://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg", analysis.Location);
            Assert.False(analysis.LocationUsesHttps);
            Assert.True(analysis.SvgFetched);
            Assert.True(analysis.SvgValid);
            Assert.Contains(warnings, w => w.FullMessage.Contains("does not use HTTPS"));
        }
    }
}
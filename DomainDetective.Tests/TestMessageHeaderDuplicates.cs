using System.IO;

namespace DomainDetective.Tests {
    public class TestMessageHeaderDuplicates {
        [Fact]
        public void ParseHeadersWithDuplicates() {
            var raw = File.ReadAllText("Data/sample-headers-duplicate.txt");
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(raw, new InternalLogger());

            Assert.Equal("Second Subject", analysis.Headers["Subject"]);
            Assert.True(analysis.DuplicateHeaders.TryGetValue("Subject", out var list));
            Assert.Equal(2, list.Count);
            Assert.Contains("First Subject", list);
            Assert.Contains("Second Subject", list);
        }
    }
}

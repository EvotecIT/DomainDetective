using System.IO;

namespace DomainDetective.Tests {
    public class TestMessageHeaderDkimInvalid {
        [Fact]
        public void RejectsInvalidDkimSignature() {
            var raw = File.ReadAllText("Data/dkim-bad-padding.txt");
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(raw, new InternalLogger());

            Assert.False(analysis.Headers.ContainsKey("DKIM-Signature"));
            Assert.Single(analysis.InvalidDkimSignatures);
        }
    }
}


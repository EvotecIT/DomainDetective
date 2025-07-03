using System.IO;

namespace DomainDetective.Tests {
    public class TestMessageHeaderDkimValidator {
        [Fact]
        public void ParseDkimValidatorHeaders() {
            var raw = File.ReadAllText("Data/dkimvalidator-headers.txt");
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(raw, new InternalLogger());

            Assert.Equal("someuser@dkimvalidator.com", analysis.Headers["Delivered-To"]);
            Assert.Single(analysis.ReceivedChain);
            Assert.Contains("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1; t=1615567890; h=from:to:subject:date:message-id:mime-version:content-type; bh=abc123; b=def456", analysis.Headers["DKIM-Signature"]);
            Assert.Contains("dkim=pass", analysis.Headers["Authentication-Results"]);
        }
    }
}

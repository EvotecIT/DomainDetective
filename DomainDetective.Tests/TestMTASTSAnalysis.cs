using DomainDetective;
using Xunit;

namespace DomainDetective.Tests {
    public class TestMTASTSAnalysis {
        [Fact]
        public void ParseValidPolicy() {
            var policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.True(analysis.PolicyValid);
            Assert.True(analysis.ValidVersion);
            Assert.True(analysis.ValidMode);
            Assert.True(analysis.ValidMaxAge);
            Assert.True(analysis.HasMx);
            Assert.Equal("enforce", analysis.Mode);
            Assert.Equal(86400, analysis.MaxAge);
            Assert.Single(analysis.Mx);
            Assert.Equal("mail.example.com", analysis.Mx[0]);
        }

        [Fact]
        public void MissingFieldsInvalidatePolicy() {
            var policy = "version: STSv1\nmode: enforce";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.False(analysis.PolicyValid);
            Assert.False(analysis.HasMx);
            Assert.False(analysis.ValidMaxAge);
        }
    }
}

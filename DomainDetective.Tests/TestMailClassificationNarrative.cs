using System.Collections.Generic;
using DomainDetective;
using DomainDetective.Definitions;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestMailClassificationNarrative
    {
        [Fact]
        public void BuildsNarrativeWithPositives()
        {
            var result = new MailDomainClassificationResult
            {
                Domain = "example.com",
                Classification = MailDomainClassificationCategory.SendingAndReceiving,
                Confidence = MailDomainClassificationConfidence.High,
                ReceivingSignals = new List<string> { "MX" },
                SendingSignals = new List<string> { "SPF" },
                Assessments = new List<Assessment>
                {
                    new Assessment { Code = MailClassificationCodes.SendingAndReceiving, Severity = AssessmentSeverity.Info, Message = "Domain supports sending and receiving mail" }
                }
            };
            var sections = MailClassificationNarrative.Build(result);
            Assert.Contains(sections.Highlights, h => h.Contains("Classification"));
            Assert.Contains("Domain supports sending and receiving mail", sections.Positives);
        }
    }
}

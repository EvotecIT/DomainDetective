using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static partial class Program
    {
        /// <summary>
        /// Demonstrates building a narrative from mail domain classification.
        /// </summary>
        public static async Task ExampleMailClassificationNarrative()
        {
            var health = new DomainHealthCheck();
            var classifier = new MailDomainClassifier(health, new InternalLogger());
            var result = await classifier.ClassifyAsync("gmail.com");
            var sections = MailClassificationNarrative.Build(result);
            Helpers.ShowPropertiesTable("Mail Classification Narrative", sections);
        }
    }
}

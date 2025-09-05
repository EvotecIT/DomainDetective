using System.Threading.Tasks;

namespace DomainDetective.Example {
    public static partial class Program {
        /// <summary>
        /// Demonstrates running HPKP analysis for a given URL.
        /// </summary>
        public static async Task ExampleAnalyseHPKP() {
            var analysis = new HPKPAnalysis();
            await analysis.AnalyzeUrl("https://www.google.com", new InternalLogger());
            Helpers.ShowPropertiesTable("HPKP Analysis for google.com", analysis);
        }
    }
}

using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Demonstrates how to analyze an SMTP server for open relay configuration.
    /// </summary>
    public static async Task ExampleAnalyseOpenRelay() {
        var analysis = new OpenRelayAnalysis();
        await analysis.AnalyzeServer("smtp.gmail.com", 25, new InternalLogger());
        if (analysis.ServerResults.TryGetValue("smtp.gmail.com:25", out var result)) {
            Console.WriteLine($"Relay status: {result.Status}, SocketError: {result.SocketErrorCode}");
        }
    }
}
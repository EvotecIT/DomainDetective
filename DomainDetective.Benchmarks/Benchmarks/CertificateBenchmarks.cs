using BenchmarkDotNet.Attributes;

namespace DomainDetective.Benchmarks;

[MemoryDiagnoser]
/// <summary>
/// Benchmarks sequential versus parallel certificate checks.
/// </summary>
public class CertificateBenchmarks
{
    private readonly string[] _urls =
    [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.github.com",
        "https://www.stackoverflow.com"
    ];

    /// <summary>Checks certificates sequentially.</summary>
    [Benchmark(Baseline = true)]
    public async Task Sequential()
    {
        foreach (var url in _urls)
        {
            await CertificateAnalysis.CheckWebsiteCertificate(url);
        }
    }

    /// <summary>Checks certificates concurrently.</summary>
    [Benchmark]
    public async Task Concurrent()
    {
        await CertificateAnalysis.CheckWebsiteCertificates(_urls);
    }
}

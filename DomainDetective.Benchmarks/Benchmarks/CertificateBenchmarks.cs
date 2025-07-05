using BenchmarkDotNet.Attributes;

namespace DomainDetective.Benchmarks;

[MemoryDiagnoser]
public class CertificateBenchmarks
{
    private readonly string[] _urls =
    [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.github.com",
        "https://www.stackoverflow.com"
    ];

    [Benchmark(Baseline = true)]
    public async Task Sequential()
    {
        foreach (var url in _urls)
        {
            await CertificateAnalysis.CheckWebsiteCertificate(url);
        }
    }

    [Benchmark]
    public async Task Concurrent()
    {
        await CertificateAnalysis.CheckWebsiteCertificates(_urls);
    }
}

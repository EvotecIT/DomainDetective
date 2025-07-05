using BenchmarkDotNet.Running;

namespace DomainDetective.Benchmarks;

public static class Program
{
    public static void Main(string[] args)
    {
        BenchmarkRunner.Run<CertificateBenchmarks>();
    }
}

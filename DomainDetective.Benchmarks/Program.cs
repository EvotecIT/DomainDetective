using BenchmarkDotNet.Running;

namespace DomainDetective.Benchmarks;

/// <summary>
/// Entry point for running benchmark scenarios.
/// </summary>
public static class Program
{
    /// <summary>Runs the benchmark suite.</summary>
    /// <param name="args">Command line arguments.</param>
    public static void Main(string[] args)
    {
        BenchmarkRunner.Run<CertificateBenchmarks>();
    }
}

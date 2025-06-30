using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

internal static class Program {
    [RequiresDynamicCode("Calls Spectre.Console.Cli.CommandApp.CommandApp(ITypeRegistrar)")]
    public static Task<int> Main(string[] args) {
        var app = new CommandApp();
        app.Configure(config => {
            config.SetApplicationName("DomainDetective");
            config.AddCommand<CheckDomainCommand>("check")
                .WithDescription("Run domain health checks");
            config.AddCommand<AnalyzeMessageHeaderCommand>("AnalyzeMessageHeader")
                .WithDescription("Analyze message header");
            config.AddCommand<AnalyzeArcCommand>("AnalyzeARC")
                .WithDescription("Analyze ARC headers");
            config.AddCommand<WhoisCommand>("Whois")
                .WithDescription("Query WHOIS information");
            config.AddCommand<AnalyzeDnsTunnelingCommand>("AnalyzeDnsTunneling")
                .WithDescription("Analyze DNS logs for tunneling patterns");
            config.AddCommand<DnsPropagationCommand>("DnsPropagation")
                .WithDescription("Check DNS propagation across public resolvers");
            config.AddCommand<BuildDmarcCommand>("BuildDmarcRecord")
                .WithDescription("Interactively build a DMARC record");
            config.AddCommand<TestSmimeaCommand>("TestSMIMEA")
                .WithDescription("Query SMIMEA record for an email address");
        });
        return app.RunAsync(args);
    }
}

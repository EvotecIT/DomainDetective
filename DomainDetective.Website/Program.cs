using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using DomainDetective.Toolbox.Services;
using DomainDetective.Website;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// Each tool route is a complete static page; the tools mount into its #dd-tool-root region only.
builder.RootComponents.Add<App>("#dd-tool-root");

builder.Services.AddScoped(sp => new HttpClient {
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
    Timeout = TimeSpan.FromMinutes(5)
});
builder.Services.AddSingleton<ToolRegistry>();
builder.Services.AddScoped<ToolAvailabilityService>();
builder.Services.AddScoped<BrowserDnsService>();
builder.Services.AddScoped<BrowserOverviewService>();
builder.Services.AddScoped<HostedAnalysisService>();

await builder.Build().RunAsync();

using System.Net;
using DomainDetective.Toolbox.Models;
using DomainDetective.Toolbox.Services;
using Microsoft.Extensions.Configuration;

namespace DomainDetective.Website.Tests;

public sealed class ToolAvailabilityServiceTests {
    [Fact]
    public async Task InitializeAsyncDetectsHostedOnlineWhenHealthEndpointSucceeds() {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Tools:Mode"] = "Auto"
            })
            .Build();
        using var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK))) {
            BaseAddress = new Uri("http://localhost")
        };
        var service = new ToolAvailabilityService(configuration, httpClient);

        await service.InitializeAsync();

        Assert.Equal(ToolsDeploymentMode.HostedOnline, service.Mode);
    }

    [Fact]
    public async Task InitializeAsyncFallsBackToStaticOnlyWhenHealthEndpointFails() {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Tools:Mode"] = "Auto"
            })
            .Build();
        using var httpClient = new HttpClient(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound))) {
            BaseAddress = new Uri("http://localhost")
        };
        var service = new ToolAvailabilityService(configuration, httpClient);

        await service.InitializeAsync();

        Assert.Equal(ToolsDeploymentMode.StaticOnly, service.Mode);
    }

    [Fact]
    public async Task InitializeAsyncFallsBackToHealthProbeWhenRuntimeManifestHasNoMode() {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Tools:Mode"] = "Auto"
            })
            .Build();
        using var httpClient = new HttpClient(new StubHttpMessageHandler(request => {
            if (request.RequestUri?.AbsolutePath.Equals("/data/tools-runtime.json", StringComparison.OrdinalIgnoreCase) == true) {
                return new HttpResponseMessage(HttpStatusCode.OK) {
                    Content = new StringContent("{}")
                };
            }

            if (request.RequestUri?.AbsolutePath.Equals("/tool-api/health", StringComparison.OrdinalIgnoreCase) == true) {
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        })) {
            BaseAddress = new Uri("http://localhost")
        };
        var service = new ToolAvailabilityService(configuration, httpClient);

        await service.InitializeAsync();

        Assert.Equal(ToolsDeploymentMode.HostedOnline, service.Mode);
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responseFactory;

        public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) {
            _responseFactory = responseFactory;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            return Task.FromResult(_responseFactory(request));
        }
    }
}

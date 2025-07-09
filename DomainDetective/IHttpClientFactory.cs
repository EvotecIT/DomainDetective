namespace DomainDetective;

using System.Net.Http;

/// <summary>
/// Provides a method for obtaining <see cref="HttpClient"/> instances.
/// </summary>
public interface IHttpClientFactory
{
    /// <summary>Creates or retrieves an <see cref="HttpClient"/>.</summary>
    HttpClient CreateClient();
}

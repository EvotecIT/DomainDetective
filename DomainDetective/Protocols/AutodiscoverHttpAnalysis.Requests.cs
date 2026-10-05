using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class AutodiscoverHttpAnalysis {
    private async Task<AutodiscoverEndpointResult> CheckEndpointAsync(string url, AutodiscoverMethod method, bool tryPost,
        bool json, string domain, InternalLogger logger, CancellationToken budget, CancellationToken caller) {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(budget);
        deadline.CancelAfter(Timeout);
        using var client = CreateClient();
        using var target = AssessmentCollector.ForAnalysis(logger, this, category: "AUTODISC", target: url);
        var watch = Stopwatch.StartNew();
        var redirects = new List<string>();
        var requests = new List<AutodiscoverRequestAttempt>();
        int status = 0;
        string? finalUrl = null, contentType = null, snippet = null, error = null, jsonEndpoint = null;
        bool html = false;
        (bool Valid, string? Namespace, bool NamespaceValid, bool Recognized, string? Kind) xml = default;
        try {
            if (!TryHttpUrl(url, out var current)) throw new InvalidOperationException("Autodiscover endpoint must be an absolute HTTP(S) URL without user information.");
            while (true) {
                deadline.Token.ThrowIfCancellationRequested();
                redirects.Add(current!.AbsoluteUri); finalUrl = current.AbsoluteUri;
                var received = await ReadRequestAsync(client, current, HttpMethod.Get, null, json, requests, deadline.Token, caller).ConfigureAwait(false);
                status = received.Status; contentType = received.ContentType;
                if (received.Location != null && status >= 300 && status < 400) {
                    if (redirects.Count > MaxRedirects) throw new InvalidOperationException($"Maximum number of redirects ({MaxRedirects}) exceeded.");
                    var next = received.Location.IsAbsoluteUri ? received.Location : new Uri(current, received.Location);
                    if (!TryHttpUrl(next.AbsoluteUri, out _) || current.Scheme == Uri.UriSchemeHttps && next.Scheme != Uri.UriSchemeHttps)
                        throw new InvalidOperationException("Autodiscover redirect used an unsupported URL or downgraded HTTPS.");
                    current = next; continue;
                }
                snippet = Snippet(received.Body);
                html = received.Body.TrimStart().StartsWith("<html", StringComparison.OrdinalIgnoreCase)
                    || contentType?.IndexOf("html", StringComparison.OrdinalIgnoreCase) >= 0;
                if (status >= 200 && status < 300) {
                    if (json) jsonEndpoint = ParseJsonEndpoint(received.Body);
                    else xml = ParseXml(received.Body);
                }
                if (!json && !xml.Recognized && tryPost && current.Scheme == Uri.UriSchemeHttps) {
                    string email = string.IsNullOrWhiteSpace(EmailForPost) ? $"autodiscover@{domain}" : EmailForPost!;
                    received = await ReadRequestAsync(client, current, HttpMethod.Post, BuildAutodiscoverRequestXml(email), false,
                        requests, deadline.Token, caller).ConfigureAwait(false);
                    status = received.Status; contentType = received.ContentType; snippet = Snippet(received.Body);
                    html = received.Body.TrimStart().StartsWith("<html", StringComparison.OrdinalIgnoreCase);
                    xml = status >= 200 && status < 300 ? ParseXml(received.Body) : default;
                }
                break;
            }
        } catch (Exception ex) when (caller.IsCancellationRequested && !ExceptionHelper.IsFatal(ex)) {
            throw new OperationCanceledException(caller);
        } catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or InvalidOperationException or IOException) {
            error = budget.IsCancellationRequested ? "Overall Autodiscover deadline exhausted."
                : deadline.IsCancellationRequested ? "Endpoint request deadline exhausted." : ex.Message;
            logger.WriteErrorCode(AutodiscoverCodes.CheckFailed, "Autodiscover HTTP check failed for {0}: {1}", url, error);
        }
        caller.ThrowIfCancellationRequested();
        var result = new AutodiscoverEndpointResult {
            Method = method, Url = url, StatusCode = status, RedirectChain = redirects, FinalUrl = finalUrl,
            FinalHost = Uri.TryCreate(finalUrl, UriKind.Absolute, out var final) ? final.Host : null,
            ContentType = contentType, ContentSnippet = snippet, ContentLooksHtml = html,
            XmlValid = xml.Valid, XmlNamespace = xml.Namespace, XmlNamespaceValid = xml.NamespaceValid,
            ServiceResponseRecognized = xml.Recognized, ServiceResponseType = xml.Kind,
            JsonValid = jsonEndpoint != null, JsonEndpointUrl = jsonEndpoint,
            Error = error, BudgetExhausted = budget.IsCancellationRequested, ElapsedMilliseconds = watch.ElapsedMilliseconds, Requests = requests
        };
        if (result.DiscoverySucceeded) {
            logger.WriteInformationCode(AutodiscoverCodes.XmlValid, "Autodiscover endpoint returned a recognized {0} response.", result.ServiceResponseType);
            logger.WriteInformationCode(AutodiscoverCodes.EndpointDiscovered, "Autodiscover service discovered at {0}.", result.FinalHost ?? url);
        } else if (result.JsonValid) logger.WriteInformationCode(AutodiscoverCodes.JsonValid, "Autodiscover JSON returned candidate endpoint {0}; HTTP/XML confirmation follows.", jsonEndpoint!);
        return result;
    }

    private async Task<(int Status, string? ContentType, Uri? Location, string Body)> ReadRequestAsync(HttpClient client,
        Uri url, HttpMethod method, string? body, bool json, List<AutodiscoverRequestAttempt> attempts, CancellationToken token, CancellationToken caller) {
        var watch = Stopwatch.StartNew();
        int? status = null;
        string phase = "request";
        try {
            using var request = new HttpRequestMessage(method, url);
            if (body != null) request.Content = new StringContent(body, Encoding.UTF8, "text/xml");
            if (json) request.Headers.Accept.ParseAdd("application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            status = (int)response.StatusCode; phase = "body";
            string text = string.Empty;
            if (status < 300 || status >= 400) text = await ReadBodyAsync(response.Content, token).ConfigureAwait(false);
            caller.ThrowIfCancellationRequested();
            attempts.Add(new AutodiscoverRequestAttempt { Url = url.AbsoluteUri, Method = method.Method, StatusCode = status, ElapsedMilliseconds = watch.ElapsedMilliseconds });
            return (status.Value, response.Content?.Headers.ContentType?.MediaType, response.Headers.Location, text);
        } catch (Exception ex) when (!ExceptionHelper.IsFatal(ex)) {
            if (!caller.IsCancellationRequested) attempts.Add(new AutodiscoverRequestAttempt {
                Url = url.AbsoluteUri, Method = method.Method, StatusCode = status, ElapsedMilliseconds = watch.ElapsedMilliseconds,
                FailureStage = phase, Error = ex.Message
            });
            throw;
        }
    }

    private async Task<string> ReadBodyAsync(HttpContent? content, CancellationToken token) {
        if (content == null) return string.Empty;
        if (content.Headers.ContentLength > MaxResponseBodyBytes) throw new HttpRequestException("Autodiscover response body exceeds its byte limit.");
        using var stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
        using var output = new MemoryStream();
        byte[] buffer = new byte[8192];
        while (true) {
            // Framework HTTP streams may only check the token before starting a read.
            // Stop waiting at the deadline; disposing the owned response stream aborts its active read.
            Task<int> reading = stream.ReadAsync(buffer, 0, (int)Math.Min(buffer.Length, MaxResponseBodyBytes - output.Length + 1L), token);
            int read;
            try { read = await reading.WaitWithCancellation(token).ConfigureAwait(false); }
            catch (OperationCanceledException) {
                _ = reading.ContinueWith(completed => { _ = completed.Exception; }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                throw;
            }
            if (read == 0) break;
            if (output.Length + read > MaxResponseBodyBytes) throw new HttpRequestException("Autodiscover response body exceeds its byte limit.");
            output.Write(buffer, 0, read);
        }
        Encoding encoding = Encoding.UTF8;
        try { if (!string.IsNullOrEmpty(content.Headers.ContentType?.CharSet)) encoding = Encoding.GetEncoding(content.Headers.ContentType!.CharSet!.Trim('"')); }
        catch (ArgumentException) { }
        output.Position = 0;
        using var reader = new StreamReader(output, encoding, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }
    private static string? Snippet(string body) => body.Length == 0 ? null : body.Length > 512 ? body.Substring(0, 512) : body;
}

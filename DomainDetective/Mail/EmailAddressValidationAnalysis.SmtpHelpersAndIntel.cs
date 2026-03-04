using DnsClientX;
using DomainDetective.Helpers;
using DomainDetective.Providers.Email;
using MimeKit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;


public sealed partial class EmailAddressValidationAnalysis {
    private static StreamReader CreateSmtpReader(Stream stream) {
        return new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
    }

    private static StreamWriter CreateSmtpWriter(Stream stream) {
        return new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };
    }

    private static async Task<(string? MailResp, string? RcptResp)> SendMailRcptAsync(StreamWriter writer, StreamReader reader, string fromAddress, string emailAddress, CancellationToken token) {
        await writer.WriteLineAsync($"MAIL FROM:<{fromAddress}>").WaitWithCancellation(token);
        var mailResp = await ReadResponseAsync(reader, token);
        await writer.WriteLineAsync($"RCPT TO:<{emailAddress}>").WaitWithCancellation(token);
        var rcptResp = await ReadResponseAsync(reader, token);
        return (mailResp, rcptResp);
    }

    private static async Task<HashSet<string>> SendEhloAsync(StreamWriter writer, StreamReader reader, string helloName, CancellationToken token) {
        await writer.WriteLineAsync($"EHLO {helloName}").WaitWithCancellation(token);
        var lines = await ReadResponseLinesAsync(reader, token);
        var success = IsPositiveResponse(lines.LastOrDefault());
        if (!success) {
            await writer.WriteLineAsync($"HELO {helloName}").WaitWithCancellation(token);
            await ReadResponseAsync(reader, token);
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
        var capabilities = ParseEhloCapabilities(lines);
        return capabilities;
    }

    private static HashSet<string> ParseEhloCapabilities(IEnumerable<string> lines) {
        var caps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines) {
            if (!line.StartsWith("250", StringComparison.Ordinal)) {
                continue;
            }
            var payload = line.Length > 4 ? line.Substring(4).Trim() : string.Empty;
            if (string.IsNullOrWhiteSpace(payload)) {
                continue;
            }
            var token = payload.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(token)) {
                caps.Add(token);
            }
        }
        return caps;
    }

    private static int ParseStatusCode(string? response) {
        if (string.IsNullOrWhiteSpace(response)) {
            return -1;
        }
        var value = response ?? string.Empty;
        if (value.Length < SmtpStatusCodeLength) {
            return -1;
        }
        if (int.TryParse(value.Substring(0, SmtpStatusCodeLength), out var code)) {
            return code;
        }
        return -1;
    }

    private static bool IsPositiveResponse(string? response) {
        var code = ParseStatusCode(response);
        return code >= 200 && code < 300;
    }

    private static async Task<string?> ReadResponseAsync(StreamReader reader, CancellationToken token) {
        string? line = await reader.ReadLineAsync().WaitWithCancellation(token);
        if (line == null) {
            return null;
        }
        var code = line.Length >= SmtpStatusCodeLength ? line.Substring(0, SmtpStatusCodeLength) : string.Empty;
        var lastLine = line;
        int linesRead = 1;
        while (line.Length >= SmtpStatusCodeLength + 1 && line[SmtpStatusCodeLength] == '-') {
            if (linesRead >= MaxSmtpResponseLines) {
                break;
            }
            line = await reader.ReadLineAsync().WaitWithCancellation(token);
            if (line == null) {
                break;
            }
            if (line.StartsWith(code, StringComparison.Ordinal)) {
                lastLine = line;
            } else {
                break;
            }
            linesRead++;
        }
        return lastLine;
    }

    private static async Task<List<string>> ReadResponseLinesAsync(StreamReader reader, CancellationToken token) {
        var lines = new List<string>();
        string? line = await reader.ReadLineAsync().WaitWithCancellation(token);
        if (line == null) {
            return lines;
        }
        lines.Add(line);
        var code = line.Length >= SmtpStatusCodeLength ? line.Substring(0, SmtpStatusCodeLength) : string.Empty;
        int linesRead = 1;
        while (line.Length >= SmtpStatusCodeLength + 1 && line[SmtpStatusCodeLength] == '-') {
            if (linesRead >= MaxSmtpResponseLines) {
                break;
            }
            line = await reader.ReadLineAsync().WaitWithCancellation(token);
            if (line == null) {
                break;
            }
            lines.Add(line);
            if (line.StartsWith(code, StringComparison.Ordinal) && line.Length >= SmtpStatusCodeLength + 1 && line[SmtpStatusCodeLength] != '-') {
                break;
            }
            linesRead++;
        }
        return lines;
    }

    /// <summary>Establishes a SOCKS5 CONNECT tunnel to the target host and port.</summary>
    /// <para>Supports anonymous and username/password authentication.</para>
    private static async Task EstablishSocks5TunnelAsync(Stream stream, string host, int port, EmailSmtpProxyOptions proxy, CancellationToken token) {
        var methods = new List<byte> { 0x00 };
        var useAuth = !string.IsNullOrWhiteSpace(proxy.Username) || !string.IsNullOrWhiteSpace(proxy.Password);
        if (useAuth) {
            methods.Add(0x02);
        }

        var greeting = new byte[2 + methods.Count];
        greeting[0] = 0x05;
        greeting[1] = (byte)methods.Count;
        for (int i = 0; i < methods.Count; i++) {
            greeting[2 + i] = methods[i];
        }

        await stream.WriteAsync(greeting, 0, greeting.Length, token);
        var response = await ReadExactAsync(stream, 2, token);
        if (response[0] != 0x05) {
            throw new IOException("SOCKS5 proxy returned an invalid version.");
        }
        if (response[1] == 0xFF) {
            throw new IOException("SOCKS5 proxy rejected authentication methods.");
        }

        if (response[1] == 0x02) {
            var username = proxy.Username ?? string.Empty;
            var password = proxy.Password ?? string.Empty;
            byte[]? userBytes = null;
            byte[]? passBytes = null;
            byte[]? auth = null;
            try {
                userBytes = Encoding.ASCII.GetBytes(username);
                passBytes = Encoding.ASCII.GetBytes(password);
                if (userBytes.Length > 255 || passBytes.Length > 255) {
                    throw new IOException("SOCKS5 proxy credentials are too long.");
                }

                auth = new byte[3 + userBytes.Length + passBytes.Length];
                auth[0] = 0x01;
                auth[1] = (byte)userBytes.Length;
                Buffer.BlockCopy(userBytes, 0, auth, 2, userBytes.Length);
                auth[2 + userBytes.Length] = (byte)passBytes.Length;
                Buffer.BlockCopy(passBytes, 0, auth, 3 + userBytes.Length, passBytes.Length);

                await stream.WriteAsync(auth, 0, auth.Length, token);
                var authResp = await ReadExactAsync(stream, 2, token);
                if (authResp[1] != 0x00) {
                    throw new IOException("SOCKS5 proxy authentication failed.");
                }
            } finally {
                if (auth != null) {
                    Array.Clear(auth, 0, auth.Length);
                }
                if (userBytes != null) {
                    Array.Clear(userBytes, 0, userBytes.Length);
                }
                if (passBytes != null) {
                    Array.Clear(passBytes, 0, passBytes.Length);
                }
            }
        }

        byte atyp;
        byte[] addrBytes;
        if (IPAddress.TryParse(host, out var ip)) {
            if (ip.AddressFamily == AddressFamily.InterNetwork) {
                atyp = 0x01;
                addrBytes = ip.GetAddressBytes();
            } else if (ip.AddressFamily == AddressFamily.InterNetworkV6) {
                atyp = 0x04;
                addrBytes = ip.GetAddressBytes();
            } else {
                throw new IOException("Unsupported IP address family for SOCKS5.");
            }
        } else {
            var hostBytes = Encoding.ASCII.GetBytes(host);
            if (hostBytes.Length == 0 || hostBytes.Length > 255) {
                throw new IOException("SOCKS5 proxy host name is invalid.");
            }
            atyp = 0x03;
            addrBytes = new byte[hostBytes.Length + 1];
            addrBytes[0] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, addrBytes, 1, hostBytes.Length);
        }

        var portBytes = new byte[2];
        portBytes[0] = (byte)(port >> 8);
        portBytes[1] = (byte)(port & 0xFF);

        var request = new byte[4 + addrBytes.Length + portBytes.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = atyp;
        Buffer.BlockCopy(addrBytes, 0, request, 4, addrBytes.Length);
        Buffer.BlockCopy(portBytes, 0, request, 4 + addrBytes.Length, portBytes.Length);

        await stream.WriteAsync(request, 0, request.Length, token);

        var header = await ReadExactAsync(stream, 4, token);
        if (header[0] != 0x05) {
            throw new IOException("SOCKS5 proxy returned an invalid connect response.");
        }
        if (header[1] != 0x00) {
            throw new IOException($"SOCKS5 proxy connection failed with code {header[1]}.");
        }

        int addrLen = header[3] switch {
            0x01 => 4,
            0x04 => 16,
            0x03 => (await ReadExactAsync(stream, 1, token))[0],
            _ => throw new IOException("SOCKS5 proxy returned an unknown address type.")
        };
        if (addrLen > 0) {
            await ReadExactAsync(stream, addrLen, token);
        }
        await ReadExactAsync(stream, 2, token);
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken token) {
        var buffer = new byte[count];
        int read = 0;
        while (read < count) {
            var bytesRead = await stream.ReadAsync(buffer, read, count - read, token);
            if (bytesRead == 0) {
                throw new IOException("Unexpected end of stream.");
            }
            read += bytesRead;
        }
        return buffer;
    }

    private static bool ContainsNonAscii(string value) {
        return value.Any(static ch => ch > 127);
    }

    private static string NormalizeRoleLocalPart(string localPart) {
        var normalized = localPart.Trim().Trim('.').ToLowerInvariant();
        var plus = normalized.IndexOf('+');
        if (plus > 0) {
            normalized = normalized.Substring(0, plus);
        }
        return normalized;
    }

    private static List<(int Priority, string Host, bool IsNull)> ParseMxRecords(IEnumerable<DnsAnswer> records) {
        var parsed = new List<(int, string, bool)>();
        foreach (var data in (records ?? Array.Empty<DnsAnswer>()).Select(static record => record.Data ?? record.DataRaw)) {
            if (string.IsNullOrWhiteSpace(data)) {
                continue;
            }
            var parts = data.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) {
                continue;
            }
            int priority = 0;
            bool hasPriority = false;
            string hostRaw;
            if (parts.Length == 1) {
                hostRaw = parts[0].Trim();
            } else {
                hasPriority = int.TryParse(parts[0], out priority);
                hostRaw = parts[1].Trim();
            }
            bool isNull = hostRaw == "." && (parts.Length == 1 || (hasPriority && priority == 0));
            string host = isNull ? string.Empty : hostRaw.Trim('.');
            if (string.IsNullOrWhiteSpace(host) && !isNull) {
                continue;
            }
            parsed.Add((priority, host, isNull));
        }
        return parsed;
    }

    private async Task<string?> TryResolveGravatarAsync(string? normalizedEmail, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(normalizedEmail)) {
            return null;
        }

        var normalizedValue = normalizedEmail ?? string.Empty;
        var normalized = normalizedValue.Trim().ToLowerInvariant();
        var hash = ComputeMd5(normalized);
        var url = $"https://www.gravatar.com/avatar/{hash}?d=404";

        try {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.HttpTimeout);
            var client = (HttpClientFactory ?? new SharedHttpClient()).CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Head, url);
            request.Headers.UserAgent.ParseAdd("DomainDetective");
            using var response = await client.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
            if (response.IsSuccessStatusCode) {
                return url;
            }
            if ((int)response.StatusCode == 405) {
                using var getRequest = new HttpRequestMessage(HttpMethod.Get, url);
                getRequest.Headers.UserAgent.ParseAdd("DomainDetective");
                using var getResponse = await client.SendAsync(getRequest, timeoutCts.Token).ConfigureAwait(false);
                if (getResponse.IsSuccessStatusCode) {
                    return url;
                }
            }
            return null;
        } catch (Exception ex) {
            logger.WriteVerbose("Gravatar check failed: {0}", ex.Message);
            return null;
        }
    }

    private async Task<bool?> TryCheckHaveIBeenPwnedAsync(string? normalizedEmail, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(normalizedEmail) || string.IsNullOrWhiteSpace(options.HaveIBeenPwnedApiKey)) {
            return null;
        }

        var baseUrl = options.HaveIBeenPwnedBaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl)) {
            return null;
        }
        baseUrl = baseUrl.Trim();
        if (!baseUrl.EndsWith("/", StringComparison.Ordinal)) {
            baseUrl += "/";
        }

        var normalizedValue = normalizedEmail ?? string.Empty;
        var encoded = Uri.EscapeDataString(normalizedValue.Trim().ToLowerInvariant());
        var url = $"{baseUrl}breachedaccount/{encoded}?truncateResponse=true";

        try {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.HttpTimeout);
            var client = (HttpClientFactory ?? new SharedHttpClient()).CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd("DomainDetective");
            request.Headers.TryAddWithoutValidation("hibp-api-key", options.HaveIBeenPwnedApiKey!);
            using var response = await client.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
            if (response.IsSuccessStatusCode) {
                return true;
            }
            if ((int)response.StatusCode == 404) {
                return false;
            }
            return null;
        } catch (Exception ex) {
            logger.WriteVerbose("Have I Been Pwned check failed: {0}", ex.Message);
            return null;
        }
    }

    private static string ComputeMd5(string input) {
        using var md5 = MD5.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = md5.ComputeHash(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) {
            sb.Append(b.ToString("x2"));
        }
        return sb.ToString();
    }
}

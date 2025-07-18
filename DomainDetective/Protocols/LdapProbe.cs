using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal static class LdapProbe
{
    private static readonly byte[] BindRequest =
    {
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00
    };

    internal static async Task<bool> ProbeAsync(System.IO.Stream stream, CancellationToken token)
    {
        await stream.WriteAsync(BindRequest, 0, BindRequest.Length, token).ConfigureAwait(false);
        var buffer = new byte[2];
        var read = await stream.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false);
        return read >= 1 && buffer[0] == 0x30;
    }
}

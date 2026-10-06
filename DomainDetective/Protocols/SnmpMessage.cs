using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace DomainDetective;

/// <summary>Encodes and correlates the basic public-community SNMPv1 probe.</summary>
internal static class SnmpMessage {
    private const string ProbeOid = "1.3.6.1.2.1";
    private static readonly byte[] Community = System.Text.Encoding.ASCII.GetBytes("public");

    internal static byte[] CreateRequest(int requestId) {
        var binding = new DerSequence(new DerObjectIdentifier(ProbeOid), DerNull.Instance);
        var pdu = new DerSequence(DerInteger.ValueOf(requestId), DerInteger.ValueOf(0), DerInteger.ValueOf(0),
            new DerSequence(binding));
        return new DerSequence(DerInteger.ValueOf(0), new DerOctetString(Community),
            new DerTaggedObject(false, 0, pdu)).GetDerEncoded();
    }

    internal static bool IsResponse(byte[] bytes, int requestId) {
        try {
            // Validate the fixed message shape before decoding primitives. Untrusted nested
            // constructed values never reach a recursive ASN.1 decoder.
            var input = new Frame(bytes, 0, bytes.Length);
            if (!input.Read(0x30, out var message) || !input.Empty ||
                !message.Integer(out int version) || version != 0 ||
                !message.Read(0x04, out var community) || !community.Bytes().SequenceEqual(Community) ||
                !message.Read(0xa2, out var pdu) || !message.Empty ||
                !pdu.Integer(out int id) || id != requestId ||
                !pdu.Integer(out int error) || error < 0 || error > 5 ||
                !pdu.Integer(out int index) || index < 0 || index > 1 ||
                ((error == 0 || error == 1) && index != 0) ||
                !pdu.Read(0x30, out var bindings) || !pdu.Empty ||
                !bindings.Read(0x30, out var binding) || !bindings.Empty ||
                !binding.Read(0x06, out var oid) ||
                DerObjectIdentifier.GetInstance(oid.Decode(0x06)).Id != ProbeOid ||
                !binding.ReadAny(out byte tag, out var value) || !binding.Empty) {
                return false;
            }
            return ValidValue(tag, value);
        } catch (Exception ex) when (ex is IOException || ex is ArgumentException ||
            ex is InvalidCastException || ex is ArithmeticException) {
            return false;
        }
    }

    private static bool ValidValue(byte tag, Frame value) {
        // SNMPv1 ObjectSyntax uses primitive scalar values, including application tags.
        switch (tag) {
            case 0x02:
                return value.Decode(tag) is DerInteger integer && integer.Value.BitLength <= 31;
            case 0x04:
                return value.Decode(tag) is Asn1OctetString;
            case 0x05:
                return value.Decode(tag) is DerNull;
            case 0x06:
                return value.Decode(tag) is DerObjectIdentifier;
            case 0x40: // IpAddress
                return value.Length == 4;
            case 0x41: // Counter
            case 0x42: // Gauge
            case 0x43: // TimeTicks
                var number = DerInteger.GetInstance(value.Decode(0x02)).Value;
                return number.SignValue >= 0 && number.BitLength <= 32;
            case 0x44: // Opaque
                return true;
            default:
                return false;
        }
    }

    /// <summary>Bounds definite-length BER frames; primitive validation remains in BouncyCastle.</summary>
    private struct Frame {
        private readonly byte[] _bytes;
        private int _start;
        private readonly int _end;
        internal Frame(byte[] bytes, int start, int end) { _bytes = bytes; _start = start; _end = end; }
        internal bool Empty => _start == _end;
        internal int Length => _end - _start;

        internal bool Read(byte expected, out Frame content) {
            return ReadAny(out byte tag, out content) && tag == expected;
        }

        internal bool ReadAny(out byte tag, out Frame content) {
            tag = 0;
            content = default;
            if (Length < 2) return false;
            tag = _bytes[_start++];
            int length = _bytes[_start++];
            if ((length & 0x80) != 0) {
                int octets = length & 0x7f;
                if (octets == 0 || octets > 4 || octets > Length) return false;
                long decoded = 0;
                for (int i = 0; i < octets; i++) decoded = (decoded << 8) | _bytes[_start++];
                if (decoded > int.MaxValue) return false;
                length = (int)decoded;
            }
            if (length > Length) return false;
            content = new Frame(_bytes, _start, _start + length);
            _start += length;
            return true;
        }

        internal bool Integer(out int number) {
            number = 0;
            if (!Read(0x02, out var content) || content.Length == 0 || content.Length > 4) return false;
            number = DerInteger.GetInstance(content.Decode(0x02)).IntValueExact;
            return true;
        }

        internal byte[] Bytes() {
            var content = new byte[Length];
            Array.Copy(_bytes, _start, content, 0, content.Length);
            return content;
        }

        internal Asn1Object Decode(byte tag) {
            // Reframe a primitive with its original contents and a bounded definite length.
            using var output = new MemoryStream();
            output.WriteByte(tag);
            if (Length < 128) {
                output.WriteByte((byte)Length);
            } else {
                output.WriteByte(0x84);
                for (int shift = 24; shift >= 0; shift -= 8) output.WriteByte((byte)(Length >> shift));
            }
            output.Write(_bytes, _start, Length);
            return Asn1Object.FromByteArray(output.ToArray());
        }
    }
}

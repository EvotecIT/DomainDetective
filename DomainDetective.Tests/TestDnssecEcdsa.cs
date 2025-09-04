using System;
using System.Reflection;
using System.Security.Cryptography;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnssecEcdsa {
        [Fact]
        public void VerifyP256Signature() {
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] data = { 1, 2, 3, 4 };
            byte[] rawSig = ecdsa.SignData(data, HashAlgorithmName.SHA256);
            byte[] sig = EnsureP1363(rawSig, 32);
            ECParameters p = ecdsa.ExportParameters(false);
            byte[] pub = new byte[64];
            Buffer.BlockCopy(p.Q.X!, 0, pub, 0, 32);
            Buffer.BlockCopy(p.Q.Y!, 0, pub, 32, 32);
            string key = Convert.ToBase64String(pub);
            string sigBase64 = Convert.ToBase64String(sig);
            var method = typeof(DnsSecAnalysis).GetMethod("VerifyEcdsaSignature", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { key, sigBase64, data, 13 })!;
            Assert.True(result);
        }

        [Fact]
        public void VerifyP384Signature() {
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            byte[] data = { 5, 6, 7, 8 };
            byte[] rawSig = ecdsa.SignData(data, HashAlgorithmName.SHA384);
            byte[] sig = EnsureP1363(rawSig, 48);
            ECParameters p = ecdsa.ExportParameters(false);
            byte[] pub = new byte[96];
            Buffer.BlockCopy(p.Q.X!, 0, pub, 0, 48);
            Buffer.BlockCopy(p.Q.Y!, 0, pub, 48, 48);
            string key = Convert.ToBase64String(pub);
            string sigBase64 = Convert.ToBase64String(sig);
            var method = typeof(DnsSecAnalysis).GetMethod("VerifyEcdsaSignature", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { key, sigBase64, data, 14 })!;
            Assert.True(result);
        }

        private static byte[] EnsureP1363(byte[] signature, int size) {
            if (signature.Length == size * 2 && signature[0] != 0x30) {
                return signature;
            }

            int pos = 0;
            if (signature[pos++] != 0x30) { throw new InvalidOperationException(); }
            int seqLen = signature[pos++];
            if (seqLen >= 0x80) {
                int lenBytes = seqLen & 0x7F;
                seqLen = 0;
                for (int i = 0; i < lenBytes; i++) {
                    seqLen = (seqLen << 8) | signature[pos++];
                }
            }
            if (signature[pos++] != 0x02) { throw new InvalidOperationException(); }
            int rLen = signature[pos++];
            if (rLen >= 0x80) {
                int lenBytes = rLen & 0x7F;
                rLen = 0;
                for (int i = 0; i < lenBytes; i++) {
                    rLen = (rLen << 8) | signature[pos++];
                }
            }
            byte[] r = new byte[rLen];
            Buffer.BlockCopy(signature, pos, r, 0, rLen);
            pos += rLen;
            if (signature[pos++] != 0x02) { throw new InvalidOperationException(); }
            int sLen = signature[pos++];
            if (sLen >= 0x80) {
                int lenBytes = sLen & 0x7F;
                sLen = 0;
                for (int i = 0; i < lenBytes; i++) {
                    sLen = (sLen << 8) | signature[pos++];
                }
            }
            byte[] s = new byte[sLen];
            Buffer.BlockCopy(signature, pos, s, 0, sLen);

            r = TrimLeadingZeros(r);
            s = TrimLeadingZeros(s);

            byte[] output = new byte[size * 2];
            Buffer.BlockCopy(r, 0, output, size - r.Length, r.Length);
            Buffer.BlockCopy(s, 0, output, (size * 2) - s.Length, s.Length);
            return output;
        }

        private static byte[] TrimLeadingZeros(byte[] value) {
            int i = 0;
            while (i < value.Length - 1 && value[i] == 0) {
                i++;
            }
            if (i == 0) {
                return value;
            }
            byte[] result = new byte[value.Length - i];
            Buffer.BlockCopy(value, i, result, 0, result.Length);
            return result;
        }
    }
}
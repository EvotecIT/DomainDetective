using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestNSAnalysis {
        private static NSAnalysis CreateAnalysis(
            Func<string, DnsRecordType, Task<DnsAnswer[]>>? overrideFunc = null,
            Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>? fullOverride = null) {
            return new NSAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = overrideFunc,
                QueryDnsFullOverride = fullOverride,
                EnableChaosFingerprinting = false,
                LookupAsnOverride = _ => Task.FromResult<int?>(null)
            };
        }

        [Fact]
        public async Task DetectAtLeastTwoRecords() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((_, _) => Task.FromResult(Array.Empty<DnsAnswer>()));
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.AtLeastTwoRecords);
            Assert.False(analysis.HasDuplicates);
        }

        [Fact]
        public async Task DetectDuplicates() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((_, _) => Task.FromResult(Array.Empty<DnsAnswer>()));
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.HasDuplicates);
        }

        [Fact]
        public async Task DetectMissingARecord() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => Task.FromResult(Array.Empty<DnsAnswer>()));
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.False(analysis.AllHaveAOrAaaa);
        }

        [Fact]
        public async Task DetectCname() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => {
                if (type == DnsRecordType.CNAME) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "cname.example.com" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            });
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.PointsToCname);
        }

        [Fact]
        public async Task DetectDiverseLocations() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => {
                return (name, type) switch {
                    ("ns1.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                    ("ns2.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2.2.2.2" } }),
                    _ => Task.FromResult(Array.Empty<DnsAnswer>())
                };
            });
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.HasDiverseLocations);
        }

        [Fact]
        public async Task EmitsHighDiversityAssessment() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => {
                return (name, type) switch {
                    ("ns1.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                    ("ns2.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2.2.2.2" } }),
                    _ => Task.FromResult(Array.Empty<DnsAnswer>())
                };
            });
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.Contains(analysis.Assessments, a => a.Code == NSCodes.HighDiversity);
        }

        [Fact]
        public async Task DetectSingleSubnet() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => {
                return (name, type) switch {
                    (_, DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                    _ => Task.FromResult(Array.Empty<DnsAnswer>())
                };
            });
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.False(analysis.HasDiverseLocations);
        }

        [Fact]
        public async Task DetectDelegationMismatch() {
            var childAnswers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis(
                overrideFunc: (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()),
                fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                    new DnsResponse {
                        Answers = new[] { new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS } },
                        Additional = Array.Empty<DnsAnswer>()
                    }
                }));
            await analysis.AnalyzeNsRecords(childAnswers, new InternalLogger());
            await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());

            Assert.False(analysis.DelegationMatches);
        }

        [Fact]
        public async Task DetectMissingGlue() {
            var childAnswers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis(
                overrideFunc: (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()),
                fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                    new DnsResponse {
                        Answers = new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } },
                        Additional = Array.Empty<DnsAnswer>()
                    }
                }));
            await analysis.AnalyzeNsRecords(childAnswers, new InternalLogger());
            await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());

            Assert.False(analysis.GlueRecordsComplete);
        }

        [Fact]
        public async Task DetectInconsistentGlue() {
            var childAnswers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis(
                overrideFunc: (name, type) => {
                    if (name == "ns1.example.com" && (type == DnsRecordType.A || type == DnsRecordType.AAAA)) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "2.2.2.2" } });
                    }
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                },
                fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                    new DnsResponse {
                        Answers = new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } },
                        Additional = new[] { new DnsAnswer { Name = "ns1.example.com", DataRaw = "1.1.1.1", Type = DnsRecordType.A } }
                    }
                }));
            await analysis.AnalyzeNsRecords(childAnswers, new InternalLogger());
            await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());

            Assert.False(analysis.GlueRecordsConsistent);
        }

        [Fact]
        public async Task AnalyzeParentDelegationSuccess() {
            var childAnswers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis(
                overrideFunc: (name, type) => {
                    if (name == "ns1.example.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                    }
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                },
                fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                    new DnsResponse {
                        Answers = new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } },
                        Additional = new[] { new DnsAnswer { Name = "ns1.example.com", DataRaw = "1.1.1.1", Type = DnsRecordType.A } }
                    }
                }));
            await analysis.AnalyzeNsRecords(childAnswers, new InternalLogger());
            await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());

            Assert.True(analysis.DelegationMatches);
            Assert.True(analysis.GlueRecordsComplete);
            Assert.True(analysis.GlueRecordsConsistent);
        }

        [Fact]
        public async Task QueryParentNsGlueParsesRecords() {
            var analysis = CreateAnalysis(fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                new DnsResponse {
                    Answers = new[] {
                        new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                        new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
                    },
                    Additional = new[] {
                        new DnsAnswer { Name = "ns1.example.com", DataRaw = "1.1.1.1", Type = DnsRecordType.A },
                        new DnsAnswer { Name = "ns2.example.com", DataRaw = "2.2.2.2", Type = DnsRecordType.A }
                    }
                }
            }));

            var (ns, glue) = await analysis.QueryParentNsGlue("example.com", new InternalLogger());

            Assert.Equal(new[] { "ns1.example.com", "ns2.example.com" }, ns);
            Assert.Equal("1.1.1.1", Assert.Single(glue["ns1.example.com"]));
            Assert.Equal("2.2.2.2", Assert.Single(glue["ns2.example.com"]));
        }

        [Fact]
        public async Task QueryRootServersRespond() {
            var analysis = CreateAnalysis((name, type) => {
                if (name == "." && type == DnsRecordType.NS) {
                    return Task.FromResult(new[] {
                        new DnsAnswer { DataRaw = "a.root-servers.net" },
                        new DnsAnswer { DataRaw = "b.root-servers.net" }
                    });
                }
                if (name == "a.root-servers.net" && type == DnsRecordType.A) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            });
            await analysis.QueryRootServers(new InternalLogger());
            Assert.True(analysis.RootServerResponses["a.root-servers.net"]);
            Assert.False(analysis.RootServerResponses["b.root-servers.net"]);
        }

        [Fact]
        public async Task DetectRecursionEnabled() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((_, _) => Task.FromResult(Array.Empty<DnsAnswer>()));
            analysis.RecursionTestOverride = _ => Task.FromResult(true);
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());
            await analysis.TestRecursion(new InternalLogger());
            Assert.True(analysis.RecursionEnabled["ns1.example.com"]);
        }

        [Fact]
        public async Task DetectChaosFingerprintingVersionAndHostname()
        {
            var answers = new List<DnsAnswer>
            {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };

            var analysis = CreateAnalysis((name, type) =>
            {
                return (name, type) switch
                {
                    ("ns1.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                    _ => Task.FromResult(Array.Empty<DnsAnswer>())
                };
            });
            analysis.EnableChaosFingerprinting = true;
            analysis.QueryUdpOverride = (_, query, __) =>
            {
                string ReadName(byte[] buf)
                {
                    int o = 12;
                    var labels = new List<string>();
                    while (o < buf.Length)
                    {
                        int len = buf[o++];
                        if (len == 0) break;
                        if (o + len > buf.Length) break;
                        labels.Add(System.Text.Encoding.ASCII.GetString(buf, o, len));
                        o += len;
                    }
                    return string.Join(".", labels);
                }

                byte[] BuildTxtResponse(byte[] req, string qname, string txt)
                {
                    var nameBytes = new List<byte>();
                    foreach (var part in qname.Split('.'))
                    {
                        var b = System.Text.Encoding.ASCII.GetBytes(part);
                        nameBytes.Add((byte)b.Length);
                        nameBytes.AddRange(b);
                    }
                    nameBytes.Add(0);

                    var txtBytes = System.Text.Encoding.ASCII.GetBytes(txt);
                    var rdata = new byte[1 + txtBytes.Length];
                    rdata[0] = (byte)txtBytes.Length;
                    Buffer.BlockCopy(txtBytes, 0, rdata, 1, txtBytes.Length);

                    var msg = new List<byte>();
                    // Header
                    msg.Add(req[0]); msg.Add(req[1]); // id
                    msg.Add(0x81); msg.Add(0x80); // standard response, NOERROR
                    msg.Add(0x00); msg.Add(0x01); // QDCOUNT
                    msg.Add(0x00); msg.Add(0x01); // ANCOUNT
                    msg.Add(0x00); msg.Add(0x00); // NSCOUNT
                    msg.Add(0x00); msg.Add(0x00); // ARCOUNT
                    // Question: QNAME + QTYPE=TXT + QCLASS=CH
                    msg.AddRange(nameBytes);
                    msg.Add(0x00); msg.Add(0x10);
                    msg.Add(0x00); msg.Add(0x03);
                    // Answer: NAME pointer to 0x0c
                    msg.Add(0xC0); msg.Add(0x0C);
                    msg.Add(0x00); msg.Add(0x10); // TXT
                    msg.Add(0x00); msg.Add(0x03); // CH
                    msg.Add(0x00); msg.Add(0x00); msg.Add(0x00); msg.Add(0x3C); // TTL
                    msg.Add((byte)(rdata.Length >> 8)); msg.Add((byte)(rdata.Length & 0xFF));
                    msg.AddRange(rdata);
                    return msg.ToArray();
                }

                var q = ReadName(query);
                if (q.Equals("version.bind", System.StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult<byte[]?>(BuildTxtResponse(query, "version.bind", "BIND 9.18.0"));
                }
                if (q.Equals("hostname.bind", System.StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult<byte[]?>(BuildTxtResponse(query, "hostname.bind", "ns1"));
                }
                return Task.FromResult<byte[]?>(null);
            };

            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.Contains(analysis.Assessments, a => a.Code == NSCodes.ChaosVersionExposed);
            Assert.Contains(analysis.Assessments, a => a.Code == NSCodes.ChaosHostnameExposed);
        }
    }
}

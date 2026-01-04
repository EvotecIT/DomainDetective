using System;
using System.Collections.Generic;
using System.IO;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestDesiredStateOverrides {
    [Fact]
    public void Load_ThrowsArgumentException_WhenPathIsWhitespace() {
        Assert.Throws<ArgumentException>(() => DesiredStateConfiguration.Load("   "));
    }

    [Fact]
    public void Load_ThrowsInvalidOperationException_WhenVersionIsZero() {
        var json = @"{ ""version"": 0, ""defaults"": { } }";
        var file = Path.GetTempFileName();
        try {
            File.WriteAllText(file, json);
            Assert.Throws<InvalidOperationException>(() => DesiredStateConfiguration.Load(file));
        } finally {
            File.Delete(file);
        }
    }

    [Fact]
    public void ResolveProfile_DoesNotApplyClassificationOverride_WhenClassificationNotProvided() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Spf = new DesiredStateSpfPolicy {
                    MaxDnsLookups = 10
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        Classifications = new[] { MailDomainClassificationCategory.Parked }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            MaxDnsLookups = 2
                        }
                    }
                }
            }
        };

        var profile = cfg.ResolveProfile("example.com", classification: null);
        Assert.Equal(10, profile.Spf?.MaxDnsLookups);
    }

    [Fact]
    public void ResolveProfile_AppliesClassificationOverride_WhenClassificationMatches() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Spf = new DesiredStateSpfPolicy {
                    MaxDnsLookups = 10
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        Classifications = new[] { MailDomainClassificationCategory.Parked }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            MaxDnsLookups = 2
                        }
                    }
                }
            }
        };

        var profile = cfg.ResolveProfile("example.com", MailDomainClassificationCategory.Parked);
        Assert.Equal(2, profile.Spf?.MaxDnsLookups);
    }

    [Fact]
    public void ResolveProfile_EmptyDomainPatterns_MatchAllDomains() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile(),
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = Array.Empty<string>()
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            RequireDenyAll = true
                        }
                    }
                }
            }
        };

        var profile = cfg.ResolveProfile("anything.example", MailDomainClassificationCategory.SendingAndReceiving);
        Assert.True(profile.Spf?.RequireDenyAll == true);
    }

    [Fact]
    public void ResolveProfile_OverlappingOverrides_LastWins() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Spf = new DesiredStateSpfPolicy {
                    MaxDnsLookups = 10
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "*.example.com" }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            MaxDnsLookups = 5
                        }
                    }
                },
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "a.example.com" }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            MaxDnsLookups = 1
                        }
                    }
                }
            }
        };

        Assert.Equal(5, cfg.ResolveProfile("b.example.com", MailDomainClassificationCategory.SendingAndReceiving).Spf?.MaxDnsLookups);
        Assert.Equal(1, cfg.ResolveProfile("a.example.com", MailDomainClassificationCategory.SendingAndReceiving).Spf?.MaxDnsLookups);
    }

    [Fact]
    public void ResolveProfile_WildcardQuestionMark_MatchesSingleLabelCharacter() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Spf = new DesiredStateSpfPolicy {
                    MaxDnsLookups = 10
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "?.example.com" }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            MaxDnsLookups = 3
                        }
                    }
                }
            }
        };

        Assert.Equal(3, cfg.ResolveProfile("a.example.com", MailDomainClassificationCategory.SendingAndReceiving).Spf?.MaxDnsLookups);
        Assert.Equal(10, cfg.ResolveProfile("aa.example.com", MailDomainClassificationCategory.SendingAndReceiving).Spf?.MaxDnsLookups);
    }

    [Fact]
    public void ResolveProfile_ThrowsArgumentException_WhenDomainIsWhitespace() {
        var cfg = new DesiredStateConfiguration();
        Assert.Throws<ArgumentException>(() => cfg.ResolveProfile("   ", MailDomainClassificationCategory.SendingAndReceiving));
    }
}


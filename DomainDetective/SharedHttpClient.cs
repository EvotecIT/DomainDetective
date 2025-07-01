using System;
using System.Net.Http;

namespace DomainDetective;

public static class SharedHttpClient
{
    public static readonly HttpClient Instance;

    static SharedHttpClient()
    {
        Instance = new HttpClient();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Instance.Dispose();
    }
}

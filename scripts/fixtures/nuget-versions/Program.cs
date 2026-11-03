// SPDX-License-Identifier: BUSL-1.1
// Only our synthetic version strings reach this SDK-owned reference library.
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using NuGet.Versioning;
using NuGet.Packaging;

class Program
{
    static void Main(string[] args)
    {
        using var input = Console.OpenStandardInput();
        using var memory = new System.IO.MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
        {
            if (memory.Length + count > 2 * 1024 * 1024) throw new Exception("owned input budget");
            memory.Write(buffer, 0, count);
        }
        var values = JsonSerializer.Deserialize<string[]>(memory.ToArray());
        if (values == null || values.Length > 4096) throw new Exception("owned case count");
        if (args.Length == 1 && args[0] == "nuspec")
        {
            var identities = values.Select(value => {
                try
                {
                    using var stream = new System.IO.MemoryStream(Convert.FromBase64String(value));
                    var reader = new NuspecReader(stream);
                    return new { valid = true, id = reader.GetId(), version_key = reader.GetVersion().ToNormalizedString().ToLowerInvariant() };
                }
                catch (Exception)
                {
                    return new { valid = false, id = "", version_key = "" };
                }
            }).ToArray();
            Console.WriteLine(JsonSerializer.Serialize(new {
                os = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "other",
                architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                version = typeof(NuspecReader).Assembly.GetName().Version.ToString(),
                rows = identities
            }));
            return;
        }
        var rows = values.Select(value => {
            bool valid = NuGetVersion.TryParse(value, out var parsed);
            return new { valid, key = valid ? parsed.ToNormalizedString().ToLowerInvariant() : "" };
        }).ToArray();
        Console.WriteLine(JsonSerializer.Serialize(new {
            os = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "other",
            architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            version = typeof(NuGetVersion).Assembly.GetName().Version.ToString(),
            rows
        }));
    }
}

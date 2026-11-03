// SPDX-License-Identifier: BUSL-1.1
// Only owned synthetic IDs, versions, manifests and archive bytes reach the SDK.
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
        int caseLimit = args.Length == 1 && args[0] == "id" ? 65536 : 4096;
        if (values == null || values.Length > caseLimit) throw new Exception("owned case count");
        if (args.Length == 1 && args[0] == "compare")
        {
            var comparisons = values.Select(value => {
                var pair = JsonSerializer.Deserialize<string[]>(value);
                if (pair == null || pair.Length != 2) throw new Exception("owned pair shape");
                var leftOK = NuGetVersion.TryParse(pair[0], out var left);
                var rightOK = NuGetVersion.TryParse(pair[1], out var right);
                bool valid = leftOK && rightOK;
                return new { valid, order = valid ? Math.Sign(VersionComparer.VersionRelease.Compare(left, right)) : 0 };
            }).ToArray();
            Console.WriteLine(JsonSerializer.Serialize(new {
                os = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "other",
                architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                version = typeof(VersionComparer).Assembly.GetName().Version.ToString(),
                rows = comparisons
            }));
            return;
        }
        if (args.Length == 1 && args[0] == "properties")
        {
            var names = new[] { "id", "version", "authors", "owners", "description", "title", "summary", "tags", "projecturl", "iconurl", "licenseurl", "language", "copyright", "releasenotes", "license", "readme", "icon" };
            var properties = values.Select(value => {
                try
                {
                    using var stream = new System.IO.MemoryStream(Convert.FromBase64String(value));
                    var reader = new NuspecReader(stream);
                    _ = reader.GetId();
                    _ = reader.GetVersion();
                    var fields = names.Select(name => new { name, value = reader.GetMetadataValue(name) })
                        .Where(field => !string.IsNullOrEmpty(field.value))
                        .ToDictionary(field => field.name, field => field.value);
                    return new { valid = true, values = fields };
                }
                catch (Exception)
                {
                    return new { valid = false, values = new System.Collections.Generic.Dictionary<string, string>() };
                }
            }).ToArray();
            Console.WriteLine(JsonSerializer.Serialize(new {
                os = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "other",
                architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                version = typeof(NuspecReader).Assembly.GetName().Version.ToString(),
                rows = properties
            }));
            return;
        }
        if (args.Length == 1 && args[0] == "id")
        {
            var identities = values.Select(value => {
                bool referenceValid;
                try { PackageIdValidator.ValidatePackageId(value); referenceValid = true; }
                catch (ArgumentException) { referenceValid = false; }
                // The repository's transport profile rejects control characters;
                // report SDK acceptance separately rather than attributing it.
                bool transportRejected = referenceValid && value.Any(c => char.IsControl(c));
                bool valid = referenceValid && !transportRejected;
                return new { valid, key = valid ? value.ToLowerInvariant() : "", reference_valid = referenceValid, transport_rejected = transportRejected };
            }).ToArray();
            Console.WriteLine(JsonSerializer.Serialize(new {
                os = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "other",
                architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                version = typeof(PackageIdValidator).Assembly.GetName().Version.ToString(),
                runtime = RuntimeInformation.FrameworkDescription,
                rows = identities
            }));
            return;
        }
        if (args.Length == 1 && args[0] == "archive")
        {
            var identities = values.Select(value => {
                try
                {
                    using var stream = new System.IO.MemoryStream(Convert.FromBase64String(value));
                    using var reader = new PackageArchiveReader(stream);
                    var identity = reader.GetIdentity();
                    using var nuspec = reader.GetNuspec();
                    using var output = new System.IO.MemoryStream();
                    nuspec.CopyTo(output);
                    return new { valid = true, id = identity.Id, version_key = identity.Version.ToNormalizedString().ToLowerInvariant(), nuspec_path = reader.GetNuspecFile(), nuspec = Convert.ToBase64String(output.ToArray()) };
                }
                catch (Exception)
                {
                    return new { valid = false, id = "", version_key = "", nuspec_path = "", nuspec = "" };
                }
            }).ToArray();
            Console.WriteLine(JsonSerializer.Serialize(new {
                os = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "other",
                architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                version = typeof(PackageArchiveReader).Assembly.GetName().Version.ToString(),
                rows = identities
            }));
            return;
        }
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

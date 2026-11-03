// SPDX-License-Identifier: BUSL-1.1
// Owned probe: invoke the installed SDK's HTTP metadata resource against the
// isolated registry. It never loads or runs package payloads or prints secrets.
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Configuration;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using NuGet.Packaging;

class Program
{
    static object ObserveGroups(IEnumerable<PackageDependencyGroup> groups, bool omitFloat)
    {
        return groups.Select(group => new {
            framework = group.TargetFramework.GetShortFolderName(),
            framework_name = group.TargetFramework.ToString(),
            packages = group.Packages.Select(dep => new {
                id = dep.Id,
                min = dep.VersionRange.MinVersion?.ToNormalizedString() ?? "",
                max = dep.VersionRange.MaxVersion?.ToNormalizedString() ?? "",
                min_metadata = dep.VersionRange.MinVersion?.Metadata ?? "",
                max_metadata = dep.VersionRange.MaxVersion?.Metadata ?? "",
                include_min = dep.VersionRange.IsMinInclusive,
                include_max = dep.VersionRange.IsMaxInclusive,
                floating = omitFloat ? false : dep.VersionRange.IsFloating,
                preference = omitFloat ? "" : (dep.VersionRange.Float?.ToString() ?? "")
            }).ToArray()
        }).ToArray();
    }

    static async Task Main(string[] args)
    {
        if (args.Length != 2 && (args.Length != 3 || args[1] != "--corpus")) throw new Exception("owned probe argument count");
        var path = Path.GetFullPath(args[0]);
        var settings = Settings.LoadSpecificSettings(Path.GetDirectoryName(path), Path.GetFileName(path));
        var source = new PackageSourceProvider(settings).LoadPackageSources().Single(s => s.Name == "cratectl");
        var uri = new Uri(source.Source);
        if (!uri.IsLoopback || uri.Port != 38443 || uri.Scheme != "http") throw new Exception("owned loopback source required");
        var repository = Repository.Factory.GetCoreV3(source);
        using var cache = new SourceCacheContext { NoCache = true, DirectDownload = true };
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var resource = await repository.GetResourceAsync<PackageMetadataResource>();
        var index = await repository.GetResourceAsync<ServiceIndexResourceV3>();
        int searchEndpointCount = index.GetServiceEntryUris(ServiceTypes.SearchQueryService).Count;
        if (args.Length == 3)
        {
            byte[] bytes = File.ReadAllBytes(args[2]);
            if (bytes.Length > 2 * 1024 * 1024) throw new Exception("owned corpus byte budget");
            using var document = JsonDocument.Parse(bytes);
            var corpus = document.RootElement.EnumerateArray().ToArray();
            if (corpus.Length < 1 || corpus.Length > 64) throw new Exception("owned corpus case budget");
            var observations = new List<object>();
            foreach (var value in corpus)
            {
                try
                {
                    string id = value.GetProperty("id").GetString();
                    bool omitFloat = value.GetProperty("omit_float_comparison").GetBoolean();
                    using var stream = new MemoryStream(Convert.FromBase64String(value.GetProperty("nuspec").GetString()));
                    var original = new NuspecReader(stream);
                    var expected = new { groups = ObserveGroups(original.GetDependencyGroups(), omitFloat), license_acceptance = original.GetRequireLicenseAcceptance() };
                    var actual = (await resource.GetMetadataAsync(id, true, true, cache, NullLogger.Instance, cancel.Token)).Single();
                    var observed = new { groups = ObserveGroups(actual.DependencySets, omitFloat), license_acceptance = actual.RequireLicenseAcceptance };
                    observations.Add(new { index = value.GetProperty("index").GetInt32(), valid = true, matches = JsonSerializer.Serialize(expected) == JsonSerializer.Serialize(observed), original = (object)expected, http = (object)observed });
                }
                catch (Exception error)
                {
                    observations.Add(new { index = value.GetProperty("index").GetInt32(), valid = false, matches = false, error_type = error.GetType().Name });
                }
            }
            Console.WriteLine(JsonSerializer.Serialize(new {
                architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                library_version = typeof(PackageMetadataResource).Assembly.GetName().Version.ToString(),
                rows = observations
            }));
            return;
        }
        var items = (await resource.GetMetadataAsync(args[1], true, true, cache, NullLogger.Instance, cancel.Token)).ToArray();
        if (items.Length > 1000) throw new Exception("owned metadata row budget");
        var rows = items.Select(item => new {
            id = item.Identity.Id,
            version = item.Identity.Version.ToFullString(),
            listed = item.IsListed,
            require_license_acceptance = item.RequireLicenseAcceptance,
            groups = item.DependencySets.Select(group => new {
                framework = group.TargetFramework.GetShortFolderName(),
                packages = group.Packages.Select(dep => new {
                    id = dep.Id,
                    min = dep.VersionRange.MinVersion?.ToNormalizedString() ?? "",
                    max = dep.VersionRange.MaxVersion?.ToNormalizedString() ?? "",
                    include_min = dep.VersionRange.IsMinInclusive,
                    include_max = dep.VersionRange.IsMaxInclusive
                }).ToArray()
            }).ToArray()
        }).ToArray();
        Console.WriteLine(JsonSerializer.Serialize(new {
            architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            library_version = typeof(PackageMetadataResource).Assembly.GetName().Version.ToString(),
            search_endpoint_count = searchEndpointCount,
            rows
        }));
    }
}

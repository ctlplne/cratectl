// SPDX-License-Identifier: BUSL-1.1
// Owned probe: invoke the installed SDK's HTTP metadata resource against the
// isolated registry. It never loads or runs package payloads or prints secrets.
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Configuration;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length != 2) throw new Exception("owned probe argument count");
        var path = Path.GetFullPath(args[0]);
        var settings = Settings.LoadSpecificSettings(Path.GetDirectoryName(path), Path.GetFileName(path));
        var source = new PackageSourceProvider(settings).LoadPackageSources().Single(s => s.Name == "cratectl");
        var uri = new Uri(source.Source);
        if (!uri.IsLoopback || uri.Port != 38443 || uri.Scheme != "http") throw new Exception("owned loopback source required");
        var repository = Repository.Factory.GetCoreV3(source);
        using var cache = new SourceCacheContext { NoCache = true, DirectDownload = true };
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var resource = await repository.GetResourceAsync<PackageMetadataResource>();
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
            rows
        }));
    }
}

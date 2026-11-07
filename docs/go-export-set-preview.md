# Preview several hosted Go versions together

The new `POST /api/v1/go/export-sets/preview` endpoint plans selected package
metadata in one database view. It is implemented; actual native qualification
is pending. A concurrent publication or policy update cannot make the first
member come from one view and the last member from another. This is metadata
planning only. Durable common-snapshot creation and package collection remain
in progress in the [complete export plan](qualification/go-export-plan.json).

Use a current tenant administrator credential with read access to every selected
hosted repository. Read each repository's current `source_revision` from normal
repository management; this counter changes when its source configuration
changes. Choose exact canonical module/version pairs. A denied, missing or
changed later member refuses the whole preview; no partial member list is
returned. Duplicate coordinates in different repositories are also refused.

Save a private JSON body, for example:

```json
{
  "entries": [
    {
      "repository": "hosted",
      "module": "go.cratectl.invalid/Owned/application",
      "version": "v1.0.0",
      "expected_source_revision": 0
    },
    {
      "repository": "hosted",
      "module": "go.cratectl.invalid/Owned/dependency",
      "version": "v1.1.0",
      "expected_source_revision": 0
    }
  ],
  "lifetime_seconds": 900,
  "max_artifact_bytes": 1073741824
}
```

The lifetime is intent for the later durable operation. Preview creates no
session or expiry clock. The byte budget bounds the sum of declared ZIP/mod/info
sizes, not bytes physically inspected by this endpoint. Repeated content counts
separately. Keep the body and any retained response private.

```sh
cratectl --config /private/path/client.json \
  --method POST --path /api/v1/go/export-sets/preview \
  --body-file /private/path/export-set-request.json \
  --response-limit 16777216 --timeout 60s
```

A successful response contains the complete selected metadata, one observed
journal head and preparation time, and the object identity of the canonical
manifest encoding. The embedded manifest is JSON data; its object hash refers
to canonical bytes including a final newline. It is unsigned and supplies no
independent trust. `physical_objects_verified` and `durable_session_created` are
false. The manifest also keeps current admission, checksum-authority trust and
dependency closure false. A list chosen by an operator is not automatic closure.

The endpoint opens no package object and adds no session, blob pin, mutation
receipt, event or job. A policy change after the admitted read does not upgrade
that old preview: the later creation path must recheck current permissions,
source epochs, exact bytes and policy under the publication fence. Do not collect
or import a bundle based only on this preview hash.

Limits are256entries,256KiB request,32KiB per child manifest,8MiB combined
canonical metadata and30seconds for the complete database planning transaction.
The usual bounded request slots/server timeouts still apply. Declared bytes must
fit the requested positive budget through64GiB. A409means refresh source
revisions and preview again;403requires current source access/policy;413requires
a smaller selection or higher permitted byte budget. No failed preview certifies
a partial or complete export. All other export/platform/provider/production
requirements remain in the plan.

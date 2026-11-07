// SPDX-License-Identifier: BUSL-1.1
import type {Common} from './view-types';
import {Copy,ErrorBox,Freshness,useResource} from './components';

const commands=`# Authenticate the exact tenant, sequence and hash through your separate
# trusted record or external signing tool. Set these variables from that record.
: "\${CRATECTL_TRUSTED_TENANT:?Set the independently authenticated tenant}"
: "\${CRATECTL_TRUSTED_JOURNAL_SEQUENCE:?Set the authenticated terminal sequence}"
: "\${CRATECTL_TRUSTED_JOURNAL_HASH?Set the authenticated terminal SHA-256; empty only at genesis}"
: "\${CRATECTL_CLIENT_CONFIG:?Set your private client JSON path}"
umask 077
cratectl journal-export --config "$CRATECTL_CLIENT_CONFIG" \\
  --tenant "$CRATECTL_TRUSTED_TENANT" \\
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \\
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \\
  --output ./cratectl-journal.jsonl
cratectl journal-verify --export-file ./cratectl-journal.jsonl \\
  --tenant "$CRATECTL_TRUSTED_TENANT" \\
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \\
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH"`;

export function JournalExport(p:Common){
  type Observation={checkpoint:{tenant:string;sequence:number;hash:string};signed:boolean;trust:string};
  const data=useResource<Observation>(p.client,'/api/v1/audit/checkpoint',p.revision);
  const observed=!data.loading&&!data.error?data.data:undefined;const anchor=observed?.checkpoint;
  const exact=!!anchor&&anchor.tenant===p.identity.tenant&&Number.isSafeInteger(anchor.sequence)&&anchor.sequence>=0&&(anchor.sequence===0?anchor.hash==='':/^[a-f0-9]{64}$/.test(anchor.hash))&&observed?.signed===false;
  return <><p>This observation is unsigned. Authenticate its exact tenant, sequence and hash through a separate trusted record or your existing external signing tool. A hash downloaded beside its data does not authenticate itself.</p><div className="view-toolbar"><Freshness at={data.at}loading={data.loading}/><button onClick={data.refresh}>Refresh journal checkpoint</button></div>{data.loading&&<p role="status">Loading the unsigned checkpoint…</p>}{data.error&&<ErrorBox error={data.error}retry={data.refresh}/>} {anchor&&!exact&&<p className="message error"role="alert">The observed checkpoint exceeds exact console precision or has invalid bindings. Use the API and CLI with exact values; do not copy rounded numbers from this view.</p>}{exact&&anchor&&<><dl className="facts"><div><dt>Tenant</dt><dd>{anchor.tenant}</dd></div><div><dt>Observed terminal sequence</dt><dd>{anchor.sequence}</dd></div><div><dt>Observed SHA-256</dt><dd><code className="break">{anchor.hash||'Empty genesis hash'}</code></dd></div><div><dt>External authentication</dt><dd>Required separately</dd></div></dl>{anchor.sequence===0&&<p role="status">This tenant has no recorded journal events. The API and CLI accept an empty genesis range with sequence zero and an empty hash.</p>}<h3>Collect and verify a complete fixed range</h3><p>Use values from your independently authenticated record in these commands. The CLI follows byte-bounded pages into a new private file and verifies every original event through the supplied terminal hash. New appends do not move that boundary. Existing files are preserved.</p><pre className="json">{commands}</pre><Copy text={commands}label="Copy journal export commands"/></>}<p>A failed collection leaves an incomplete private file and emits no success receipt. Preserve it and retry into a new file using the same trusted checkpoint. A verified range establishes integrity relative to that checkpoint; it does not prove event claims or approve package bytes.</p></>;
}

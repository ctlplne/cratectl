// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {pending} from './api';
import type {Repository} from './api';
import type {Common} from './view-types';
import {Copy,CursorPages,Empty,ErrorBox,Freshness,Heading,Json,MutationForm,Panel,useResource} from './components';
import {JournalExport} from './journal-export';

type Session={id:string;repository:string;module:string;version:string;source_revision:number;generation:number;created_sequence:number;change_sequence:number;state:string;manifest:{digest:string;size:number};expires_at:string;max_expires_at:string;server_time:string;delivery_verified:boolean;payload_pins_retained:boolean;manifest_retained:boolean};
const repositoryName=(v:unknown)=>typeof v==='string'&&/^[a-z][a-z0-9-]{0,62}$/.test(v);
const hash=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const integer=(v:number,min=0)=>Number.isSafeInteger(v)&&v>=min;
const instant=(v:unknown)=>typeof v==='string'&&v.length<=64&&Number.isFinite(Date.parse(v));
function sourceText(value:unknown,fallback:string,max=512){return typeof value==='string'&&value.length>0&&value.length<=max?value:fallback}
function exact(v:Session){return repositoryName(v.repository)&&typeof v.module==='string'&&v.module.length>0&&v.module.length<=512&&typeof v.version==='string'&&v.version.length>0&&v.version.length<=128&&hash(v.id)&&hash(v.manifest?.digest??'')&&integer(v.manifest?.size,1)&&v.manifest.size<=32768&&integer(v.source_revision)&&integer(v.generation,1)&&integer(v.created_sequence,1)&&integer(v.change_sequence,v.created_sequence)&&v.delivery_verified===false&&v.manifest_retained===true&&typeof v.payload_pins_retained==='boolean'&&['open','acknowledged','cancelled','expired','expired_unreconciled'].includes(v.state)&&instant(v.expires_at)&&instant(v.max_expires_at)&&instant(v.server_time)}
const sh=(v:string)=>"'"+v.replace(/'/g,"'\\''")+"'";
function commands(v:Session,resume=false){
 const required=`: "\${CRATECTL_CLIENT_CONFIG:?Set your private client JSON path}"
: "\${CRATECTL_TRUSTED_TENANT:?Set the independently authenticated tenant}"
: "\${CRATECTL_TRUSTED_JOURNAL_SEQUENCE:?Set the authenticated terminal sequence}"
: "\${CRATECTL_TRUSTED_JOURNAL_HASH:?Set the authenticated terminal SHA-256}"
: "\${CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE:?Set the separately trusted public key path}"`;
 const collect=`cratectl go-export-collect --config "$CRATECTL_CLIENT_CONFIG" ${resume?'--resume ':''}\\
  --export-id ${sh(v.id)} --generation ${v.generation} \\
  --repository ${sh(v.repository)} --module ${sh(v.module)} --version ${sh(v.version)} \\
  --output-directory ./cratectl-export-input/collected \\
  --journal-file ./cratectl-journal.jsonl --journal-tenant "$CRATECTL_TRUSTED_TENANT" \\
  --journal-event-sequence ${v.created_sequence} --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \\
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" --checkpoint-file ./checkpoint.json \\
  --checkpoint-signature-file ./checkpoint.sig --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"`;
 if(resume)return `# Refresh the session first. This resumes its same signed immutable snapshot.
# Existing partial files are retained; a renewed generation is explicit above.
(
set -euC
umask 077
${required}
${collect}
)`;
 return `# Obtain the complete independently signed journal and checkpoint first.
# Creation event ${v.created_sequence} must be inside that range; trust its key separately.
# First collection only: choose a fresh owner-private parent directory.
(
set -euC
umask 077
${required}
mkdir -m 700 ./cratectl-export-input
${collect}
# If interrupted, keep the directory. Refresh and copy the --resume command.
# Completion proves historical bytes, not current destination or checksum trust.
cratectl go-module-offline --repository ${sh(v.repository)} --module ${sh(v.module)} --version ${sh(v.version)} \\
  --export-id ${sh(v.id)} --manifest-file ./cratectl-export-input/collected/manifest.json \\
  --zip-file ./cratectl-export-input/collected/original.zip --mod-file ./cratectl-export-input/collected/original.mod \\
  --info-file ./cratectl-export-input/collected/original.info --output-directory ./cratectl-export-input/offline \\
  --journal-file ./cratectl-export-input/collected/journal.jsonl --journal-tenant "$CRATECTL_TRUSTED_TENANT" \\
  --journal-event-sequence ${v.created_sequence} --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \\
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" --checkpoint-file ./cratectl-export-input/collected/checkpoint.json \\
  --checkpoint-signature-file ./cratectl-export-input/collected/checkpoint.sig --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"
)`
}

export function GoExports(p:Common){return p.identity.role==='admin'?<ExportAdmin {...p}/>:<><Heading eyebrow="Artifact exit"title="Hosted Go exports"description="Export exact package bytes with their historical source policy and journal context."/><p className="message warning"role="status">An administrator is required to export retained policy and journal context.</p></>}
function importCommands(v:Session,destination:string){return `# Requires a completed collection and independently trusted original journal signer.
# Destination publication uses its current permissions; source approval is historical.
(
set -euC
umask 077
: "\${CRATECTL_DESTINATION_CLIENT_CONFIG:?Set the private destination client JSON path}"
: "\${CRATECTL_DESTINATION_IMPORT_KEY:?Set a stable nonsecret mutation key; retain it for identical retries}"
: "\${CRATECTL_IMPORT_ATTEMPT_DIRECTORY:?Choose a new directory under an owner-private parent}"
: "\${CRATECTL_TRUSTED_TENANT:?Set the independently authenticated source tenant}"
: "\${CRATECTL_TRUSTED_JOURNAL_SEQUENCE:?Set the authenticated original terminal sequence}"
: "\${CRATECTL_TRUSTED_JOURNAL_HASH:?Set the authenticated original terminal SHA-256}"
: "\${CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE:?Set the separately trusted original public key path}"
cratectl go-export-import --config "$CRATECTL_DESTINATION_CLIENT_CONFIG" \\
  --destination-repository ${sh(destination)} --idempotency-key "$CRATECTL_DESTINATION_IMPORT_KEY" \\
  --repository ${sh(v.repository)} --module ${sh(v.module)} --version ${sh(v.version)} \\
  --export-id ${sh(v.id)} --manifest-file ./cratectl-export-input/collected/manifest.json \\
  --zip-file ./cratectl-export-input/collected/original.zip --mod-file ./cratectl-export-input/collected/original.mod \\
  --info-file ./cratectl-export-input/collected/original.info --output-directory "$CRATECTL_IMPORT_ATTEMPT_DIRECTORY" \\
  --journal-file ./cratectl-export-input/collected/journal.jsonl --journal-tenant "$CRATECTL_TRUSTED_TENANT" \\
  --journal-event-sequence ${v.created_sequence} --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \\
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" --checkpoint-file ./cratectl-export-input/collected/checkpoint.json \\
  --checkpoint-signature-file ./cratectl-export-input/collected/checkpoint.sig --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"
# Preserve this attempt directory even when the response fails.
# Retry only with the same destination/source/key and a NEW private attempt directory.
# A publication receipt does not grant scan approval, checksum trust or dependency closure.
)`}
function ImportInstructions({session}:{session:Session}){
 const id=useId(),[destination,setDestination]=useState('');const valid=repositoryName(destination);
 return <><p>Use files from a completed collection of <strong>{session.module}@{session.version}</strong>. The CLI verifies the original signed journal, manifest and bytes again before contacting the destination. Its separately trusted signer must come from your own trust configuration.</p>
 <p>Choose the destination repository explicitly. Set your private destination client configuration on the machine running the command. No destination credential or configuration is uploaded through this console.</p>
 <label htmlFor={id}>Destination hosted Go repository</label><input id={id}value={destination}maxLength={63}aria-invalid={!!destination&&!valid}aria-describedby={id+'hint'}onChange={e=>setDestination(e.target.value)}/><p id={id+'hint'}className="small muted">Use a lowercase name starting with a letter, with at most 63 letters, digits or hyphens. Confirm that this repository belongs to the intended destination installation.</p>
 {valid?<><pre className="json">{importCommands(session,destination)}</pre><Copy text={importCommands(session,destination)}label="Copy destination import command"/></>:<p role="status">Enter the exact destination repository to prepare its command.</p>}
 <p>A failed response may follow a committed publication. Keep the attempt directory and repeat explicitly with the same source, destination and mutation key, choosing a new private attempt directory. Current write permissions are checked on replay.</p>
 <p>Source approval never becomes destination scan evidence or access. A review-required destination keeps unassessed packages unavailable until its own current policy is satisfied. Historical files already collected can be imported after the source session ends; this does not restore source download access.</p></>
}
function ExportAdmin(p:Common){
 const [after,setAfter]=useState('');const data=useResource<{items:Session[];more:boolean;next_after:number}>(p.client,'/api/v1/go/exports?limit=25'+(after?'&after='+encodeURIComponent(after):''),p.revision);
 const shapeOK=data.data===undefined||!!data.data&&Array.isArray(data.data.items),rows=shapeOK?data.data?.items??[]:[],fresh=!data.loading&&!data.error&&shapeOK;const next=data.data?.next_after??0;const cursorOK=integer(next)&&(!data.data?.more||rows.length>0&&next===(rows.at(-1)?.created_sequence??0)&&next>Number(after||0));
 function action(v:Session,name:'renew'|'acknowledge'|'cancel'|'expire'){
  p.run(name==='renew'?'Renew export':name==='cancel'?'Cancel export':name==='expire'?'Reconcile expiry':'Acknowledge collection',name==='acknowledge'?'Record that you collected this exact manifest. This is your acknowledgment, not independent delivery verification.':name==='cancel'?'Stop future downloads and release this session’s package pins. The historical manifest and journal remain retained.':name==='expire'?'Commit the expired session’s terminal state before releasing its package pins.':'Extend the current session by up to one hour within its original 24-hour window. This changes the generation; resume with the new value.',{method:'PATCH',path:'/api/v1/go/exports/'+v.id,body:{action:name,expected_generation:v.generation,lifetime_seconds:name==='renew'?3600:0,manifest_sha256:v.manifest.digest}})
 }
 return <><Heading eyebrow="Artifact exit"title="Hosted Go exports"description="Collect an immutable hosted Go version and its historical source policy. Downloads still check current access and policy."action={<button disabled={!fresh}onClick={()=>p.open('Create hosted Go export',<CreateExport {...p}/>)}>New hosted export</button>}/>
 <div className="view-toolbar"><Freshness at={data.at}loading={data.loading}/><button onClick={data.refresh}>Refresh exports</button><button onClick={()=>p.open('Journal export and external verification',<JournalExport {...p}/>)}>Journal and separate trust</button></div>
 <p>Each session preserves one version’s ZIP, go.mod, info and source decisions. Approve packages for the disconnected environment separately. Dependency closure, checksum-authority approval and destination permissions are separate requirements.</p>
 {data.loading&&<p role="status">Loading export sessions…</p>}{data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>}
 <Panel title="Retained export sessions">{data.data!==undefined&&!data.error&&(!shapeOK?<p role="alert"className="message error">The export list has invalid bindings. Refresh or inspect exact values through the API.</p>:rows.length?<div className="table-wrap"role="region"aria-label="Hosted Go export sessions"tabIndex={0}><table><thead><tr><th>Package / session</th><th>State / expiry</th><th>Manifest and actions</th></tr></thead><tbody>{rows.map((v,n)=>{if(!v||typeof v!=='object'||Array.isArray(v))return <tr key={'invalid-'+n}><td colSpan={3}><p role="alert"className="message error">This export record has invalid bindings. Refresh or use the API with exact values.</p></td></tr>;const valid=exact(v),active=v.state==='open'||v.state==='acknowledged';return <tr key={sourceText(v.id,'invalid-'+n,64)}><td><strong>{sourceText(v.module,'Invalid module')}@{sourceText(v.version,'Invalid version',128)}</strong><span className="block muted">{sourceText(v.repository,'Invalid repository',63)}</span><code className="break block">{sourceText(v.id,'Invalid export ID',64)}</code></td><td><strong>{sourceText(v.state,'Invalid state',64)}</strong><time className="block"dateTime={instant(v.expires_at)?v.expires_at:''}>{instant(v.expires_at)?new Date(v.expires_at).toLocaleString():'Unknown expiry'}</time><span className="small block">Package pins: {v.payload_pins_retained===true?'retained':v.payload_pins_retained===false?'released':'unknown'} · Manifest {v.manifest_retained===true?'retained':'unverified'}</span></td><td><code className="break block">{sourceText(v.manifest?.digest,'Invalid manifest binding',64)}</code>{!valid?<p role="alert"className="message error">This session exceeds exact console precision or has invalid bindings. Use the API and CLI with exact values.</p>:<><span className="small block">Generation {v.generation} · Creation event #{v.created_sequence}</span><div className="actions"><button disabled={!fresh}onClick={()=>p.open('Historical export receipt',<Json value={v}/>)}>Inspect session</button><button disabled={!fresh}onClick={()=>p.open('Publish signed export at a destination',<ImportInstructions session={v}/>)}>Destination import command</button>{active&&<><button disabled={!fresh}onClick={()=>p.open('Collect and verify hosted export',<><p>Refresh the session before resuming. Creation event #{v.created_sequence} must be inside the complete independently authenticated journal. The collector keeps interrupted private files for explicit resume and verifies every completed file. A local receipt does not grant destination access. Credentials and signing private keys stay outside the collection.</p><pre className="json">{commands(v)}</pre><Copy text={commands(v)}label="Copy export collection commands"/><Copy text={commands(v,true)}label="Copy resume collection command"/></>)}>Collection commands</button><button disabled={!fresh}onClick={()=>action(v,'renew')}>Renew</button><button disabled={!fresh}onClick={()=>action(v,'acknowledge')}>Acknowledge collection</button></>}{v.state==='expired_unreconciled'&&<button disabled={!fresh}onClick={()=>action(v,'expire')}>Reconcile expiry</button>}{v.payload_pins_retained&&<button disabled={!fresh}onClick={()=>action(v,'cancel')}>Cancel</button>}</div></>}</td></tr>})}</tbody></table></div>:<Empty title="No export sessions">Create a hosted export after publishing and approving the exact package version.</Empty>)}</Panel>
 {data.data&&!cursorOK&&<p role="alert"className="message error">The export cursor exceeds exact console precision. Continue through the API or CLI.</p>}<CursorPages after={after}next={fresh&&cursorOK&&data.data?.more?String(next):''}setAfter={setAfter}label="Export session pages"/>
 <p className="small muted">Expiry blocks serving. Pins remain until the terminal expiry transition commits; queue failure keeps them retained. Acknowledgment records your statement and does not certify external delivery.</p></>
}

function CreateExport(p:Common){
 const id=useId(),live=useRef(true);useEffect(()=>()=>{live.current=false},[]);
 const repos=useResource<{items:Repository[];more?:boolean}>(p.client,'/api/v1/repositories?limit=1000',p.revision);
 const [repo,setRepo]=useState(''),[module,setModule]=useState(''),[version,setVersion]=useState(''),[ttl,setTTL]=useState(900),[busy,setBusy]=useState(false),[error,setError]=useState(''),[preview,setPreview]=useState<{request:string;value:unknown}>();
 const selected=repos.data?.items.find(r=>r.name===repo&&r.format==='go'&&r.mode==='hosted');const valid=!!selected&&!repos.loading&&!repos.error&&integer(selected.source_revision)&&module.length>0&&module.length<=512&&version.length>0&&version.length<=128&&integer(ttl,60)&&ttl<=3600;
 const request={repository:repo,module,version,expected_source_revision:selected?.source_revision??-1,lifetime_seconds:ttl},fingerprint=JSON.stringify(request);
 async function inspect(e:FormEvent){e.preventDefault();if(!valid)return;setError('');setPreview(undefined);setBusy(true);try{const r=await p.client.request('/api/v1/go/exports/preview',{mutation:pending({method:'POST',path:'/api/v1/go/exports/preview',body:request})});if(live.current)setPreview({request:fingerprint,value:r.value})}catch(e){if(live.current)setError(e instanceof Error?e.message:'Unable to preview export.')}finally{if(live.current)setBusy(false)}}
 return <><p>Choose one published hosted Go version. The server captures all three representations and their source policy, verifies stored bytes and rechecks the snapshot before committing its manifest and references.</p>{repos.error&&<ErrorBox error={repos.error}retry={repos.refresh}/>} {repos.loading&&<p role="status">Loading hosted repositories…</p>}{repos.data?.more&&<p className="message warning">This repository page is incomplete. Use the API to select a repository beyond this page.</p>}
 <form onSubmit={inspect}><label htmlFor={id+'repo'}>Hosted Go repository</label><select id={id+'repo'}value={repo}onChange={e=>setRepo(e.target.value)}required><option value="">Choose a repository</option>{repos.data?.items.filter(r=>r.format==='go'&&r.mode==='hosted').map(r=><option key={r.name}value={r.name}>{r.name}</option>)}</select><label htmlFor={id+'module'}>Module path</label><input id={id+'module'}value={module}maxLength={512}required onChange={e=>setModule(e.target.value)}/><label htmlFor={id+'version'}>Canonical version</label><input id={id+'version'}value={version}maxLength={128}required onChange={e=>setVersion(e.target.value)}/><label htmlFor={id+'ttl'}>Initial lifetime in seconds</label><input id={id+'ttl'}type="number"min={60}max={3600}step={1}value={ttl}required onChange={e=>setTTL(Number(e.target.value))}/><button type="submit"disabled={!valid||busy}>{busy?'Previewing…':'Preview export'}</button></form>
 {error&&<p role="alert"className="message error">{error}</p>}{preview&&preview.request===fingerprint&&valid&&<><h3>Unsigned source snapshot preview</h3><Json value={preview.value}/><MutationForm client={p.client}label="Create export"build={()=>({method:'POST',path:'/api/v1/go/exports',body:request})}onDone={p.done}><p>Creation checks current state again and verifies physical bytes. The resulting manifest is historical source context; it does not grant destination access, checksum-authority trust or dependency closure. Collect its exact creation event through a complete externally signed journal.</p></MutationForm></>}</>
}

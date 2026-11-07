// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {pending} from './api';
import type {Repository} from './api';
import type {Common} from './view-types';
import {Copy,CursorPages,Empty,ErrorBox,Freshness,Heading,Json,MutationForm,Panel,useResource} from './components';
import {JournalExport} from './journal-export';

type Session={id:string;repository:string;module:string;version:string;source_revision:number;generation:number;created_sequence:number;change_sequence:number;state:string;manifest:{digest:string;size:number};expires_at:string;max_expires_at:string;server_time:string;delivery_verified:boolean;payload_pins_retained:boolean;manifest_retained:boolean};
const hash=(v:string)=>/^[a-f0-9]{64}$/.test(v);
const integer=(v:number,min=0)=>Number.isSafeInteger(v)&&v>=min;
function exact(v:Session){return hash(v.id)&&hash(v.manifest?.digest??'')&&integer(v.manifest?.size,1)&&v.manifest.size<=32768&&integer(v.source_revision)&&integer(v.generation,1)&&integer(v.created_sequence,1)&&integer(v.change_sequence,v.created_sequence)&&v.delivery_verified===false&&v.manifest_retained===true&&['open','acknowledged','cancelled','expired','expired_unreconciled'].includes(v.state)&&Number.isFinite(Date.parse(v.expires_at))&&Number.isFinite(Date.parse(v.server_time))}
const sh=(v:string)=>"'"+v.replace(/'/g,"'\\''")+"'";
function commands(v:Session){const base='/api/v1/go/exports/'+v.id;return `# Use a fresh directory and your private administrator client configuration.
# Downloads check this session generation and current policy on every request.
(
set -euC
umask 077
: "\${CRATECTL_CLIENT_CONFIG:?Set your private client JSON path}"
mkdir -m 700 ./cratectl-export-input
cratectl --config "$CRATECTL_CLIENT_CONFIG" --raw-response --response-limit 32768 \\
  --path ${sh(base+'/manifest?generation='+v.generation)} > ./cratectl-export-input/manifest.json
cratectl --config "$CRATECTL_CLIENT_CONFIG" --raw-response --response-limit 536870912 \\
  --path ${sh(base+'/zip?generation='+v.generation)} > ./cratectl-export-input/package.zip
cratectl --config "$CRATECTL_CLIENT_CONFIG" --raw-response --response-limit 1048576 \\
  --path ${sh(base+'/mod?generation='+v.generation)} > ./cratectl-export-input/package.mod
cratectl --config "$CRATECTL_CLIENT_CONFIG" --raw-response --response-limit 65536 \\
  --path ${sh(base+'/info?generation='+v.generation)} > ./cratectl-export-input/package.info
# Collect a complete journal through a checkpoint authenticated by your external
# signer, including export creation event ${v.created_sequence}. Keep its public key independently trusted.
: "\${CRATECTL_TRUSTED_TENANT:?Set the independently authenticated tenant}"
: "\${CRATECTL_TRUSTED_JOURNAL_SEQUENCE:?Set the authenticated terminal sequence}"
: "\${CRATECTL_TRUSTED_JOURNAL_HASH:?Set the authenticated terminal SHA-256}"
: "\${CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE:?Set the separately trusted public key path}"
cratectl go-module-offline --repository ${sh(v.repository)} --module ${sh(v.module)} --version ${sh(v.version)} \\
  --export-id ${sh(v.id)} --manifest-file ./cratectl-export-input/manifest.json \\
  --zip-file ./cratectl-export-input/package.zip --mod-file ./cratectl-export-input/package.mod \\
  --info-file ./cratectl-export-input/package.info --output-directory ./cratectl-export-input/offline \\
  --journal-file ./cratectl-journal.jsonl --journal-tenant "$CRATECTL_TRUSTED_TENANT" \\
  --journal-event-sequence ${v.created_sequence} --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \\
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" --checkpoint-file ./checkpoint.json \\
  --checkpoint-signature-file ./checkpoint.sig --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"
)`}

export function GoExports(p:Common){return p.identity.role==='admin'?<ExportAdmin {...p}/>:<><Heading eyebrow="Artifact exit"title="Hosted Go exports"description="Export exact package bytes with their historical source policy and journal context."/><p className="message warning"role="status">An administrator is required to export retained policy and journal context.</p></>}
function ExportAdmin(p:Common){
 const [after,setAfter]=useState('');const data=useResource<{items:Session[];more:boolean;next_after:number}>(p.client,'/api/v1/go/exports?limit=25'+(after?'&after='+encodeURIComponent(after):''),p.revision);
 const rows=data.data?.items??[],fresh=!data.loading&&!data.error;const next=data.data?.next_after??0;const cursorOK=integer(next)&&(!data.data?.more||rows.length>0&&next===(rows.at(-1)?.created_sequence??0)&&next>Number(after||0));
 function action(v:Session,name:'renew'|'acknowledge'|'cancel'|'expire'){
  p.run(name==='renew'?'Renew export':name==='cancel'?'Cancel export':name==='expire'?'Reconcile expiry':'Acknowledge collection',name==='acknowledge'?'Record that you collected this exact manifest. This is your acknowledgment, not independent delivery verification.':name==='cancel'?'Stop future downloads and release this session’s package pins. The historical manifest and journal remain retained.':name==='expire'?'Commit the expired session’s terminal state before releasing its package pins.':'Extend the current session by up to one hour within its original 24-hour window. This changes the generation; resume with the new value.',{method:'PATCH',path:'/api/v1/go/exports/'+v.id,body:{action:name,expected_generation:v.generation,lifetime_seconds:name==='renew'?3600:0,manifest_sha256:v.manifest.digest}})
 }
 return <><Heading eyebrow="Artifact exit"title="Hosted Go exports"description="Collect an immutable hosted Go version and its historical source policy. Downloads still check current access and policy."action={<button disabled={data.loading||!!data.error}onClick={()=>p.open('Create hosted Go export',<CreateExport {...p}/>)}>New hosted export</button>}/>
 <div className="view-toolbar"><Freshness at={data.at}loading={data.loading}/><button onClick={data.refresh}>Refresh exports</button><button onClick={()=>p.open('Journal export and external verification',<JournalExport {...p}/>)}>Journal and separate trust</button></div>
 <p>Each session preserves one version’s ZIP, go.mod, info and source decisions. Approve packages for the disconnected environment separately. Dependency closure, checksum-authority approval and destination permissions are separate requirements.</p>
 {data.loading&&<p role="status">Loading export sessions…</p>}{data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>}
 <Panel title="Retained export sessions">{data.data&&!data.error&&(rows.length?<div className="table-wrap"role="region"aria-label="Hosted Go export sessions"tabIndex={0}><table><thead><tr><th>Package / session</th><th>State / expiry</th><th>Manifest and actions</th></tr></thead><tbody>{rows.map(v=>{const valid=exact(v),active=v.state==='open'||v.state==='acknowledged';return <tr key={v.id}><td><strong>{v.module}@{v.version}</strong><span className="block muted">{v.repository}</span><code className="break block">{v.id}</code></td><td><strong>{v.state}</strong><time className="block"dateTime={v.expires_at}>{new Date(v.expires_at).toLocaleString()}</time><span className="small block">Package pins: {v.payload_pins_retained?'retained':'released'} · Manifest retained</span></td><td><code className="break block">{v.manifest?.digest??'Invalid manifest binding'}</code>{!valid?<p role="alert"className="message error">This session exceeds exact console precision or has invalid bindings. Use the API and CLI with exact values.</p>:<><span className="small block">Generation {v.generation} · Creation event #{v.created_sequence}</span><div className="actions"><button disabled={!fresh}onClick={()=>p.open('Historical export receipt',<Json value={v}/>)}>Inspect session</button>{active&&<><button disabled={!fresh}onClick={()=>p.open('Collect and verify hosted export',<><p>Refresh the session before resuming. Creation event #{v.created_sequence} must be inside the complete independently authenticated journal. These commands preserve existing local files and never export your credential.</p><pre className="json">{commands(v)}</pre><Copy text={commands(v)}label="Copy export collection commands"/></>)}>Collection commands</button><button disabled={!fresh}onClick={()=>action(v,'renew')}>Renew</button><button disabled={!fresh}onClick={()=>action(v,'acknowledge')}>Acknowledge collection</button></>}{v.state==='expired_unreconciled'&&<button disabled={!fresh}onClick={()=>action(v,'expire')}>Reconcile expiry</button>}{v.payload_pins_retained&&<button disabled={!fresh}onClick={()=>action(v,'cancel')}>Cancel</button>}</div></>}</td></tr>})}</tbody></table></div>:<Empty title="No export sessions">Create a hosted export after publishing and approving the exact package version.</Empty>)}</Panel>
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

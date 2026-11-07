// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {ApiError,pending} from './api';
import type {Common} from './view-types';
import {Details,ErrorBox,Freshness,MutationForm,useResource} from './components';

export type ChecksumState={blocked:boolean;legacy_review_required:boolean;checkpoint_sha256:string;checkpoint:{key_digest:string;revision:number}};
type Incident={sequence:number;event_hash:string;reviewed_for_key:boolean;created_at:string};
type Page={items:Incident[];more:boolean;next_after:number};
type Input={repository:string;dry_run:boolean;accept_unattributed_history:boolean;incident_hash:string;expected_source_revision:number;key_digest:string;expected_checkpoint_revision:number;checkpoint_sha256:string;review_reference_sha256:string;reason:string};
const exact=(n:number)=>Number.isSafeInteger(n)&&n>=0;
const digest=(v:string)=>/^[0-9a-f]{64}$/.test(v);

export function GoChecksumLegacy({repository,sourceRevision,authority,...p}:Common&{repository:string;sourceRevision:number;authority:ChecksumState}){
  const base='/api/v1/go/checksum/legacy-incidents',id=useId();
  const [after,setAfter]=useState(0),[selected,setSelected]=useState<Incident>(),[outcome,setOutcome]=useState(false),[reason,setReason]=useState(''),[reference,setReference]=useState(''),[snapshot,setSnapshot]=useState<{input:Input;preview:unknown}>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>();
  const live=useRef(true),controller=useRef(new AbortController());
  useEffect(()=>()=>{live.current=false;controller.current.abort()},[]);
  const valid=exact(sourceRevision)&&exact(authority.checkpoint.revision)&&digest(authority.checkpoint.key_digest)&&digest(authority.checkpoint_sha256);
  const page=useResource<Page>(p.client,valid?base+'?limit=25&after='+after+'&key_digest='+authority.checkpoint.key_digest:'',p.revision);
  const item=selected&&exact(selected.sequence)&&selected.sequence>0&&digest(selected.event_hash)?base+'/'+selected.sequence:'';
  const evidence=useResource<unknown>(p.client,item+(outcome?'/reviews?key_digest='+authority.checkpoint.key_digest:''),p.revision);
  const rows=!page.error?page.data?.items:undefined;
  const pagingSafe=!page.data?.more||exact(page.data.next_after)&&page.data.next_after>after;
  function choose(v:Incident,receipt:boolean){setSelected(v);setOutcome(receipt);setSnapshot(undefined);setReason('');setReference('');setError(undefined)}
  async function preview(e:FormEvent){
    e.preventDefault();if(!valid||!item||!selected||authority.blocked||busy||evidence.error||!evidence.data)return;
    const input:Input={repository,dry_run:false,accept_unattributed_history:true,incident_hash:selected.event_hash,expected_source_revision:sourceRevision,key_digest:authority.checkpoint.key_digest,expected_checkpoint_revision:authority.checkpoint.revision,checkpoint_sha256:authority.checkpoint_sha256,review_reference_sha256:reference,reason};
    setBusy(true);setError(undefined);
    try{const r=await p.client.request(item+'/reviews',{mutation:pending({method:'POST',path:item+'/reviews',body:{...input,dry_run:true,accept_unattributed_history:false}}),signal:controller.current.signal});if(live.current&&!p.client.closed)setSnapshot({input,preview:r.value})}
    catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{if(live.current&&!p.client.closed)setBusy(false)}
  }
  return <section aria-label="Unattributed checksum incident recovery"><h3>Unattributed checksum incidents</h3><p>An old fork label without original proof cannot identify a compromised key. It requires a separate external trust decision for each exact authority key in this tenant. Review preserves the incident, signed checkpoints and package policy. It cannot clear an authenticated fork or approve package bytes.</p>
    {!valid&&<p role="alert">The exact current source and checkpoint bindings are unavailable or exceed console precision. Use the API and CLI.</p>}
    <Freshness at={page.at}loading={page.loading}/>{page.error&&<ErrorBox error={page.error}retry={()=>{setSelected(undefined);setSnapshot(undefined);page.refresh()}}/>}
    {rows&&<>{!rows.length?<p>No retained unattributed incidents on this page. This does not establish authority health or package admission.</p>:<ul>{rows.map((v,n)=><li key={n}><p>Original journal sequence {v.sequence} · <code className="digest">{v.event_hash}</code> · {v.reviewed_for_key?'Reviewed for this exact key':'External trust review required'}</p><button disabled={!exact(v.sequence)||v.sequence<=0||!digest(v.event_hash)}onClick={()=>choose(v,false)}>Inspect legacy incident {v.sequence}</button>{v.reviewed_for_key&&<button onClick={()=>choose(v,true)}>Read retained review {v.sequence}</button>}</li>)}</ul>}
      {!pagingSafe&&<p role="alert">The legacy journal cursor cannot be represented exactly or did not advance. Use the API and CLI.</p>}<nav className="pagination"aria-label="Legacy checksum incident pages"><button disabled={page.loading||after===0}onClick={()=>{setAfter(0);setSelected(undefined);setSnapshot(undefined)}}>First legacy page</button><button disabled={page.loading||!page.data?.more||!pagingSafe}onClick={()=>{setAfter(page.data!.next_after);setSelected(undefined);setSnapshot(undefined)}}>Next legacy page</button></nav></>}
    {selected&&!page.error&&<><h4>{outcome?'Retained external trust review':'Original incident context'}</h4>{evidence.error&&<ErrorBox error={evidence.error}retry={evidence.refresh}/>}{!evidence.error&&evidence.data!==undefined&&<><Details title={outcome?'Historical review and signed checkpoint':'Original event and local hash link'}value={evidence.data}/><p>The local hash link is not an independent journal anchor. The old label remains unattributed. Retained review receipts describe a historical decision and do not report current key usability.</p>
      {!outcome&&!selected.reviewed_for_key&&(authority.blocked?<p role="alert">This key has an authenticated fork. External review cannot unblock it. Select a separately trusted authority through repository configuration.</p>:!snapshot?<form onSubmit={preview}><fieldset disabled={busy}><label htmlFor={id+'-reference'}>SHA-256 of separate external trust review</label><input id={id+'-reference'}required pattern="[0-9a-f]{64}"maxLength={64}value={reference}onChange={e=>setReference(e.target.value)}/><label htmlFor={id+'-reason'}>External trust decision reason</label><textarea id={id+'-reason'}required maxLength={1024}value={reason}onChange={e=>setReason(e.target.value)}/><button type="submit">{busy?'Reading review impact…':'Preview external trust review'}</button></fieldset></form>:<><Details title="Exact external trust review preview"value={snapshot.preview}/><p>This records one incident/key decision. Every other unresolved incident still requires review. Package retrieval must subsequently revalidate bytes and satisfy current policy.</p><MutationForm client={p.client}label="Record external trust review"onDone={p.done}retainRequest build={()=>({method:'POST',path:item+'/reviews',body:snapshot.input})}><label><input type="checkbox"required/>I explicitly accept that the old incident lacks original proof and trust this exact external key on the basis of the separate review.</label></MutationForm><button onClick={()=>{setSnapshot(undefined);setError(undefined)}}>Edit external review and preview again</button></>)}</>}
    </>}{error&&<ErrorBox error={error}retry={()=>{setError(undefined);setSnapshot(undefined);evidence.refresh()}}/>}
  </section>;
}

// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {ApiError,pending} from './api';
import type {Page} from './api';
import type {Common} from './view-types';
import {Badge,CursorPages,Details,Empty,ErrorBox,MutationForm,Panel,useResource} from './components';

type Case={repository:string;path:string;digest:string;case_id:string;revision:number;held:boolean;released:boolean;hold_reason?:string;hold_until?:string;reason?:string;actor?:string;created_sequence:number;change_sequence:number};
type Record=Case&{status:string;repository_state:string};
type Preview={case:Case;current:{held:boolean;legacy_held:boolean;case_held:boolean;revision:number};action:string};
type Snapshot={input:{path:string;digest:string;action:string;expected_revision:number;reason:string;hold_until?:string;dry_run:boolean};preview:Preview};
type Change={sequence:number;action:string;case:Case;current:Preview['current'];actor:string;recorded_at:string;event_hash:string};

export function HoldCases(p:Common){
 const [state,setState]=useState('active'),[query,setQuery]=useState(''),[repository,setRepository]=useState(''),[filters,setFilters]=useState({q:'',repository:''}),[cursor,setCursor]=useState('');
 const params=new URLSearchParams({state,limit:'100',...filters,...(cursor?{cursor}:{})});
 const data=useResource<Page<Record>&{observed_at:string}>(p.client,'/api/v1/hold-cases?'+params,p.revision);
 return <Panel title="Independent hold cases"action={<button onClick={()=>p.open('Place independent hold case',<CaseLocator {...p}/>)}>Place independent hold</button>}>
  <p>Each named case protects one exact reference. Releasing a case preserves every other active case and the original hold slot. An expired case remains in history. Case names are scoped to each repository and reference.</p>
  <form className="hold-filters"onSubmit={e=>{e.preventDefault();setFilters({q:query,repository});setCursor('')}}>
   <label>Case state<select value={state}onChange={e=>{setState(e.target.value);setCursor('')}}><option value="active">Active cases</option><option value="expired">Expired cases</option><option value="released">Released cases</option><option value="all">All cases</option></select></label>
   <label>Case repository (optional)<input value={repository}maxLength={63}pattern="[a-z][a-z0-9-]{0,62}"onChange={e=>setRepository(e.target.value)}/></label>
   <label>Search case names, references or reasons<input type="search"value={query}maxLength={256}onChange={e=>setQuery(e.target.value)}/></label><button type="submit">Search cases</button>
  </form>
  <button onClick={data.refresh}>Refresh cases</button>{data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>} {data.loading&&<p role="status">Loading independent cases…</p>}
  {data.data&&<><p className="small muted">Observed <time dateTime={data.data.observed_at}>{new Date(data.data.observed_at).toLocaleString()}</time>. Refresh before changing a case; expiry and concurrent changes can alter later pages.</p>
   {!data.data.items.length?<Empty title="No matching hold cases">Place a case using its repository and canonical digest path, or change the case state and filters.</Empty>:<div className="table-wrap"role="region"aria-label="Independent hold case records"tabIndex={0}><table><thead><tr><th>Case / exact reference</th><th>Status</th><th>Preservation reason / expiry</th><th>Actions</th></tr></thead><tbody>{data.data.items.map(c=><tr key={c.repository+'\n'+c.path+'\n'+c.case_id}>
    <td><strong>{c.case_id}</strong><span className="block">{c.repository} · repository {c.repository_state}</span><code className="break block">{c.path}</code></td><td><Badge value={c.status}/></td><td>{c.hold_reason}<span className="small muted block">{c.hold_until?new Date(c.hold_until).toLocaleString():'No expiry; administrator release required'}</span></td><td><button onClick={()=>p.open('Manage case · '+c.case_id,<HoldCaseEditor {...p}repository={c.repository}path={c.path}caseID={c.case_id}/>)}>Manage case</button><button onClick={()=>p.open('Case history · '+c.case_id,<CaseHistory {...p}repository={c.repository}path={c.path}caseID={c.case_id}/>)}>Inspect case history</button></td>
   </tr>)}</tbody></table></div>}<CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Hold case pages"/>
  </>}
 </Panel>
}
function CaseLocator(p:Common){
 const [repository,setRepository]=useState(''),[path,setPath]=useState(''),[id,setID]=useState('');
 return <form onSubmit={e=>{e.preventDefault();p.open('Manage case · '+id,<HoldCaseEditor {...p}repository={repository}path={path}caseID={id}/>)}}>
  <p>Use the exact canonical OCI manifest or blob path shown in the package inventory. The server reads its digest and current case revision before preview.</p>
  <label>Repository<input required value={repository}maxLength={63}pattern="[a-z][a-z0-9-]{0,62}"onChange={e=>setRepository(e.target.value)}/></label>
  <label>Canonical reference path<input required value={path}maxLength={2048}onChange={e=>setPath(e.target.value)}/></label>
  <label>Case name<input required value={id}maxLength={63}pattern="[a-z][a-z0-9-]{0,62}"onChange={e=>setID(e.target.value)}/></label><p className="small muted">Start with a lowercase letter; use lowercase letters, digits and hyphens. The name legacy is reserved.</p>
  <button className="primary"type="submit">Read case and reference</button>
 </form>
}
export function HoldCaseEditor({repository,path,caseID,...p}:Common&{repository:string;path:string;caseID:string}){
 const endpoint=`/api/v1/repositories/${encodeURIComponent(repository)}/artifacts/holds/${encodeURIComponent(caseID)}`;
 const current=useResource<Case>(p.client,endpoint+'?'+new URLSearchParams({path}),p.revision);
 const id=useId(),[action,setAction]=useState(''),[reason,setReason]=useState(''),[until,setUntil]=useState(''),[snapshot,setSnapshot]=useState<Snapshot>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>();
 const live=useRef(true),controller=useRef(new AbortController());useEffect(()=>()=>{live.current=false;controller.current.abort()},[]);
 const c=current.data,chosen=action||(c&&c.revision>0&&!c.released?'release_hold':'hold');
 async function preview(e:FormEvent){
  e.preventDefault();if(!c||!Number.isSafeInteger(c.revision))return;
  const input={path,digest:c.digest,action:chosen,expected_revision:c.revision,reason,...(chosen==='hold'&&until?{hold_until:new Date(until).toISOString()}:{}),dry_run:false};
  setBusy(true);setError(undefined);
  try{const response=await p.client.request<Preview>(endpoint,{mutation:pending({method:'PUT',path:endpoint,body:{...input,dry_run:true}}),signal:controller.current.signal});if(live.current&&!p.client.closed)setSnapshot({input,preview:response.value})}
  catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{if(live.current&&!p.client.closed)setBusy(false)}
 }
 return <><p><strong>{caseID}</strong> · {repository}<code className="break block">{path}</code></p><p>Only this named case will change. Other cases and the original hold remain in force. Downloads still follow repository and security policy.</p>
  {current.error&&<ErrorBox error={current.error}retry={current.refresh}/>}<p role="status">{current.loading?'Reading current case…':c?!Number.isSafeInteger(c.revision)?'Case revision exceeds exact console precision. Use the CLI or API to inspect and change this case.':c.revision===0?'This is a new case.':`Case revision ${c.revision}: ${c.released?'released':c.held?'active':'expired'}.`:''}</p>{c&&<Details title="Current case record"value={c}/>}
  {!snapshot?<form onSubmit={e=>void preview(e)}><fieldset disabled={busy||current.loading||!!current.error||!c||!Number.isSafeInteger(c.revision)}>
   <label htmlFor={id+'-action'}>Case action</label><select id={id+'-action'}value={chosen}onChange={e=>setAction(e.target.value)}><option value="hold">Place or update this case hold</option>{!!c?.revision&&!c.released&&<option value="release_hold">Release this case hold</option>}</select>
   <label htmlFor={id+'-reason'}>Case change reason</label><input id={id+'-reason'}required maxLength={1024}value={reason}onChange={e=>setReason(e.target.value)}/>
   {chosen==='hold'&&<><label htmlFor={id+'-until'}>Case expiry (optional, local time)</label><input id={id+'-until'}type="datetime-local"value={until}onChange={e=>setUntil(e.target.value)}/></>}
   <button className="primary"type="submit">{busy?'Reading case impact…':'Preview case change'}</button>
  </fieldset></form>:<><div className="message"role="status"><p>Previewed case revision {snapshot.preview.case.revision}. The reference is currently {snapshot.preview.current.held?'protected by at least one active hold':'without an active hold'}.</p><p>Releasing this case removes only its protection. Another active case or the original hold will continue to block deletion and restore. No bytes are erased.</p></div>
   <MutationForm client={p.client}label="Apply case change"onDone={p.done}build={()=>({method:'PUT',path:endpoint,body:snapshot.input})}><p>Apply {snapshot.input.action==='hold'?'hold placement':'release'} to {caseID} using its own revision {snapshot.input.expected_revision}. A concurrent change to this case rejects the request.</p></MutationForm>
   <button onClick={()=>{setSnapshot(undefined);setError(undefined);current.refresh()}}>Change case preview</button></>}
  {error&&<ErrorBox error={error}retry={()=>{setError(undefined);current.refresh()}}/>}
 </>
}
function CaseHistory({repository,path,caseID,...p}:Common&{repository:string;path:string;caseID:string}){
 const [cursor,setCursor]=useState(''),params=new URLSearchParams({path,limit:'100',...(cursor?{cursor}:{})});
 const data=useResource<Page<Change>>(p.client,`/api/v1/repositories/${encodeURIComponent(repository)}/artifacts/holds/${encodeURIComponent(caseID)}/history?`+params,p.revision);
 return <section><p><strong>{caseID}</strong> · {repository}<code className="break block">{path}</code></p><p>Original case receipts preserve the case and aggregate reference state at each change. Expiry adds no release event. These filtered receipts identify events in the full audit export.</p><button onClick={data.refresh}>Refresh case history</button>
  {data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>} {data.loading&&<p role="status">Loading case receipts…</p>}
  {data.data&&<>{!data.data.items.length?<Empty title="No case receipts recorded">This reference has no recorded change for this named case.</Empty>:<ol className="observation-list">{data.data.items.map(v=><li key={v.event_hash}><strong>{v.action==='hold'?'Case hold placed':'Case hold released'}</strong> by {v.actor} · <time dateTime={v.recorded_at}>{new Date(v.recorded_at).toLocaleString()}</time><p>{v.case.reason}</p><p>The reference {v.current.held?'remained protected':'had no active hold'} at this change.</p><Details title="Original case journal snapshot"value={v}/></li>)}</ol>}<CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Case history pages"/></>}
 </section>
}

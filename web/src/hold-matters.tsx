// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {ApiError,pending} from './api';
import type {Job,Page} from './api';
import type {Common} from './view-types';
import {Badge,CursorPages,Details,Empty,ErrorBox,LocalPages,MutationForm,Panel,useResource} from './components';

type Matter={name:string;revision:number;state:string;title:string;reason:string};
type Member={repository:string;path:string;digest:string;revision:number;status:string;reason:string;hold_reason:string;hold_until?:string;repository_state:string;deleted:boolean;created_sequence:number};
type Target={ordinal:number;repository:string;path:string;digest:string;revision:number;status:string;lifecycle_revision:number;effective_held:boolean};
type Plan={matter:Matter;action:string;reason:string;hold_until?:string;requester:string;evaluated_at:string;expires_at:string;target_count:number;targets?:Target[];preview_digest:string};
type Operation={sequence:number;matter:string;revision:number;state:string;plan:Plan;requester:string;approver?:string;job?:string};
type Outcome=Target&{outcome:string;member_revision:number;effective_held_after?:boolean};
type OperationDetail={operation:Operation;job?:Job;processed:number;effected:number;skipped:number;remaining:number;all_targets_processed?:boolean};
type Change={sequence:number;kind:string;actor:string;event_hash:string;recorded_at:string;data:unknown};
const matterPath=(name:string)=>'/api/v1/hold-matters/'+encodeURIComponent(name);
const precise=(v:Target)=>[v.ordinal,v.revision,v.lifecycle_revision].every(Number.isSafeInteger);
const integer=(v:number)=>Number.isSafeInteger(v)?String(v):'Use the API for the exact integer';

export function HoldMatters(p:Common){
 const [q,setQ]=useState(''),[query,setQuery]=useState(''),[cursor,setCursor]=useState('');
 const data=useResource<Page<Matter>>(p.client,'/api/v1/hold-matters?'+new URLSearchParams({limit:'100',q:query,...(cursor?{cursor}:{})}),p.revision);
 return <Panel title="Cross-reference hold matters"action={<button onClick={()=>p.open('Create hold matter',<MatterEditor {...p}/>)}>Create matter</button>}>
  <p>One matter preserves exact OCI references across repositories. Other matters, independent cases and the original hold remain separate protections. Releasing matter members requires a different current administrator's approval.</p>
  <form className="hold-filters"onSubmit={e=>{e.preventDefault();setQuery(q);setCursor('')}}><label>Search matters<input type="search"value={q}maxLength={256}onChange={e=>setQ(e.target.value)}/></label><button type="submit">Search matters</button></form><button onClick={data.refresh}>Refresh matters</button>
  {data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>} {data.loading&&<p role="status">Loading matters…</p>}
  {data.data&&<>{!data.data.items.length?<Empty title="No matching matters">Create a matter to preserve references for one investigation, or change the search.</Empty>:<ul className="observation-list">{data.data.items.map(m=><li key={m.name}><strong>{m.title}</strong> · {m.name} <Badge value={m.state}/><p>{m.reason}</p><button onClick={()=>p.open('Matter · '+m.name,<MatterDetail {...p}name={m.name}/>)}>Inspect matter</button></li>)}</ul>}<CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Matter pages"/></>}
 </Panel>
}
function MatterEditor({matter,...p}:Common&{matter?:Matter}){
 const [name,setName]=useState(matter?.name??''),[title,setTitle]=useState(matter?.title??''),[reason,setReason]=useState(''),[state,setState]=useState(matter?.state??'open');
 return <><p>A matter records the investigation's purpose. Each membership keeps its own immutable reference and revision. Closing requires all memberships to be released and all work to be terminal. Editing metadata invalidates pending previews and work.</p>
  <MutationForm client={p.client}label={matter?'Save matter metadata':'Create matter'}onDone={p.done}build={()=>({method:'PUT',path:matterPath(name),body:{expected_revision:matter?.revision??0,title,reason,state}})}>
   <label>Matter name<input required disabled={!!matter}value={name}pattern="[a-z][a-z0-9-]{0,62}"maxLength={63}onChange={e=>setName(e.target.value)}/></label>
   <label>Matter title<input required value={title}maxLength={256}onChange={e=>setTitle(e.target.value)}/></label>
   <label>Matter metadata reason<input required value={reason}maxLength={1024}onChange={e=>setReason(e.target.value)}/></label>
   {matter&&<label>Matter state<select value={state}onChange={e=>setState(e.target.value)}><option value="open">Open</option><option value="closed">Closed</option></select></label>}
  </MutationForm>
 </>
}
function MatterDetail({name,...p}:Common&{name:string}){
 const data=useResource<Matter>(p.client,matterPath(name),p.revision),[tab,setTab]=useState('members');
 return <><button onClick={data.refresh}>Refresh matter</button>{data.error&&<ErrorBox error={data.error}retry={data.refresh}/>}{data.loading&&<p role="status">Loading matter…</p>}
  {data.data&&<><h3>{data.data.title}</h3><p>{data.data.reason} · <Badge value={data.data.state}/></p><p>Metadata revision {integer(data.data.revision)}.</p>
   {Number.isSafeInteger(data.data.revision)&&<button onClick={()=>p.open('Edit matter · '+name,<MatterEditor {...p}matter={data.data}/>)}>Edit matter</button>}
   {data.data.state==='open'&&<button onClick={()=>p.open('Review matter targets · '+name,<MatterComposer {...p}name={name}/>)}>Preview membership change</button>}
   <label>Matter records<select value={tab}onChange={e=>setTab(e.target.value)}><option value="members">Members</option><option value="operations">Operations and approvals</option><option value="history">Journal history</option></select></label>
   {tab==='members'?<MatterMembers {...p}name={name}/>:tab==='operations'?<MatterOperations {...p}name={name}/>:<MatterHistory {...p}name={name}/>}
  </>}
 </>
}
function MatterMembers({name,...p}:Common&{name:string}){
 const [cursor,setCursor]=useState(''),[state,setState]=useState('active');
 const data=useResource<Page<Member>&{observed_at:string}>(p.client,matterPath(name)+'/members?'+new URLSearchParams({state,limit:'100',...(cursor?{cursor}:{})}),p.revision);
 return <><label>Membership state<select value={state}onChange={e=>{setState(e.target.value);setCursor('')}}><option value="active">Active</option><option value="expired">Expired</option><option value="released">Released</option><option value="all">All</option></select></label><button onClick={data.refresh}>Refresh memberships</button>
  {data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>} {data.loading&&<p role="status">Loading memberships…</p>}
  {data.data&&<><p>Observed <time dateTime={data.data.observed_at}>{new Date(data.data.observed_at).toLocaleString()}</time>. Expiry may change later observations.</p>{!data.data.items.length?<Empty title="No matching memberships">Preview an explicit reference list to place a hold, or inspect expired and released records.</Empty>:<ul className="observation-list">{data.data.items.map(m=><li key={m.repository+'\n'+m.path}><strong>{m.repository}</strong> <Badge value={m.status}/><code className="break block">{m.path}</code><p>{m.hold_reason} · {m.hold_until?new Date(m.hold_until).toLocaleString():'No expiry'}</p><p>Member revision {integer(m.revision)} · repository {m.repository_state}{m.deleted?' · retained deleted reference':''}.</p></li>)}</ul>}<CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Matter membership pages"/></>}
 </>
}
function TargetTable({items}:{items:Target[]}){
 return <div className="table-wrap"role="region"aria-label="Exact matter target manifest"tabIndex={0}><table><thead><tr><th>Ordinal / reference</th><th>Member revision</th><th>Reviewed state</th></tr></thead><tbody>{items.map(v=><tr key={v.ordinal}><td>{integer(v.ordinal)} · {v.repository}<code className="break block">{v.path}</code><code className="break block">sha256:{v.digest}</code></td><td>{integer(v.revision)}</td><td>{v.status} · aggregate {v.effective_held?'held':'unheld'}<span className="block">Lifecycle revision {integer(v.lifecycle_revision)}</span></td></tr>)}</tbody></table></div>
}
function MatterComposer({name,...p}:Common&{name:string}){
 const [action,setAction]=useState('hold'),[reason,setReason]=useState(''),[until,setUntil]=useState(''),[text,setText]=useState(''),[plan,setPlan]=useState<Plan>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>(),[reviewed,setReviewed]=useState(false);
 const live=useRef(true),controller=useRef(new AbortController());useEffect(()=>()=>{live.current=false;controller.current.abort()},[]);
 async function preview(e:FormEvent){
  e.preventDefault();setError(undefined);setBusy(true);
  try{
   const lines=text.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
   if(!lines.length||lines.length>10000)throw new ApiError(400,'target_limit','Supply 1–10,000 explicit references; the server may set a smaller resource budget.');
   const targets=lines.map(line=>{const fields=line.split(/\s+/);if(fields.length!==2)throw new ApiError(400,'target_coordinates','Use one repository, a space and its canonical reference path on each line.');return {repository:fields[0],path:fields[1]}});
   const endpoint=matterPath(name)+'/operations/preview';
   const response=await p.client.request<Plan>(endpoint,{mutation:pending({method:'POST',path:endpoint,body:{action,reason,targets,...(action==='hold'&&until?{hold_until:new Date(until).toISOString()}:{})}}),signal:controller.current.signal});
   if(live.current&&!p.client.closed){setPlan(response.value);setReviewed(false)}
  }catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{if(live.current&&!p.client.closed)setBusy(false)}
 }
 const exact=plan&&Number.isSafeInteger(plan.matter.revision)&&Number.isSafeInteger(plan.target_count)&&plan.target_count===plan.targets?.length&&plan.targets.every(precise);
 return <><p>Supply every intended canonical OCI reference explicitly. A preview covers this complete bounded list. Placement admits work; release creates a proposal for independent approval. No bytes are erased.</p>
  {!plan?<form onSubmit={e=>void preview(e)}><fieldset disabled={busy}>
   <label>Membership action<select value={action}onChange={e=>setAction(e.target.value)}><option value="hold">Place or refresh matter holds</option><option value="release_hold">Request release of matter holds</option></select></label>
   <label>Membership change reason<input required value={reason}maxLength={1024}onChange={e=>setReason(e.target.value)}/></label>
   {action==='hold'&&<label>Matter hold expiry (optional, local time)<input type="datetime-local"value={until}onChange={e=>setUntil(e.target.value)}/></label>}
   <label>Complete target list<textarea required value={text}maxLength={2*1024*1024}rows={8}placeholder="repository app/manifests/sha256:…"onChange={e=>setText(e.target.value)}/></label>
   <button className="primary"type="submit">{busy?'Reading complete manifest…':'Preview complete manifest'}</button>
  </fieldset></form>:<><p>{plan.target_count} targets · {plan.action==='hold'?'Hold placement':'Release proposal'} · expires <time dateTime={plan.expires_at}>{new Date(plan.expires_at).toLocaleString()}</time>.</p><p>{plan.reason}</p><code className="break block">Preview digest: {plan.preview_digest}</code>
   <LocalPages items={plan.targets??[]}label="Preview target pages">{items=><TargetTable items={items}/>}</LocalPages>
   {exact?<><label><input type="checkbox"checked={reviewed}onChange={e=>setReviewed(e.target.checked)}/>I reviewed the complete target list, reason and expiry.</label>{reviewed&&<MutationForm client={p.client}label={plan.action==='hold'?'Admit matter placement':'Request independent release approval'}onDone={p.done}build={()=>({method:'POST',path:matterPath(name)+'/operations',body:plan})}><p>The server checks the exact manifest and every current membership revision again. Later members remain outside this operation.</p></MutationForm>}</>:<p role="alert">The manifest contains an integer outside exact console precision or is incomplete. Use the CLI/API to review and submit the exact bytes.</p>}
   <button onClick={()=>{setPlan(undefined);setReviewed(false)}}>Discard preview and edit</button>
  </>}{error&&<ErrorBox error={error}retry={()=>setError(undefined)}/>}</>
}
function MatterOperations({name,...p}:Common&{name:string}){
 const [cursor,setCursor]=useState('');const data=useResource<Page<Operation>>(p.client,matterPath(name)+'/operations?'+new URLSearchParams({limit:'100',...(cursor?{cursor}:{})}),p.revision);
 return <><button onClick={data.refresh}>Refresh matter operations</button>{data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>} {data.loading&&<p role="status">Loading operations…</p>}
  {data.data&&<>{!data.data.items.length?<Empty title="No matter operations">Preview an explicit target list to place holds or request a reviewed release.</Empty>:<ul className="observation-list">{data.data.items.map(o=><li key={o.sequence}><strong>{integer(o.sequence)} · {o.plan.action==='hold'?'Placement':'Release'}</strong> <Badge value={o.state}/><p>{o.plan.target_count} targets · requested by {o.requester}{o.approver?' · approved by '+o.approver:''}.</p>{Number.isSafeInteger(o.sequence)&&<button onClick={()=>p.open('Matter operation · '+o.sequence,<MatterOperation {...p}name={name}sequence={o.sequence}/>)}>Inspect operation and targets</button>}</li>)}</ul>}<CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Matter operation pages"/></>}
 </>
}
function MatterOperation({name,sequence,...p}:Common&{name:string;sequence:number}){
 const endpoint=matterPath(name)+'/operations/'+sequence,data=useResource<OperationDetail>(p.client,endpoint,p.revision);
 const [cursor,setCursor]=useState(''),[reviewed,setReviewed]=useState<Set<number>>(new Set()),[reason,setReason]=useState('');
 const targets=useResource<Page<Outcome>>(p.client,endpoint+'/items?'+new URLSearchParams({limit:'100',...(cursor?{cursor}:{})}),p.revision);
 const o=data.data?.operation,rows=targets.data?.items??[],allReviewed=!!o&&reviewed.size===o.plan.target_count;
 const safe=!!o&&!data.loading&&!data.error&&!targets.loading&&!targets.error&&[o.sequence,o.revision,o.plan.target_count,o.plan.matter.revision].every(Number.isSafeInteger)&&rows.every(precise);
 const waiting=o?.state==='awaiting_approval',self=o?.requester===p.identity.actor;
 return <><button onClick={()=>{data.refresh();targets.refresh()}}>Refresh operation and outcomes</button>{data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>} {data.loading&&<p role="status">Loading operation…</p>}
  {data.data&&o&&<><p><Badge value={o.state}/> · {o.plan.action==='hold'?'Placement':'Release'} · requested by {o.requester}{o.approver?' · approved by '+o.approver:''}.</p><p>{o.plan.reason}</p><p>Authority and deadline are rechecked for every target. Deadline: <time dateTime={o.plan.expires_at}>{new Date(o.plan.expires_at).toLocaleString()}</time>.</p><code className="break block">Preview digest: {o.plan.preview_digest}</code>
   <p role="status">Processed {integer(data.data.processed)} of {integer(o.plan.target_count)}; changed {integer(data.data.effected)}, skipped {integer(data.data.skipped)}, remaining {integer(data.data.remaining)}.{data.data.job?' Job: '+data.data.job.state+'.':''}</p>
   {data.data.job&&<><p>Cancellation preserves committed results. Retry resumes this immutable intent with its original authorities. Revoked authority, changed metadata or expiry requires a fresh proposal for remaining targets.</p><Details title="Durable matter job"value={data.data.job}/>{o.job&&<button disabled={data.loading||!!data.error||['succeeded','failed','cancelled','uncertain'].includes(data.data.job.state)}onClick={()=>p.run('Cancel matter work','Already committed target effects remain. Refresh this operation to inspect partial outcomes.',{method:'POST',path:'/api/v1/jobs/'+encodeURIComponent(o.job!)+'/cancel',body:{}})}>Cancel matter work</button>}{o.job&&['failed','cancelled'].includes(data.data.job.state)&&<button onClick={()=>p.run('Retry same matter intent','Original requester, approver and deadline still apply. No completed target is repeated.',{method:'POST',path:'/api/v1/jobs/'+encodeURIComponent(o.job!)+'/retry',body:{}})}>Retry same matter intent</button>}</>}
   {waiting&&<p>{self?'You requested this release. Another current administrator must inspect and approve the complete manifest.':'Review and acknowledge every immutable target page before approving this release.'}</p>}
  </>}
  {targets.error&&<ErrorBox error={targets.error}retry={targets.refresh}stale={!!targets.data}/>} {targets.loading&&<p role="status">Loading exact targets and outcomes…</p>}
  {targets.data&&<><TargetTable items={rows}/><ul className="observation-list">{rows.map(v=><li key={v.ordinal}>Target {integer(v.ordinal)}: <Badge value={v.outcome}/>{v.outcome!=='pending'&&<> · resulting member revision {integer(v.member_revision)} · reference {v.effective_held_after?'remained held':'had no active hold'} at this observation.</>}</li>)}</ul>
   {waiting&&!self&&safe&&<label><input type="checkbox"checked={rows.length>0&&rows.every(v=>reviewed.has(v.ordinal))}onChange={e=>{const next=new Set(reviewed);for(const v of rows){if(e.target.checked)next.add(v.ordinal);else next.delete(v.ordinal)}setReviewed(next)}}/>I reviewed this page of immutable targets ({reviewed.size} reviewed in total).</label>}
   <CursorPages after={cursor}next={targets.data.next}setAfter={setCursor}label="Immutable matter target pages"/>
  </>}
  {waiting&&safe&&<><label>Proposal review reason<input required maxLength={1024}value={reason}onChange={e=>setReason(e.target.value)}/></label>{!self&&allReviewed&&reason.trim()&&<MutationForm client={p.client}label="Approve exact release manifest"onDone={p.done}build={()=>({method:'POST',path:endpoint+'/approve',body:{expected_revision:o!.revision,preview_digest:o!.plan.preview_digest,reason}})}><p>Approve all {o!.plan.target_count} targets as the independent administrator. Both authorities must remain current during execution.</p></MutationForm>}{reason.trim()&&<MutationForm client={p.client}label="Cancel pending proposal"onDone={p.done}build={()=>({method:'POST',path:endpoint+'/cancel',body:{expected_revision:o!.revision,preview_digest:o!.plan.preview_digest,reason}})}><p>Cancel this proposal before any release job is admitted. Existing protections stay in place.</p></MutationForm>}</>}
  {o&&!safe&&<p role="alert">Use the CLI/API for exact large integers before changing this operation.</p>}
 </>
}
function MatterHistory({name,...p}:Common&{name:string}){
 const [cursor,setCursor]=useState(''),data=useResource<Page<Change>>(p.client,matterPath(name)+'/history?'+new URLSearchParams({limit:'100',...(cursor?{cursor}:{})}),p.revision);
 return <><p>These original matter events retain the observed state. Expiry changes current protection without rewriting a receipt. This filtered view is part of the full audit chain.</p><button onClick={data.refresh}>Refresh matter history</button>{data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>} {data.loading&&<p role="status">Loading matter history…</p>}{data.data&&<>{!data.data.items.length?<Empty title="No matter history">No matter event is recorded.</Empty>:<ol className="observation-list">{data.data.items.map(v=><li key={v.event_hash}><strong>{v.kind}</strong> by {v.actor} · <time dateTime={v.recorded_at}>{new Date(v.recorded_at).toLocaleString()}</time><Details title="Original matter receipt"value={v}/></li>)}</ol>}<CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Matter history pages"/></>}</>
}

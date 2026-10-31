// SPDX-License-Identifier: BUSL-1.1
import {useState} from 'react';
import type {Page} from './api';
import type {Common} from './view-types';
import {Badge,CursorPages,Details,Empty,ErrorBox,Freshness,Panel,useResource} from './components';
import {Lifecycle} from './lifecycle';

type HoldState={repository:string;path:string;digest:string;revision:number;held:boolean;deleted:boolean;hold_reason?:string;hold_until?:string;reason:string;actor:string;changed_at:string;change_sequence:number};
type Hold=HoldState&{status:'active'|'expired'|'released';repository_state:string;format:string;mode:string};
type Change={sequence:number;action:'hold'|'release_hold';state:HoldState;actor:string;recorded_at:string;event_hash:string};
function moment(value?:string){return value?<time dateTime={value}>{new Date(value).toLocaleString()}</time>:'No expiry; administrator release required'}

export function Holds(p:Common){
 const [state,setState]=useState('active'),[query,setQuery]=useState(''),[repository,setRepository]=useState(''),[filters,setFilters]=useState({q:'',repository:''}),[cursor,setCursor]=useState('');
 const params=new URLSearchParams({state,limit:'100',...filters,...(cursor?{cursor}:{})});
 const data=useResource<Page<Hold>&{observed_at:string}>(p.client,'/api/v1/holds?'+params,p.revision);
 return <Panel title="Reference holds" action={<button onClick={data.refresh}>Refresh holds</button>}>
  <p className="panel-copy">A hold protects an exact retained reference from deletion. Releasing a hold retains its history and bytes. Place a new hold from the package's Lifecycle action.</p>
  <form className="hold-filters" onSubmit={e=>{e.preventDefault();setFilters({q:query,repository});setCursor('')}}>
   <label>Hold state<select value={state}onChange={e=>{setState(e.target.value);setCursor('')}}><option value="active">Active holds</option><option value="expired">Expired holds</option><option value="released">Released holds</option><option value="all">All hold records</option></select></label>
   <label>Exact repository (optional)<input value={repository}maxLength={63}pattern="[a-z][a-z0-9-]{0,62}"onChange={e=>setRepository(e.target.value)}/></label>
   <label>Search hold references or reasons<input type="search"value={query}maxLength={256}onChange={e=>setQuery(e.target.value)}/></label><button type="submit">Search holds</button>
  </form>
  <div className="hold-observation"><Freshness at={data.at}loading={data.loading}/>{data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>}
  {data.loading&&<p role="status">Loading hold records…</p>}</div>
  {data.data&&<><p className="panel-copy">Hold state observed <time dateTime={data.data.observed_at}>{new Date(data.data.observed_at).toLocaleString()}</time>. Expiry and concurrent changes can change later pages. Refresh before deciding what to change.</p>
   {!data.data.items.length?<Empty title="No matching hold records">Change the state, repository or search. A hold that expired or was released remains available in its corresponding view and journal history.</Empty>:
   <div className="table-wrap"role="region"aria-label="Hold records"tabIndex={0}><table><thead><tr><th>Repository / exact reference</th><th>Hold state</th><th>Reason / expiry</th><th>Revision</th><th>Actions</th></tr></thead><tbody>{data.data.items.map(row=><tr key={row.repository+'\n'+row.path}>
    <td><strong>{row.repository}</strong><code className="break block">{row.path}</code><span className="small muted block">Repository {row.repository_state} · {row.mode} {row.format}</span></td>
    <td><Badge value={row.status}/>{row.deleted&&<span className="small block">Reference retained in deleted state</span>}</td>
    <td>{row.hold_reason||'No active hold reason'}<span className="small muted block">{row.hold_reason?moment(row.hold_until):'Inspect history for earlier hold and release reasons'}</span></td>
    <td>{Number.isSafeInteger(row.revision)?row.revision:'Use the API for an exact large revision'}</td>
    <td><button onClick={()=>p.open('Hold history · '+row.repository,<HoldHistory {...p}repository={row.repository}path={row.path}/>)}>Inspect hold history</button><button onClick={()=>p.open('Manage hold · '+row.repository,<Lifecycle {...p}repository={row.repository}path={row.path}initialAction={row.status==='released'?'hold':'release_hold'}/>)}>Manage hold</button></td>
   </tr>)}</tbody></table></div>}
   <CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Hold record pages"/>
  </>}
 </Panel>
}

export function HoldHistory({repository,path,...p}:Common&{repository:string;path:string}){
 const [cursor,setCursor]=useState('');
 const params=new URLSearchParams({path,limit:'100',...(cursor?{cursor}:{})});
 const data=useResource<Page<Change>>(p.client,'/api/v1/repositories/'+encodeURIComponent(repository)+'/artifacts/lifecycle/history?'+params,p.revision);
 return <section><p><strong>{repository}</strong><code className="break block">{path}</code></p>
  <p>These original hold and release snapshots were recorded with their changes. Expiry changes today's status and leaves the original receipt intact. Event hashes identify records in the full audit export; this filtered view is not the complete audit chain.</p>
  <div className="view-toolbar"><button onClick={data.refresh}>Refresh hold history</button><Freshness at={data.at}loading={data.loading}/><button onClick={()=>p.open('Manage hold · '+repository,<Lifecycle {...p}repository={repository}path={path}initialAction="release_hold"/>)}>Manage this hold</button></div>
  {data.error&&<ErrorBox error={data.error}retry={data.refresh}stale={!!data.data}/>}
  {data.loading&&<p role="status">Loading immutable hold receipts…</p>}
  {data.data&&<>{!data.data.items.length?<Empty title="No hold receipts recorded">No hold or release event is recorded for this reference. No historical action has been invented.</Empty>:<ol className="observation-list">{data.data.items.map(row=><li key={row.event_hash}><strong>{row.action==='hold'?'Hold placed':'Hold released'}</strong><span> by {row.actor} · <time dateTime={row.recorded_at}>{new Date(row.recorded_at).toLocaleString()}</time></span><p>{row.state.reason}</p><p>Revision {Number.isSafeInteger(row.state.revision)?row.state.revision:'exceeds exact console precision; inspect the API'}. {row.action==='hold'?<>Recorded expiry: {moment(row.state.hold_until)}.</>:'The release preserves earlier receipts.'}</p><Details title="Original hold journal snapshot"value={row}/></li>)}</ol>}<CursorPages after={cursor}next={data.data.next}setAfter={setCursor}label="Hold history pages"/></>}
 </section>
}

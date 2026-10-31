// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {ApiError,pending} from './api';
import type {Common} from './view-types';
import {Details,ErrorBox,MutationForm,useResource} from './components';

type State={state?:string;revision:number;deleted?:boolean;held?:boolean;digest?:string;hold_reason?:string;hold_until?:string};
type Preview={current:State;desired?:string;strong_parents?:string[];tags?:string[];weak_subject_dependents?:string[];active_retrievals:number;active_uploads?:number;groups?:string[]};
type Snapshot={input:Record<string,unknown>;preview:Preview};

export function Lifecycle({repository,path,initialAction,...p}:Common&{repository:string;path?:string;initialAction?:string}){
  const api=`/api/v1/repositories/${encodeURIComponent(repository)}/${path?'artifacts/lifecycle':'state'}`;
  const state=useResource<State>(p.client,api+(path?'?'+new URLSearchParams({path}):''),p.revision);
  const id=useId(),[action,setAction]=useState(initialAction??''),[reason,setReason]=useState(''),[until,setUntil]=useState(''),[snapshot,setSnapshot]=useState<Snapshot>(),[error,setError]=useState<ApiError>(),[busy,setBusy]=useState(false);
  const live=useRef(true),controller=useRef(new AbortController());useEffect(()=>()=>{live.current=false;controller.current.abort()},[]);
  const current=state.data;
  const focused=useRef(false);
  useEffect(()=>{if(focused.current||state.loading||!current||state.error)return;const field=document.getElementById(id+'-action'),dialog=field?.closest('dialog');if(document.activeElement===dialog||document.activeElement===dialog?.querySelector('[aria-label="Close dialog"]'))field?.focus();focused.current=true},[current,state.loading,state.error,id]);
  const choices=path?[...(current?.deleted?['restore']:['delete']),...(p.identity.role==='admin'?['hold','release_hold']:[])]:current?.state==='removed'?['restore']:current?.state==='suspended'?['resume','remove']:['suspend','remove'];
  const chosen=choices.includes(action)?action:choices[0];
  const previewAction=String(snapshot?.input.action??chosen);
  const blocked=!!snapshot&&(!!snapshot.preview.current.held&&['delete','restore'].includes(previewAction)||previewAction==='delete'&&!!snapshot.preview.strong_parents?.length);
  async function preview(e:FormEvent){
    e.preventDefault();if(!current||!Number.isSafeInteger(current.revision))return;
    const input={action:chosen,expected_revision:current.revision,reason,...(path?{path,digest:current.digest}:{}),...(chosen==='hold'&&until?{hold_until:new Date(until).toISOString()}:{}),dry_run:false};
    setBusy(true);setError(undefined);
    try{const response=await p.client.request<Preview>(api,{mutation:pending({method:'PUT',path:api,body:{...input,dry_run:true}}),signal:controller.current.signal});if(live.current&&!p.client.closed)setSnapshot({input,preview:response.value})}
    catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{if(live.current&&!p.client.closed)setBusy(false)}
  }
  return <><p><strong>{repository}</strong>{path&&<code className="break">{path}</code>}</p><p>Deletion and repository removal retain bytes and history. Restore checks retained content; existing security decisions still apply.</p>{state.error&&<ErrorBox error={state.error}retry={state.refresh}/>}<p role="status">{state.loading?'Loading current lifecycle…':current?`Current state: ${current.state??(current.deleted?'deleted':'active')}. Revision ${current.revision}.${current.held?' An active hold protects this reference.':''}`:''}</p>{current&&<Details value={current}title="Current lifecycle record"/>}
  {!snapshot?<form onSubmit={e=>void preview(e)}><fieldset disabled={busy||state.loading||!!state.error||!current||!Number.isSafeInteger(current.revision)}><label htmlFor={id+'-action'}>Action</label><select id={id+'-action'}value={chosen}onChange={e=>setAction(e.target.value)}>{choices.map(value=><option key={value}value={value}>{({suspend:'Suspend repository',resume:'Resume repository',remove:'Remove repository',restore:'Restore',delete:'Delete reference',hold:'Place hold',release_hold:'Release hold'}as Record<string,string>)[value]}</option>)}</select><label htmlFor={id+'-reason'}>Reason</label><input id={id+'-reason'}maxLength={1024}required value={reason}onChange={e=>setReason(e.target.value)}/>{chosen==='hold'&&<><label htmlFor={id+'-until'}>Hold expiry (optional, local time)</label><input id={id+'-until'}type="datetime-local"value={until}onChange={e=>setUntil(e.target.value)}/><p>Leave expiry empty for a hold that requires an administrator to release it.</p></>}<button className="primary"type="submit">{busy?'Reading impact…':'Preview impact'}</button></fieldset></form>:<><div className="message"role="status"><p>Previewed revision {snapshot.preview.current.revision}. {snapshot.preview.active_retrievals} active retrievals; {snapshot.preview.active_uploads??0} active uploads.</p>{snapshot.preview.groups?.length? <p>Groups using this source: {snapshot.preview.groups.join(', ')}. They fail while this source is inactive.</p>:null}{snapshot.preview.tags?.length?<p>Tag aliases: {snapshot.preview.tags.join(', ')}. A deleted target is hidden; restore keeps newer tag targets.</p>:null}{snapshot.preview.strong_parents?.length?<><p>Incoming manifest references:</p><ul>{snapshot.preview.strong_parents.map(path=><li key={path}><code className="break">{path}</code></li>)}</ul></>:null}{snapshot.preview.weak_subject_dependents?.length?<p>{snapshot.preview.weak_subject_dependents.length} subject dependents become unavailable when this subject is deleted.</p>:null}<p>{path?'No physical storage is reclaimed. Restore verifies every retained graph member.':'Suspension or removal fences active transfers. Resume or restore requires fresh transfers; old writers stay fenced.'}</p></div>{blocked?<p className="message error">This operation is blocked by an active hold or incoming manifest reference. Inspect the lifecycle record and parent references before trying again.</p>:<MutationForm client={p.client}label={'Apply '+previewAction.replaceAll('_',' ')}onDone={p.done}build={()=>({method:'PUT',path:api,body:snapshot.input})}><p>Apply the previewed action using revision {snapshot.preview.current.revision}. A concurrent change will reject this request.</p></MutationForm>}<button onClick={()=>{setSnapshot(undefined);setError(undefined);state.refresh()}}>Change action and preview again</button></>}{error&&<ErrorBox error={error}retry={()=>{setError(undefined);state.refresh()}}/>}</>;
}

// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {ApiError,pending} from './api';
import type {Common} from './view-types';
import {Details,ErrorBox,MutationForm} from './components';

type Batch={after_path:string;limit:number;reason:string;dry_run:boolean};
type Result={repository:string;after_path:string;more:boolean;examined:number;changed:number;dry_run:boolean;retained_bytes:boolean;reason:string};
type Preview={input:Batch;result:Result};

export function NuGetCatalog({repository,...p}:Common&{repository:string}){
  const api=`/api/v1/repositories/${encodeURIComponent(repository)}/nuget/reindex`;
  const id=useId(),[reason,setReason]=useState(''),[limit,setLimit]=useState('100'),[after,setAfter]=useState('');
  const [snapshot,setSnapshot]=useState<Preview>(),[receipt,setReceipt]=useState<{result:Result;replayed:boolean}>(),[error,setError]=useState<ApiError>(),[busy,setBusy]=useState(false),[attempted,setAttempted]=useState(false);
  const live=useRef(true),controller=useRef(new AbortController()),resultFocus=useRef<HTMLDivElement>(null);
  useEffect(()=>()=>{live.current=false;controller.current.abort()},[]);
  useEffect(()=>{if(snapshot||receipt)resultFocus.current?.focus();else document.getElementById(id+'-reason')?.focus()},[snapshot,receipt,id]);
  function edit(cursor:string){setAfter(cursor);setAttempted(false);setSnapshot(undefined);setReceipt(undefined);setError(undefined)}
  async function preview(e:FormEvent){
    e.preventDefault();if(busy)return;
    const input={after_path:after,limit:Number(limit),reason,dry_run:false};
    setBusy(true);setError(undefined);
    try{
      const response=await p.client.request<Result>(api,{mutation:pending({method:'POST',path:api,body:{...input,dry_run:true}}),signal:controller.current.signal});
      if(live.current&&!p.client.closed)setSnapshot({input,result:response.value});
    }catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{if(live.current&&!p.client.closed)setBusy(false)}
  }
  return <><p><strong>{repository}</strong></p><p>Rebuild package discovery from retained validated manifests when search reports that its catalog needs rebuilding. Package bytes, listing state and security decisions are preserved.</p><p>Each batch commits independently. Stop between batches and keep the last confirmed path to resume later. New packages can appear before that path; repeat from the beginning after the final batch.</p>
    {!snapshot&&!receipt&&<form onSubmit={e=>void preview(e)}><fieldset disabled={busy}>
      <label htmlFor={id+'-reason'}>Reason</label><input id={id+'-reason'}required maxLength={1024}value={reason}onChange={e=>{e.target.setCustomValidity(new TextEncoder().encode(e.target.value).length>1024?'Use no more than 1024 UTF-8 bytes.':'');setReason(e.target.value)}}/>
      <label htmlFor={id+'-limit'}>Packages per batch</label><input id={id+'-limit'}type="number"required min={1}max={1000}value={limit}onChange={e=>setLimit(e.target.value)}/>
      <p className="field-help">Use a smaller batch if the server reports a metadata limit. Preview reads metadata without changing it.</p>
      <label htmlFor={id+'-after'}>Resume after package path (optional)</label><input id={id+'-after'}maxLength={2048}value={after}onChange={e=>{e.target.setCustomValidity(new TextEncoder().encode(e.target.value).length>2048?'Use no more than 2048 UTF-8 bytes.':'');setAfter(e.target.value)}}/>
      <p className="field-help">Leave empty to begin. Use the last confirmed batch’s exact path to resume.</p><button type="submit"className="primary">{busy?'Reading batch…':'Preview batch'}</button>
    </fieldset></form>}
    {snapshot&&!receipt&&<><div ref={resultFocus}tabIndex={-1}className="message"role="status"><p>Preview: {snapshot.result.examined} packages examined; {snapshot.result.changed} need rebuilding. {snapshot.result.more?'More packages remain after this batch.':'This batch reaches the end of the current inventory.'}</p><p>This is an observation. Apply reads the batch again under current authorization; its counts may change.</p></div><MutationForm client={p.client}retainRequest onAttempt={()=>setAttempted(true)}label="Rebuild this batch"build={()=>({method:'POST',path:api,body:snapshot.input})}onDone={(value,replayed)=>setReceipt({result:value as Result,replayed})}><p>Apply only this batch for the recorded reason. A rejected batch changes no discovery metadata. If confirmation is lost, retry this same request before moving to another batch. Before closing without confirmation, save the request identity and body below for a later retry.</p></MutationForm><Details title="Previewed batch"value={snapshot}/><button disabled={attempted}onClick={()=>edit(after)}>Change batch and preview again</button></>}
    {receipt&&<><div ref={resultFocus}tabIndex={-1}className="message success"role="status"><p>{receipt.replayed?'Original batch confirmed.':'Batch confirmed.'} {receipt.result.examined} packages examined; {receipt.result.changed} rebuilt.</p><p>{receipt.result.more?'More packages remain. Preview the next batch to continue.':'End of the current inventory. Repeat from the beginning to check for earlier concurrent publications.'}</p></div><Details title="Confirmed batch receipt"value={receipt.result}/><label htmlFor={id+'-confirmed'}>Last confirmed package path</label><input id={id+'-confirmed'}readOnly value={receipt.result.after_path}/><p className="field-help">Keep this path to resume after closing the dialog. Completed batches remain committed.</p><div className="inline">{receipt.result.more&&<button onClick={()=>edit(receipt.result.after_path)}>Continue to next batch</button>}<button onClick={()=>edit('')}>Check again from beginning</button><button onClick={()=>p.done(receipt.result,receipt.replayed)}>Close and refresh repositories</button></div></>}
    {error&&<ErrorBox error={error}retry={()=>{setError(undefined);document.getElementById(id+'-reason')?.focus()}}/>}
  </>;
}

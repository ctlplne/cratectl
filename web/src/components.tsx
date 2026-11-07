// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent,ReactNode} from 'react';
import {ApiError,pending} from './api';
import type {Client,PendingRequest,RequestSpec} from './api';

export function useResource<T>(client:Client,path:string,revision:number=0){
  const [value,setValue]=useState<{path:string;data?:T;error?:ApiError;loading:boolean;at:number}>({path,loading:true,at:0});
  const [refresh,setRefresh]=useState(0);
  useEffect(()=>{
    if(!path){setValue({path,loading:false,at:0});return}
    const controller=new AbortController();
    setValue(v=>({path,data:v.path===path?v.data:undefined,loading:true,at:v.path===path?v.at:0}));
    client.request<T>(path,{signal:controller.signal}).then(r=>{if(!controller.signal.aborted&&!client.closed)setValue({path,data:r.value,loading:false,at:Date.now()})}).catch(e=>{
      if(!controller.signal.aborted&&!client.closed)setValue(v=>({path,data:e.status===403?undefined:v.data,error:e,loading:false,at:v.at}));
    });
    return ()=>controller.abort();
  },[client,path,revision,refresh]);
  return {...(value.path===path?value:{path,loading:true,at:0}),refresh:()=>setRefresh(v=>v+1)};
}
export function Badge({value}:{value:string}){
  const labels:Record<string,string>={allowed:'Manually allowed',unassessed:'Unassessed',verified:'SHA-256 verified',io_error:'Read error',cancel_requested:'Cancellation requested',retry:'Retry waiting',temporary_retained:'Staged · retained',legacy_retained:'Legacy · retained'};
  const positive=['allowed','verified','succeeded','ready'].includes(value),negative=['denied','failed','corrupt','missing','changed','io_error','unsupported'].includes(value);
  return <span className={`badge ${positive?'positive':negative?'negative':'neutral'}`}>{labels[value]??value.replaceAll('_',' ')}</span>;
}
export function Empty({title,children,action}:{title:string;children:ReactNode;action?:ReactNode}){return <div className="empty"><span className="empty-mark" aria-hidden="true">◇</span><h2>{title}</h2><p>{children}</p>{action}</div>}
export function ErrorBox({error,retry,stale=false}:{error:ApiError;retry:()=>void;stale?:boolean}){return <div role="alert" className="message error"><strong>{error.status===403?'Access denied':stale?'Refresh failed · showing an older observation':'Unable to load this view'}</strong><p>{error.message}</p><div className="inline"><code>{error.code}</code><button onClick={retry}>Try again</button></div></div>}
export function Freshness({at,loading}:{at:number;loading:boolean}){
  const [now,setNow]=useState(Date.now());useEffect(()=>{const timer=setInterval(()=>setNow(Date.now()),5000);return()=>clearInterval(timer)},[]);
  if(loading)return <span role="status" className="muted">Loading current data…</span>;
  if(!at)return null;const stale=now-at>60000;
  return <span className={stale?'stale':'muted'}>{stale?'Stale observation · ':''}<time dateTime={new Date(at).toISOString()}>Fetched {new Date(at).toLocaleTimeString()}</time></span>;
}
export function Heading({eyebrow,title,description,action}:{eyebrow:string;title:string;description:string;action?:ReactNode}){return <header className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1 tabIndex={-1} id="page-title">{title}</h1><p>{description}</p></div>{action}</header>}
export function Panel({title,children,action}:{title:string;children:ReactNode;action?:ReactNode}){return <section className="panel"><div className="panel-heading"><h2>{title}</h2>{action}</div>{children}</section>}
export function Json({value}:{value:unknown}){const text=JSON.stringify(value,null,2)??'No value recorded.';return <pre className="json"tabIndex={0}>{text.length>20000?text.slice(0,20000)+'\n… Display truncated; use the API for the complete record.':text}</pre>}
export function Details({value,title='Recorded details'}:{value:unknown;title?:string}){return <details className="record-details"><summary>{title}</summary><Json value={value}/></details>}
export function Copy({text,label='Copy'}:{text:string;label?:string}){
  const [message,setMessage]=useState('');
  return <><button onClick={async()=>{try{await navigator.clipboard.writeText(text);setMessage('Copied.')}catch{setMessage('Select and copy the text below.')}}}>{label}</button><span role="status" className="muted">{message}</span></>;
}
export function LocalPages<T>({items,children,label}:{items:T[];children:(rows:T[])=>ReactNode;label:string}){
  const [page,setPage]=useState(0);useEffect(()=>setPage(0),[items]);const count=Math.max(1,Math.ceil(items.length/100));const safe=Math.min(page,count-1);
  return <>{children(items.slice(safe*100,safe*100+100))}{count>1&&<nav className="pagination" aria-label={label}><button disabled={safe===0}onClick={()=>setPage(p=>p-1)}>Previous loaded rows</button><span>{safe*100+1}–{Math.min(items.length,safe*100+100)} of {items.length} loaded</span><button disabled={safe+1===count}onClick={()=>setPage(p=>p+1)}>Next loaded rows</button></nav>}</>;
}
export function CursorPages({after,next,more,last,setAfter,label}:{after:string;next?:string;more?:boolean;last?:string;setAfter:(value:string)=>void;label:string}){
  const stack=useRef<string[]>([]);
  useEffect(()=>{if(!after)stack.current=[]},[after]);
  const forward=next??(more?last:'');
  return <nav className="pagination" aria-label={label}><button disabled={!after}onClick={()=>{const prev=stack.current.pop()??'';setAfter(prev)}}>Previous page</button><span>Live, cursor-based page</span><button disabled={!forward}onClick={()=>{stack.current.push(after);setAfter(forward!)}}>Next page</button></nav>;
}
export function Modal({title,children,onClose}:{title:string;children:ReactNode;onClose:()=>void}){
  const id=useId();const ref=useRef<HTMLDialogElement>(null);const previous=useRef<HTMLElement|null>(null);
  useEffect(()=>{const dialog=ref.current;previous.current=document.activeElement as HTMLElement;dialog?.showModal();return()=>{dialog?.close();if(previous.current?.isConnected)previous.current.focus()}},[]);
  useEffect(()=>{const dialog=ref.current;const field=dialog?.querySelector<HTMLElement>('input:not([type="hidden"]):not(:disabled),select:not(:disabled),textarea:not(:disabled)');(field??dialog?.querySelector<HTMLElement>('button'))?.focus()},[title]);
  return <dialog ref={ref}aria-labelledby={id}onCancel={e=>{e.preventDefault();onClose()}}><div className="modal-heading"><h2 id={id}>{title}</h2><button aria-label="Close dialog"onClick={onClose}>Close</button></div>{children}</dialog>;
}
export function MutationForm({client,children,build,label,onDone,onAttempt,retainRequest=false}:{client:Client;children:ReactNode;build:()=>RequestSpec;label:string;onDone:(value:unknown,replayed:boolean)=>void;onAttempt?:()=>void;retainRequest?:boolean}){
  const [snapshot,setSnapshot]=useState<PendingRequest>();const [busy,setBusy]=useState(false);const [error,setError]=useState<ApiError>();
  const live=useRef(true);const controller=useRef(new AbortController());useEffect(()=>()=>{live.current=false;controller.current.abort()},[]);
  async function send(request:PendingRequest){setSnapshot(request);setBusy(true);setError(undefined);onAttempt?.();try{const r=await client.request(request.path,{mutation:request,signal:controller.current.signal});if(!client.closed&&live.current)onDone(r.value,r.replayed)}catch(e){if(!client.closed&&live.current)setError(e as ApiError)}finally{if(!client.closed&&live.current)setBusy(false)}}
  function submit(e:FormEvent){e.preventDefault();if(!busy)void send(snapshot??pending(build()))}
  return <form onSubmit={submit}><fieldset disabled={busy||!!snapshot}>{children}</fieldset>{error&&<div className="message error"role="alert"><strong>{error.status===0||error.status>=500?'Outcome not confirmed':'Request rejected'}</strong><p>{error.message}</p><p>The request below retains its original bytes and idempotency key. Retry to confirm that request.</p><code className="break">{snapshot?.key}</code></div>}{snapshot&&<details className="record-details"><summary>Request identity and body</summary><Json value={snapshot}/></details>}<div className="modal-actions"><button className="primary"disabled={busy}type="submit">{busy?'Waiting for confirmation…':snapshot?'Retry same request':label}</button>{error&&!retainRequest&&<button type="button"onClick={()=>{setSnapshot(undefined);setError(undefined)}}>Edit as a new request</button>}<span role="status"aria-live="polite">{busy?'Do not assume completion until the server confirms.':''}</span></div></form>;
}
export function bytes(value:number|string){if(typeof value==='number'&&!Number.isSafeInteger(value))return 'Size exceeds exact console precision; inspect API data';try{const n=BigInt(value);if(n<1024n)return `${n} B`;for(const [threshold,unit]of [[1099511627776n,'TiB'],[1073741824n,'GiB'],[1048576n,'MiB'],[1024n,'KiB']]as const){if(n>=threshold)return `${n/threshold}.${(n%threshold)*10n/threshold} ${unit}`}}catch{}return String(value)}

// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {ApiError,pending} from './api';
import type {Page,PendingRequest,Repository} from './api';
import type {Common} from './view-types';
import type {Policy} from './retention';
import {Badge,CursorPages,Details,Empty,ErrorBox,Freshness,Panel,useResource} from './components';

export type ScheduleReceipt={revision:number;due_at:string;coalesced_intervals:number};
type Settings={interval_seconds:number;max_targets:number;enabled:boolean;reason:string};
type Schedule=Settings&{repository:string;policy:Policy;source_revision:number;revision:number;authorize_future_retirements:boolean;authorized_actor:string;configured_at:string;next_due_at:string;retry_at:string;blocked:boolean;last_error:string;last_job?:string;last_state?:string};
type Input=Settings&{expected_revision:number;expected_policy_revision:number;expected_source_revision:number;authorize_future_retirements:boolean;run_immediately:boolean};
type Run={job:string;state:string;plan:{policy:Policy;targets:number;eligible:number;schedule?:ScheduleReceipt}};
type Props=Common&{repository:string;name:string;openRun:(id:string)=>void};
const base=(repo:string,name:string)=>'/api/v1/repositories/'+encodeURIComponent(repo)+'/retention-policies/'+encodeURIComponent(name);
const exact=(n:number)=>Number.isSafeInteger(n)?String(n):'Use the CLI for the exact value';
const validReason=(s:string)=>s.trim().length>0&&new TextEncoder().encode(s).length<=1024&&!/[\u0000-\u001f\u007f-\u009f]/.test(s);
function useLifetime(){const live=useRef(true),controller=useRef(new AbortController());useEffect(()=>{live.current=true;if(controller.current.signal.aborted)controller.current=new AbortController();return()=>{live.current=false;controller.current.abort()}},[]);return {live,controller}}
function state(s:Schedule){return !s.enabled?'paused':s.blocked?'blocked':s.last_error?'deferred':'enabled'}
function explanation(code:string){switch(code){
  case 'requester_authorization_unavailable':return 'The original authorizing credential expired or was revoked. Edit and explicitly reauthorize with your current administrator credential.';
  case 'policy_changed':return 'The approved policy revision changed or was disabled. Review the current policy before approving a new schedule revision.';
  case 'source_changed':return 'The approved source revision changed. Review the current repository source before approving a new schedule revision.';
  case 'previous_run_active':return 'A previous run of this policy is still active. Inspect its recorded outcomes or request cancellation; the due slot has not been consumed.';
  case 'plan_budget_exceeded':return 'The complete manifest set exceeds the approved target or metadata limit. No partial run was admitted. Inspect repository size and explicitly review a new limit if appropriate.';
  case 'maintenance_queue_full':case 'events_queue_full':return 'A required work queue is full. The worker will retry without consuming the due slot.';
  case 'repository_unavailable':return 'The repository is unavailable. Inspect its retained state; the due slot remains pending.';
  default:return code;
}}
export function ScheduleProvenance({receipt}:{receipt:ScheduleReceipt}){return <p className="small muted">Scheduled capture · schedule revision {exact(receipt.revision)} · due <time dateTime={receipt.due_at}>{new Date(receipt.due_at).toLocaleString()}</time> · {exact(receipt.coalesced_intervals)} missed intervals coalesced.</p>}

export function RetentionScheduleView({repository,name,openRun,...p}:Props){
  const path=base(repository,name),schedule=useResource<Schedule>(p.client,path+'/schedule',p.revision),policy=useResource<Policy>(p.client,path,p.revision),repo=useResource<Repository>(p.client,'/api/v1/repositories/'+encodeURIComponent(repository),p.revision);
  const [section,setSection]=useState('runs'),[after,setAfter]=useState('');
  const records=useResource<Page<Schedule|Run>>(p.client,schedule.data?path+'/schedule/'+section+'?limit=50&after='+(after||'0'):'',p.revision);
  const current=schedule.data,missing=schedule.error?.status===404&&!current;
  const fresh=!!policy.data&&!!repo.data&&!policy.error&&!repo.error&&!policy.loading&&!repo.loading&&!schedule.loading&&(!schedule.error||missing);
  const precise=Number.isSafeInteger(policy.data?.revision)&&Number.isSafeInteger(repo.data?.source_revision)&&Number.isSafeInteger((current?.revision??0)+1);
  const changed=!!current&&!!policy.data&&!!repo.data&&(current.policy.revision!==policy.data.revision||current.source_revision!==repo.data.source_revision);
  const last=records.data?.items.at(-1),cursor=section==='runs'?(last as Run|undefined)?.job.split(':')[0]??'':Number.isSafeInteger((last as Schedule|undefined)?.revision)?String((last as Schedule).revision):'';
  function edit(seed?:Schedule){p.open('Review automatic retirement',<ScheduleEditor {...p} repository={repository} name={name} current={current} policy={policy.data!} source={repo.data!.source_revision} seed={seed}/>)}
  function refresh(){schedule.refresh();policy.refresh();repo.refresh();records.refresh()}
  return <>
    <p><strong>{repository} / {name}</strong>. Automatic retirement authorizes future complete target captures. Every run keeps immutable outcomes and rechecks current holds, tags, references and authority. Bytes reclaimed: 0.</p>
    <div className="view-toolbar"><Freshness at={schedule.at} loading={schedule.loading}/><button onClick={refresh}>Refresh automatic retirement</button><button className="primary" disabled={!fresh||!precise} onClick={()=>edit()}>{current?'Edit automatic retirement':'Configure automatic retirement'}</button></div>
    {policy.error&&<ErrorBox error={policy.error} retry={policy.refresh} stale={!!policy.data}/>}{repo.error&&<ErrorBox error={repo.error} retry={repo.refresh} stale={!!repo.data}/>}
    {schedule.error&&!missing&&<ErrorBox error={schedule.error} retry={schedule.refresh} stale={!!current}/>}
    {schedule.loading&&!current&&<p role="status">Loading automatic retirement…</p>}
    {fresh&&!precise&&<p className="message warning" role="status">A revision exceeds exact console precision. Use the CLI to inspect and change this schedule without rounding its identity.</p>}
    {missing&&<Empty title="Automatic retirement is not configured">A normal retention policy admits no automatic work. Configure and explicitly approve future captures to create a schedule. A worker must be running to admit and execute due runs.</Empty>}
    {current&&<><div className="view-toolbar"><Badge value={state(current)}/><span>Schedule revision {exact(current.revision)}</span></div><dl className="facts"><div><dt>Approved policy revision</dt><dd>{exact(current.policy.revision)}</dd></div><div><dt>Approved source revision</dt><dd>{exact(current.source_revision)}</dd></div><div><dt>Interval</dt><dd>{current.interval_seconds} seconds</dd></div><div><dt>Complete-set limit</dt><dd>{current.max_targets} live manifests</dd></div><div><dt>Authorizing actor</dt><dd>{current.authorized_actor}</dd></div><div><dt>Next due slot</dt><dd><time dateTime={current.next_due_at}>{new Date(current.next_due_at).toLocaleString()}</time></dd></div></dl>
      <p>{current.enabled?'Future captures are configured. This does not confirm that a run was admitted or completed.':'Future captures are paused. Unprocessed targets from earlier schedule revisions cannot continue; earlier outcomes remain retained.'}</p>
      {current.last_error&&<div className="message warning" role="status"><strong>{current.blocked?'Automatic retirement blocked':'Automatic retirement deferred'}</strong><p>{explanation(current.last_error)}</p><code>{current.last_error}</code>{!current.blocked&&<p>Next admission retry: <time dateTime={current.retry_at}>{new Date(current.retry_at).toLocaleString()}</time>.</p>}</div>}
      {changed&&<p className="message warning" role="status">Current policy or source revisions differ from this approval. Its future runs cannot use the changed settings. Review current bindings and explicitly authorize a new schedule revision.</p>}
      {current.last_job&&<div className="message"><p>Last recorded run: <code className="break">{current.last_job}</code> <Badge value={current.last_state??'unknown'}/></p><button onClick={()=>openRun(current.last_job!)}>Inspect last scheduled run</button></div>}
      <Details title="Recorded automatic retirement configuration" value={current}/>
      <label className="select-field">Automatic retirement records<select value={section} onChange={e=>{setSection(e.target.value);setAfter('')}}><option value="runs">Scheduled retirement runs</option><option value="history">Schedule configuration history</option></select></label>
      <Freshness at={records.at} loading={records.loading}/>{records.error&&<ErrorBox error={records.error} retry={records.refresh} stale={!!records.data}/>}
      {records.loading&&!records.data&&<p role="status">Loading automatic retirement records…</p>}
      <Panel title={section==='runs'?'Scheduled retirement runs':'Schedule configuration history'}>
        {records.data?.items.map(item=>section==='runs'?<section className="message" key={(item as Run).job}><h3>Scheduled retirement run <code className="break">{(item as Run).job}</code></h3><Badge value={(item as Run).state}/>{(item as Run).plan.schedule&&<ScheduleProvenance receipt={(item as Run).plan.schedule!}/>}<p>Captured targets: {(item as Run).plan.targets}; initially eligible: {(item as Run).plan.eligible}. Policy revision {exact((item as Run).plan.policy.revision)}.</p><button onClick={()=>openRun((item as Run).job)}>Inspect scheduled retirement run</button></section>:<section className="message" key={(item as Schedule).revision}><h3>Schedule configuration revision {exact((item as Schedule).revision)}</h3><Details title="Recorded schedule approval" value={item}/><button disabled={!fresh||!precise||!!records.error||records.loading} onClick={()=>edit(item as Schedule)}>Prepare these settings for new approval</button></section>)}
        {records.data&&!records.data.items.length&&<p className="muted">No {section==='runs'?'scheduled runs':'configuration revisions'} on this page. A due configuration is not proof of retirement.</p>}
      </Panel>
      <CursorPages after={after} more={records.data?.more} last={cursor} setAfter={setAfter} label="Automatic retirement record pages"/>
    </>}
  </>;
}

function ScheduleEditor({repository,name,current,policy,source,seed,...p}:Common&{repository:string;name:string;current?:Schedule;policy:Policy;source:number;seed?:Schedule}){
  const id=useId(),{live,controller}=useLifetime(),defaults=seed??current;
  const [interval,setInterval]=useState(defaults?.interval_seconds??3600),[limit,setLimit]=useState(defaults?.max_targets??100),[enabled,setEnabled]=useState((defaults?.enabled??true)&&policy.enabled),[immediate,setImmediate]=useState(false),[consent,setConsent]=useState(false),[reason,setReason]=useState('');
  const [preview,setPreview]=useState<{body:Input;proposed:Schedule}>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>();
  async function inspect(e:FormEvent){e.preventDefault();setBusy(true);setError(undefined);try{
    if(![current?.revision??0,(current?.revision??0)+1,policy.revision,source,interval,limit].every(Number.isSafeInteger))throw new ApiError(400,'integer_limit','Use exact whole values within the displayed limits; use the CLI for a revision beyond console precision.');
    if(!validReason(reason))throw new ApiError(400,'reason_required','Supply a nonempty reason of at most 1024 UTF-8 bytes without control characters.');
    if(enabled&&!consent)throw new ApiError(400,'future_authority_required','Explicitly approve future target captures before enabling automatic retirement.');
    const body:Input={expected_revision:current?.revision??0,expected_policy_revision:policy.revision,expected_source_revision:source,interval_seconds:interval,max_targets:limit,enabled,authorize_future_retirements:enabled&&consent,run_immediately:enabled&&immediate,reason};
    const path=base(repository,name)+'/schedule',response=await p.client.request<Schedule>(path,{mutation:pending({method:'PUT',path,body:{...body,dry_run:true}}),signal:controller.current.signal});
    if(live.current&&!p.client.closed)setPreview({body,proposed:response.value});
  }catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{if(live.current&&!p.client.closed)setBusy(false)}}
  return <>
    <p>Repository: <strong>{repository}</strong>. Policy: <strong>{name}</strong>. This approval binds current policy revision {exact(policy.revision)} and source revision {exact(source)} to your current administrator credential.</p>
    {seed&&<p className="message" role="status">Historical cadence, limit and enabled setting are prepared. Current policy/source bindings and a new explicit approval govern future runs; the old authority is not restored.</p>}
    {!policy.enabled&&<p className="message warning" role="status">This policy is disabled. You can pause its schedule; enable the policy before authorizing future runs.</p>}
    {!preview?<form onSubmit={e=>void inspect(e)}><fieldset disabled={busy}>
      <label htmlFor={id+'-interval'}>Retirement interval in seconds</label><input id={id+'-interval'} autoFocus type="number" required min={60} max={31536000} step={1} value={interval} onChange={e=>setInterval(Number(e.target.value))}/>
      <label htmlFor={id+'-limit'}>Maximum live manifests per run</label><input id={id+'-limit'} type="number" required min={1} max={10000} step={1} value={limit} onChange={e=>setLimit(Number(e.target.value))}/>
      <p className="small muted">The complete set, including protected manifests, must fit this limit. A larger set defers the whole run. The server may enforce a lower ceiling.</p>
      <label className="check"><input type="checkbox" disabled={!policy.enabled} checked={enabled} onChange={e=>{setEnabled(e.target.checked);setConsent(false);if(!e.target.checked)setImmediate(false)}}/>Enable automatic retirement</label>
      <label className="check"><input type="checkbox" disabled={!enabled} required={enabled} checked={consent} onChange={e=>setConsent(e.target.checked)}/>I authorize future complete target captures under these policy and source revisions</label>
      <label className="check"><input type="checkbox" disabled={!enabled} checked={immediate} onChange={e=>setImmediate(e.target.checked)}/>Make the first retirement slot due immediately</label>
      <label htmlFor={id+'-reason'}>Automatic retirement change reason</label><input id={id+'-reason'} required maxLength={1024} value={reason} onChange={e=>setReason(e.target.value)}/>
      <p>Changing or pausing this schedule stops unprocessed targets of earlier scheduled runs. Earlier outcomes remain retained. Cancelling one run does not pause future slots.</p>
      <button className="primary" type="submit">{busy?'Reading automatic retirement impact…':'Preview automatic retirement'}</button>
    </fieldset></form>:<>
      <div className="message" role="status"><p>Automatic retirement preview: revision {exact(preview.proposed.revision)} will be <strong>{preview.proposed.enabled?'enabled':'paused'}</strong>. {preview.proposed.enabled?`Each due run captures the complete set within ${preview.proposed.max_targets} targets every ${preview.proposed.interval_seconds} seconds.`:'No new automatic captures are authorized.'}</p><p>Missed intervals coalesce into one run. Active work, queue pressure or an oversized capture defers admission. The first due time is calculated again when this configuration commits.</p><p>Bytes reclaimed: 0. Holds, references, current tags, policy and authorization remain effective.</p></div>
      <Details title="Current policy bound to future retirement" value={preview.proposed.policy}/><Details title="Proposed automatic retirement approval" value={preview.proposed}/>
      <ScheduleApproval {...p} path={base(repository,name)+'/schedule'} body={preview.body} edit={()=>{setPreview(undefined);setError(undefined);setConsent(false)}}/>
    </>}
    {error&&<ErrorBox error={error} retry={()=>{setError(undefined);setPreview(undefined)}}/>}
  </>;
}

function ScheduleApproval({path,body,edit,...p}:Common&{path:string;body:Input;edit:()=>void}){
  const {live,controller}=useLifetime(),request=useRef<PendingRequest|undefined>(undefined),sending=useRef(false);
  const [snapshot,setSnapshot]=useState<PendingRequest>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>();
  const uncertain=!!error&&(error.status===0||error.status>=500);
  async function send(e:FormEvent){e.preventDefault();if(sending.current)return;request.current??=pending({method:'PUT',path,body});const original=request.current;setSnapshot(original);setBusy(true);sending.current=true;setError(undefined);
    try{const result=await p.client.request(path,{mutation:original,signal:controller.current.signal});if(live.current&&!p.client.closed)p.done(result.value,result.replayed)}catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{sending.current=false;if(live.current&&!p.client.closed)setBusy(false)}
  }
  return <form onSubmit={e=>void send(e)}><p>Apply only after reviewing the complete policy, source revision and future authority. If you close while waiting, inspect current schedule state and configuration history before another approval.</p>
    {error&&<div className="message error" role="alert"><strong>{uncertain?'Automatic retirement approval not confirmed':'Automatic retirement approval rejected'}</strong><p>{error.message}</p><code>{error.code}</code><p>{uncertain?'Retry the original request and key to confirm its outcome. Automatic work may already have been authorized.':'Read current revisions and review a new approval when the configuration changed.'}</p></div>}
    {snapshot&&<Details title="Automatic retirement request identity" value={snapshot}/>}
    <div className="modal-actions"><button className="primary" autoFocus disabled={busy} type="submit">{busy?'Waiting for approval confirmation…':snapshot?'Retry same automatic retirement request':body.enabled?'Authorize scheduled retirement':'Apply retirement pause'}</button><button type="button" disabled={busy||uncertain} onClick={edit}>Edit automatic retirement plan</button></div>
  </form>;
}

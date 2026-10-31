// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useId,useRef,useState} from 'react';
import type {FormEvent} from 'react';
import {ApiError,pending} from './api';
import type {Job,Page,PendingRequest} from './api';
import type {Common} from './view-types';
import {Badge,CursorPages,Details,Empty,ErrorBox,Freshness,LocalPages,MutationForm,Panel,bytes,useResource} from './components';
import {Lifecycle} from './lifecycle';

type Settings={min_age_seconds:number;keep_last:number;protect_tagged:boolean;enabled:boolean;reason:string};
type Policy=Settings&{repository:string;name:string;revision:number;actor:string;configured_at:string};
type PolicyInput=Settings&{expected_revision:number};
type Target={ordinal:number;path:string;digest:string;size:number;created_at:string;lifecycle_revision:number;status:string;tags:string[];strong_parents:string[]};
type Plan={policy:Policy;source_revision:number;evaluated_at:string;expires_at:string;reason:string;targets:number;eligible:number;items?:Target[];preview_digest:string;bytes_reclaimed:number};
type Run={job:string;state:string;plan:Plan};
type Outcome=Target&{outcome:string;outcome_revision:number;observed_at?:string};
type RunDetail={job:Job;plan:Plan;processed:number;retired:number;skipped:number;all_targets_processed:boolean;bytes_reclaimed:number};
const policyPath=(repo:string,name?:string)=>'/api/v1/repositories/'+encodeURIComponent(repo)+'/retention-policies'+(name?'/'+encodeURIComponent(name):'');
const exactRevision=(value:number)=>Number.isSafeInteger(value)?String(value):'Use the CLI for this revision';
const reasonValid=(value:string)=>value.trim().length>0&&new TextEncoder().encode(value).length<=1024&&!/[\u0000-\u001f\u007f-\u009f]/.test(value);

function useRequestLifetime(){
  const live=useRef(true),controller=useRef(new AbortController());
  useEffect(()=>{live.current=true;if(controller.current.signal.aborted)controller.current=new AbortController();return()=>{live.current=false;controller.current.abort()}},[]);
  return {live,controller};
}

export function Retention(p:Common){
  const id=useId(),[draft,setDraft]=useState(''),[repository,setRepository]=useState('');
  function choose(e:FormEvent){e.preventDefault();setRepository(draft)}
  return <>
    <p className="muted">Retire old OCI manifests through an approved policy. Bytes and history remain retained; no disk space is reclaimed.</p>
    <form onSubmit={choose} className="view-toolbar">
      <label htmlFor={id}>OCI repository</label>
      <input id={id} required maxLength={63} pattern="[a-z][a-z0-9-]*" value={draft} onChange={e=>setDraft(e.target.value)}/>
      <button type="submit">Load retention policies</button>
    </form>
    {repository?<PolicyList key={repository} {...p} repository={repository}/>:<Empty title="Choose an OCI repository">Enter a hosted or proxy OCI repository name to inspect its retention policies. Group endpoints do not own these references.</Empty>}
  </>;
}

function PolicyList({repository,...p}:Common&{repository:string}){
  const [after,setAfter]=useState('');
  const data=useResource<Page<Policy>>(p.client,policyPath(repository)+'?limit=50&after='+encodeURIComponent(after),p.revision);
  return <>
    <div className="view-toolbar">
      <Freshness at={data.at} loading={data.loading}/><button onClick={data.refresh}>Refresh retention policies</button>
      <button className="primary" disabled={!data.data||!!data.error||data.loading} onClick={()=>p.open('Create retention policy',<PolicyEditor {...p} repository={repository}/>)}>Create retention policy</button>
    </div>
    {data.error&&<ErrorBox error={data.error} retry={data.refresh} stale={!!data.data}/>}
    <Panel title="Retention policies">
      {data.loading&&!data.data&&<p role="status">Loading retention policies…</p>}
      {data.data&&(data.data.items.length?<div className="table-wrap" role="region" aria-label="Retention policies" tabIndex={0}><table>
        <thead><tr><th>Policy / repository</th><th>State</th><th>Selection and protections</th><th>Revision</th><th><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>{data.data.items.map(row=><tr key={row.name}>
          <td><strong>{row.name}</strong><span className="small muted block">{repository}</span></td>
          <td><Badge value={row.enabled?'enabled':'disabled'}/></td>
          <td>{row.min_age_seconds} seconds old; keep {row.keep_last} newest per image<span className="small muted block">{row.protect_tagged?'Tagged manifests protected':'Reviewed tagged targets may be retired'}</span></td>
          <td>{exactRevision(row.revision)}</td>
          <td><button onClick={()=>p.open('Retention policy · '+row.name,<PolicyDetail {...p} repository={repository} name={row.name}/>)}>Inspect retention policy</button></td>
        </tr>)}</tbody>
      </table></div>:<Empty title="No retention policies on this page">Create a policy, review its exact manifest selection, then approve a run. A worker must be running to execute admitted work.</Empty>)}
    </Panel>
    <CursorPages after={after} more={data.data?.more} last={data.data?.items.at(-1)?.name??''} setAfter={setAfter} label="Retention policy pages"/>
  </>;
}

function PolicyEditor({repository,current,...p}:Common&{repository:string;current?:Policy}){
  const id=useId(),{live,controller}=useRequestLifetime();
  const [name,setName]=useState(current?.name??''),[age,setAge]=useState(current?.min_age_seconds??2592000),[keep,setKeep]=useState(current?.keep_last??5);
  const [tagged,setTagged]=useState(current?.protect_tagged??true),[enabled,setEnabled]=useState(current?.enabled??true),[reason,setReason]=useState('');
  const [snapshot,setSnapshot]=useState<{body:PolicyInput;policy:Policy}>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>();
  async function preview(e:FormEvent){
    e.preventDefault();setError(undefined);setBusy(true);
    try{
      if(!Number.isSafeInteger(current?.revision??0)||!Number.isSafeInteger(age)||!Number.isSafeInteger(keep))throw new ApiError(400,'integer_limit','Use whole values within the displayed limits; use the CLI for a revision beyond exact console precision.');
      if(!reasonValid(reason))throw new ApiError(400,'reason_required','Supply a nonempty reason of at most 1024 UTF-8 bytes without control characters.');
      const body:PolicyInput={expected_revision:current?.revision??0,min_age_seconds:age,keep_last:keep,protect_tagged:tagged,enabled,reason};
      const response=await p.client.request<Policy>(policyPath(repository,name),{mutation:pending({method:'PUT',path:policyPath(repository,name),body:{...body,dry_run:true}}),signal:controller.current.signal});
      if(live.current&&!p.client.closed)setSnapshot({body,policy:response.value});
    }catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{if(live.current&&!p.client.closed)setBusy(false)}
  }
  return <>
    <p>Repository: <strong>{repository}</strong>. Policies select canonical OCI manifests by their creation age. This is not time since a download or tag update.</p>
    {!snapshot?<form onSubmit={e=>void preview(e)}><fieldset disabled={busy}>
      <label htmlFor={id+'-name'}>Retention policy name</label><input id={id+'-name'} required pattern="[a-z][a-z0-9-]*" maxLength={63} readOnly={!!current} value={name} onChange={e=>setName(e.target.value)}/>
      <label htmlFor={id+'-age'}>Minimum age in seconds</label><input id={id+'-age'} required type="number" min={60} max={315360000} step={1} value={age} onChange={e=>setAge(Number(e.target.value))}/>
      <label htmlFor={id+'-keep'}>Newest manifests to keep per image</label><input id={id+'-keep'} required type="number" min={0} max={1000000} step={1} value={keep} onChange={e=>setKeep(Number(e.target.value))}/>
      <p className="small muted">Zero disables the newest-version protection. Active holds and incoming manifest references always protect content.</p>
      <label className="check"><input type="checkbox" checked={tagged} onChange={e=>setTagged(e.target.checked)}/>Protect tagged manifests</label>
      <label className="check"><input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)}/>Allow retirement runs</label>
      <label htmlFor={id+'-reason'}>Retention policy change reason</label><input id={id+'-reason'} required maxLength={1024} value={reason} onChange={e=>setReason(e.target.value)}/>
      <button className="primary" type="submit">{busy?'Reading policy impact…':'Preview retention policy'}</button>
    </fieldset></form>:<>
      <div className="message" role="status"><p>Policy preview: <strong>{snapshot.policy.name}</strong> will be {snapshot.policy.enabled?'enabled':'disabled'} at revision {exactRevision(snapshot.policy.revision)}.</p><p>Changing or disabling this policy stops further effects from its earlier runs. Existing outcomes and tombstones remain retained.</p></div>
      <Details title="Proposed retention configuration" value={snapshot.policy}/>
      <MutationForm client={p.client} label="Apply retention policy" build={()=>({method:'PUT',path:policyPath(repository,name),body:snapshot.body})} onDone={p.done}><p>Saving a policy does not retire content or schedule automatic execution. Review and approve each run separately.</p></MutationForm>
      <button onClick={()=>setSnapshot(undefined)}>Edit policy plan</button>
    </>}
    {error&&<ErrorBox error={error} retry={()=>{setError(undefined);setSnapshot(undefined)}}/>}
  </>;
}

function PolicyDetail({repository,name,...p}:Common&{repository:string;name:string}){
  const path=policyPath(repository,name),data=useResource<Policy>(p.client,path,p.revision);
  const [section,setSection]=useState('runs'),[after,setAfter]=useState('');
  const records=useResource<Page<Run|Policy>>(p.client,path+'/'+section+'?limit=50&after='+(after||'0'),p.revision),current=data.data;
  const last=records.data?.items.at(-1);
  const lastCursor=section==='runs'?(last as Run|undefined)?.job.split(':')[0]??'':Number.isSafeInteger((last as Policy|undefined)?.revision)?String((last as Policy).revision):'';
  return <>
    <div className="view-toolbar">
      {current&&<Badge value={current.enabled?'enabled':'disabled'}/>}<Freshness at={data.at} loading={data.loading}/>
      <button onClick={()=>{data.refresh();records.refresh()}}>Refresh retention policy</button>
      <button disabled={!current||!!data.error||data.loading||!Number.isSafeInteger(current.revision)} onClick={()=>p.open('Edit retention policy · '+name,<PolicyEditor {...p} repository={repository} current={current}/>)}>Edit retention policy</button>
      <button className="primary" disabled={!current?.enabled||!!data.error||data.loading||!Number.isSafeInteger(current?.revision)} onClick={()=>p.open('Preview retirement · '+name,<RunPreview {...p} policy={current!}/>)}>Preview retirement</button>
    </div>
    {data.error&&<ErrorBox error={data.error} retry={data.refresh} stale={!!current}/>}
    {data.loading&&!current&&<p role="status">Loading current retention policy…</p>}
    {current&&<><dl className="facts"><div><dt>Repository</dt><dd>{repository}</dd></div><div><dt>Policy revision</dt><dd>{exactRevision(current.revision)}</dd></div><div><dt>Minimum creation age</dt><dd>{current.min_age_seconds} seconds</dd></div><div><dt>Newest kept per image</dt><dd>{current.keep_last}</dd></div></dl><p>{current.enabled?'Each run requires a fresh approved preview.':'This policy is disabled. Edit it to allow newly approved runs.'} Bytes and security decisions remain retained.</p><Details title="Current retention configuration" value={current}/></>}
    <label className="select-field">Retention records<select value={section} onChange={e=>{setSection(e.target.value);setAfter('')}}><option value="runs">Retirement runs</option><option value="history">Configuration history</option></select></label>
    <Freshness at={records.at} loading={records.loading}/>{records.error&&<ErrorBox error={records.error} retry={records.refresh} stale={!!records.data}/>}
    {records.loading&&!records.data&&<p role="status">Loading retention records…</p>}
    {records.data?.items.map(row=>section==='runs'?<section className="message" key={(row as Run).job}>
      <h3>Retirement run <code className="break">{(row as Run).job}</code></h3><Badge value={(row as Run).state}/>
      <p>Approved targets: {(row as Run).plan.targets}. Initially eligible: {(row as Run).plan.eligible}. Policy revision {exactRevision((row as Run).plan.policy.revision)}.</p>
      <button onClick={()=>p.open('Retirement run',<RetentionRun {...p} id={(row as Run).job}/>)}>Inspect retirement run</button>
    </section>:<Details key={(row as Policy).revision} title={'Retention configuration revision '+exactRevision((row as Policy).revision)} value={row}/>)}
    {records.data&&!records.data.items.length&&<p className="muted">No {section==='runs'?'retirement runs':'configuration revisions'} on this page.</p>}
    <CursorPages after={after} more={records.data?.more} last={lastCursor} setAfter={setAfter} label="Retention record pages"/>
  </>;
}

function TargetTable({items,outcomes,onInspect}:{items:(Target|Outcome)[];outcomes?:boolean;onInspect?:(row:Target)=>void}){
  return <div className="table-wrap" role="region" aria-label={outcomes?'Retirement outcomes':'Approved retirement targets'} tabIndex={0}><table>
    <thead><tr><th>Manifest / digest</th><th>Size</th><th>Preview selection</th>{outcomes&&<th>Committed outcome</th>}<th>Aliases and protections</th>{onInspect&&<th><span className="sr-only">Actions</span></th>}</tr></thead>
    <tbody>{items.map(row=><tr key={row.ordinal}>
      <td><strong className="break">{row.path}</strong><code className="digest">sha256:{row.digest}</code></td><td>{bytes(row.size)}</td><td><Badge value={row.status}/></td>
      {outcomes&&<td><Badge value={(row as Outcome).outcome}/>{(row as Outcome).observed_at&&<time className="small muted block" dateTime={(row as Outcome).observed_at}>{new Date((row as Outcome).observed_at!).toLocaleString()}</time>}</td>}
      <td><span className="small">{row.tags.length} tags; {row.strong_parents.length} incoming manifests</span><Details title={'Recorded aliases and references · target '+row.ordinal} value={{tags:row.tags,strong_parents:row.strong_parents,lifecycle_revision:row.lifecycle_revision}}/></td>
      {onInspect&&<td><button onClick={()=>onInspect(row)}>Inspect lifecycle or restore</button></td>}
    </tr>)}</tbody>
  </table></div>;
}

function RunPreview({policy,...p}:Common&{policy:Policy}){
  const id=useId(),{live,controller}=useRequestLifetime();
  const [reason,setReason]=useState(''),[plan,setPlan]=useState<Plan>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>();
  async function preview(e:FormEvent){
    e.preventDefault();setBusy(true);setError(undefined);
    try{
      if(!reasonValid(reason))throw new ApiError(400,'reason_required','Supply a nonempty reason of at most 1024 UTF-8 bytes without controls.');
      if(!Number.isSafeInteger(policy.revision))throw new ApiError(400,'integer_limit','Use the CLI to preserve this exact policy revision.');
      const path=policyPath(policy.repository,policy.name)+'/runs';
      const response=await p.client.request<Plan>(path,{mutation:pending({method:'POST',path,body:{expected_revision:policy.revision,reason,dry_run:true}}),signal:controller.current.signal});
      if(live.current&&!p.client.closed)setPlan(response.value);
    }catch(e){if(live.current&&!p.client.closed){const error=e as ApiError;setError(error.code==='response_limit'?new ApiError(error.status,error.code,'This complete preview exceeds the console response budget. Review it with cratectl --response-limit 16777216; no retirement run was admitted.'):error)}}finally{if(live.current&&!p.client.closed)setBusy(false)}
  }
  return <>
    <p><strong>{policy.repository} / {policy.name}</strong>. Review all selected manifests, their aliases and protections before approving retirement.</p>
    {!plan?<form onSubmit={e=>void preview(e)}><fieldset disabled={busy}>
      <label htmlFor={id}>Retirement run reason</label><input id={id} required maxLength={1024} value={reason} onChange={e=>setReason(e.target.value)}/>
      <button className="primary" type="submit">{busy?'Reading complete selection…':'Preview retirement targets'}</button>
    </fieldset></form>:<>
      <div className="message" role="status"><p>Retirement preview: <strong>{plan.eligible} eligible</strong> out of {plan.targets} approved targets. Other targets remain protected or ineligible.</p><p>Approval expires at <time dateTime={plan.expires_at}>{new Date(plan.expires_at).toLocaleString()}</time>. Current holds, tags, references and authority are checked again during execution.</p><p>Bytes reclaimed: 0. Existing content security decisions remain unchanged.</p></div>
      {plan.targets?<LocalPages items={plan.items??[]} label="Retirement preview target pages">{rows=><TargetTable items={rows}/>}</LocalPages>:<Empty title="No manifests in this preview">A recorded empty run retires no content and verifies no bytes.</Empty>}
      <Details title="Approved retention plan identity" value={{policy:plan.policy,evaluated_at:plan.evaluated_at,preview_digest:plan.preview_digest,source_revision:plan.source_revision}}/>
      <RunApproval {...p} plan={plan} repreview={()=>{setPlan(undefined);setError(undefined)}}/>
    </>}
    {error&&<ErrorBox error={error} retry={()=>{setError(undefined);setPlan(undefined)}}/>}
  </>;
}

function RunApproval({plan,repreview,...p}:Common&{plan:Plan;repreview:()=>void}){
  const {live,controller}=useRequestLifetime(),request=useRef<PendingRequest|undefined>(undefined),sending=useRef(false);
  const [snapshot,setSnapshot]=useState<PendingRequest>(),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError>();
  const uncertain=!!error&&(error.status===0||error.status>=500);
  async function apply(e:FormEvent){
    e.preventDefault();if(sending.current)return;
    const path=policyPath(plan.policy.repository,plan.policy.name)+'/runs';
    request.current??=pending({method:'POST',path,body:{expected_revision:plan.policy.revision,reason:plan.reason,evaluated_at:plan.evaluated_at,preview_digest:plan.preview_digest}});
    const attempt=request.current;setSnapshot(attempt);sending.current=true;setBusy(true);setError(undefined);
    try{const response=await p.client.request(path,{mutation:attempt,signal:controller.current.signal});if(live.current&&!p.client.closed)p.done(response.value,response.replayed)}
    catch(e){if(live.current&&!p.client.closed)setError(e as ApiError)}finally{sending.current=false;if(live.current&&!p.client.closed)setBusy(false)}
  }
  return <form onSubmit={e=>void apply(e)}>
    <fieldset disabled={busy||!!snapshot}><label className="check"><input type="checkbox" required/>I reviewed all {plan.targets} targets and their aliases</label><p>Approval admits a durable job. Inspect its committed outcomes to confirm which manifests were retired. If you close while waiting, inspect policy runs before creating another run.</p></fieldset>
    {error&&<div className="message error" role="alert"><strong>{uncertain?'Retirement admission not confirmed':'Retirement request rejected'}</strong><p>{error.message}</p><code>{error.code}</code><p>{uncertain?'Retry the same request to confirm its outcome. Keep its original approval and request identity.':'Obtain a new preview when the approved selection or policy changed.'}</p></div>}
    {snapshot&&<Details title="Retirement request identity" value={snapshot}/>}
    <div className="modal-actions"><button className="primary" disabled={busy} type="submit">{busy?'Waiting for admission…':snapshot?'Retry same retirement request':'Approve retirement run'}</button><button type="button" disabled={busy||uncertain} onClick={repreview}>Review a new retirement preview</button></div>
  </form>;
}

export function RetentionRun({id,...p}:Common&{id:string}){
  const path='/api/v1/maintenance/retention-runs/'+encodeURIComponent(id),data=useResource<RunDetail>(p.client,path,p.revision);
  const [after,setAfter]=useState(''),rows=useResource<Page<Outcome>>(p.client,path+'/items?limit=50&after='+(after||'0'),p.revision);
  const detail=data.data,j=detail?.job,policy=detail?.plan.policy;
  const needsNewApproval=j&&['retention_requester_authorization','retention_plan_changed'].includes(j.last_error);
  return <>
    <p><code className="break">{id}</code></p>
    <div className="view-toolbar">{j&&<Badge value={j.state}/>}<Freshness at={data.at} loading={data.loading}/><button onClick={()=>{data.refresh();rows.refresh()}}>Refresh retirement run</button>
      {policy&&<button onClick={()=>p.open('Retention policy · '+policy.name,<PolicyDetail {...p} repository={policy.repository} name={policy.name}/>)}>Review current retention policy</button>}
    </div>
    {data.error&&<ErrorBox error={data.error} retry={data.refresh} stale={!!detail}/>}
    {data.loading&&!detail&&<p role="status">Loading retirement outcomes…</p>}
    {detail&&<><dl className="facts"><div><dt>Approved targets</dt><dd>{detail.plan.targets}</dd></div><div><dt>Processed targets</dt><dd>{detail.processed}</dd></div><div><dt>Retired manifests</dt><dd>{detail.retired}</dd></div><div><dt>Skipped targets</dt><dd>{detail.skipped}</dd></div></dl><p>{detail.all_targets_processed?'All approved targets have committed outcomes.':'Remaining targets are not confirmed complete.'} Bytes reclaimed: 0. Bytes, history and security decisions remain retained.</p></>}
    {needsNewApproval&&<p className="message warning" role="status">The policy, source or requesting credential changed. Inspect earlier outcomes, then review the current policy and approve a new run. Retrying this job does not replace its original authority.</p>}
    {j&&<div className="inline">
      <button disabled={!!data.error||data.loading||['succeeded','failed','cancelled','uncertain'].includes(j.state)} onClick={()=>p.run('Cancel retirement run','Stop remaining retirement after the worker confirms cancellation. Earlier outcomes and tombstones stay retained.',{method:'POST',path:'/api/v1/jobs/'+id+'/cancel',body:{}})}>Cancel retirement run</button>
      <button disabled={!!data.error||data.loading||!!needsNewApproval||['pending','running','retry','cancel_requested'].includes(j.state)} onClick={()=>p.run('Retry retirement run','Resume only unprocessed approved targets with the original authority. Already committed targets do not repeat.',{method:'POST',path:'/api/v1/jobs/'+id+'/retry',body:{acknowledge_unknown:true}})}>Retry retirement run</button>
    </div>}
    <Freshness at={rows.at} loading={rows.loading}/>{rows.error&&<ErrorBox error={rows.error} retry={rows.refresh} stale={!!rows.data}/>}
    {rows.data&&<TargetTable items={rows.data.items} outcomes onInspect={policy?row=>p.open('Retained manifest lifecycle',<Lifecycle {...p} repository={policy.repository} path={row.path}/>):undefined}/>}
    {rows.data&&!rows.data.items.length&&<p className="muted">No targets on this approved page. An empty run retires no content.</p>}
    <CursorPages after={after} more={rows.data?.more} last={String(rows.data?.items.at(-1)?.ordinal??'')} setAfter={setAfter} label="Retirement outcome pages"/>
    {detail&&<Details title="Immutable approved retention plan" value={detail.plan}/>}{j&&<Details title="Recorded job projection" value={j}/>}
  </>;
}

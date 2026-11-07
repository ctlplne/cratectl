// SPDX-License-Identifier: BUSL-1.1
import {useState} from 'react';
import type {Repository} from './api';
import type {Common} from './view-types';
import {Copy,Details,ErrorBox,Freshness,useResource} from './components';
import {GoChecksumLegacy} from './go-checksum-legacy';
import type {ChecksumState} from './go-checksum-legacy';

type State={source_revision:number;authority:ChecksumState;package_admission:false};
type Failure={root_path:string;source_revision:number;generation:number;key_digest:string;classification:string;evidence_sha256:string;sequence:number;created_at:string};
type History={items:Failure[];more:boolean;next_after:number};
const exact=(n:number)=>Number.isSafeInteger(n)&&n>=0;
const quote=(v:string)=>"'"+v.replaceAll("'","'\\''")+"'";

export function GoChecksum({repository,...p}:Common&{repository:Repository}){
  const [after,setAfter]=useState(0),[selected,setSelected]=useState<Failure>(),[showLegacy,setShowLegacy]=useState(false),[refresh,setRefresh]=useState(0);
  const base=`/api/v1/repositories/${encodeURIComponent(repository.name)}/go/checksum`;
  const state=useResource<State>(p.client,exact(repository.source_revision)?base+'?source_revision='+repository.source_revision:'',p.revision);
  const history=useResource<History>(p.client,p.identity.role==='admin'?base+'/failures?limit=25&after='+after:'',p.revision);
  const current=!state.error?state.data:undefined,rows=!history.error?history.data?.items:undefined;
  const pagingSafe=!history.data?.more||exact(history.data.next_after)&&history.data.next_after>after;
  const selectedExact=selected&&exact(selected.source_revision)&&exact(selected.generation)&&exact(selected.sequence);
  const download=selectedExact?base+'/failures/evidence?'+new URLSearchParams({root_path:selected.root_path,source_revision:String(selected.source_revision),generation:String(selected.generation)}):'';
  const command=download?'umask 077\ncratectl --config "$CRATECTL_CLIENT_CONFIG" --path '+quote(download)+' --raw-response > go-checksum-failure.json\ncratectl go-checksum-verify --evidence-file ./go-checksum-failure.json --key-file "$CRATECTL_CHECKSUM_PUBLIC_KEY" --expected-sha256 "$CRATECTL_TRUSTED_EVIDENCE_SHA256"':'';
  return <><p><strong>{repository.name}</strong></p><p>A checksum authority signs a public record of module hashes. A proved conflict blocks its exact key throughout this tenant. Retained trust and package review still apply independently.</p>
    <div className="view-toolbar"><Freshness at={state.at}loading={state.loading}/><button onClick={()=>{state.refresh();history.refresh();setSelected(undefined);setShowLegacy(false);setRefresh(v=>v+1)}}>Refresh checksum inspection</button></div>
    {!exact(repository.source_revision)&&<p role="alert"className="message error">This source revision exceeds exact console precision. Use the management API and CLI.</p>}
    {state.error&&<ErrorBox error={state.error}retry={state.refresh}/>}
    {current&&<><p role="status"className="message">{current.authority.blocked?'Authenticated fork: this authority key is blocked. Inspect retained evidence and choose a separately trusted authority key. Retrying or changing the source cannot reset this block.':current.authority.legacy_review_required?'Unattributed historical incident: external trust review is required. Missing original proof does not establish an authenticated fork or a clean authority.':'No authenticated fork is recorded for this key. This is not a health check, a recent authority contact or permission to serve package bytes.'}</p><Details title="Retained checksum checkpoint"value={current.authority.checkpoint}/></>}
    {p.identity.role==='admin'?<><h3>Retained failure history</h3><p>These summaries omit upstream response bodies. An unverified observation does not prove a fork or a clean authority. Suspended and removed repository records retain inspection access.</p><Freshness at={history.at}loading={history.loading}/>{history.error&&<ErrorBox error={history.error}retry={history.refresh}/>}
      {rows&&<>{!rows.length?<p>No retained failures on this page. Older prototype records may lack original proof; this page does not resolve those incidents.</p>:<div className="table-wrap"role="region"aria-label="Checksum failure history"tabIndex={0}><table><thead><tr><th>Module ZIP root</th><th>Classification</th><th>Evidence SHA-256</th><th><span className="sr-only">Inspection</span></th></tr></thead><tbody>{rows.map((v,n)=><tr key={n}><td className="break">{v.root_path}</td><td>{v.classification==='fork'?'Authenticated fork':'Unverified observation'}</td><td><code className="digest">{v.evidence_sha256}</code></td><td><button onClick={()=>setSelected(v)}>Evidence commands</button></td></tr>)}</tbody></table></div>}
        {!pagingSafe&&<p role="alert"className="message error">The next journal position exceeds exact console precision or did not advance. Use the API and CLI to continue.</p>}<nav className="pagination"aria-label="Checksum failure pages"><button disabled={history.loading||after===0}onClick={()=>{setAfter(0);setSelected(undefined)}}>First failure page</button><button disabled={history.loading||!history.data?.more||!pagingSafe}onClick={()=>{setAfter(history.data!.next_after);setSelected(undefined)}}>Next failure page</button></nav></>}
      {selected&&<section aria-label="Private evidence export"><h3>Verify exact retained evidence offline</h3><p>Original upstream bodies can contain sensitive source data. Save them to an owner-private file. Obtain the public verifier key separately and set <code>CRATECTL_TRUSTED_EVIDENCE_SHA256</code> from a trusted audit journal or export manifest. This summary and the download alone do not authenticate cratectl attribution.</p>{selectedExact?<><pre className="json">{command}</pre><Copy text={command}label="Copy private evidence commands"/></>:<p role="alert">This record exceeds exact console precision. Use the API and CLI without copying rounded numbers from this view.</p>}<p>The offline command returns success only for an authenticated fork. An unverified observation returns a nonzero exit status. Neither result approves package bytes.</p></section>}
      {current&&<><button onClick={()=>setShowLegacy(v=>!v)}>{showLegacy?'Hide legacy incidents':'Inspect retained legacy incidents'}</button>{(showLegacy||current.authority.legacy_review_required)&&<GoChecksumLegacy key={refresh+'/'+current.source_revision+'/'+current.authority.checkpoint.key_digest} {...p}repository={repository.name}sourceRevision={current.source_revision}authority={current.authority}/>}</>}
    </>:<p>Raw failure history and upstream response bodies require a current tenant administrator credential.</p>}
  </>;
}

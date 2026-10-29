// SPDX-License-Identifier: BUSL-1.1
export type Identity={tenant:string;actor:string;role:'admin'|'writer'|'reader';public_url:string;formats:string[]};
export type Repository={source_revision:number;name:string;format:string;mode:string;access:string;require_review:boolean;settings:Record<string,unknown>};
export type Artifact={lifecycle?:{deleted:boolean;held:boolean;revision:number};path:string;digest:string;size:number;decision:string;media_type:string;created_at:string;metadata:unknown;metadata_omitted?:boolean};
export type Job={sequence:number;task:string;handler:string;kind:string;queue:string;state:string;attempts:number;generation:number;last_error:string;updated_at:string;target:Record<string,unknown>};
export type Audit={sequence:number;payload:string;hash:string;previous_hash:string;created_at:string};
export type Page<T>={items:T[];next?:string;previous?:string;more?:boolean;limit?:number;scope?:string};
export type RequestSpec={method:'POST'|'PUT';path:string;body:unknown};
export type PendingRequest={method:'POST'|'PUT';path:string;body:string;key:string};
export class ApiError extends Error {
  constructor(public status:number,public code:string,message:string){super(message)}
}
export class Client {
  private controller=new AbortController();
  private active=0;
  readonly id=crypto.randomUUID();
  constructor(private token:string,private unauthorized:()=>void){}
  get closed(){return this.controller.signal.aborted}
  dispose(){this.controller.abort();this.token=''}
  async request<T>(path:string,options:{signal?:AbortSignal;mutation?:PendingRequest}={}):Promise<{value:T;replayed:boolean;status:number}>{
    if(!path.startsWith('/api/v1/')||path.length>8192)throw new ApiError(0,'invalid_path','Use a management endpoint on this server.');
    if(this.active>=6)throw new ApiError(0,'client_busy','Wait for a current request to finish, then refresh.');
    this.active++;
    const signal=AbortSignal.any([this.controller.signal,AbortSignal.timeout(20000),...(options.signal?[options.signal]:[])]);
    try{
      const headers:Record<string,string>={Authorization:`Bearer ${this.token}`};
      const mutation=options.mutation;
      if(mutation){headers['Content-Type']='application/json';headers['Idempotency-Key']=mutation.key}
      const response=await fetch(path,{method:mutation?.method??'GET',headers,body:mutation?.body,signal,redirect:'error',cache:'no-store',credentials:'omit'});
      if(signal.aborted)throw signal.reason;
      if(response.status===401){this.dispose();this.unauthorized();throw new ApiError(401,'credential_required','The credential expired, was revoked or is not valid for this console. Reconnect with a current tenant credential.')}
      const reader=response.body?.getReader();let size=0;const chunks:Uint8Array[]=[];
      if(reader)for(;;){const next=await reader.read();if(next.done)break;size+=next.value.byteLength;if(size>4*1024*1024){await reader.cancel();throw new ApiError(0,'response_limit','This response exceeds the console budget. Use a smaller page or a narrower query.')}chunks.push(next.value)}
      const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength}
      let data:unknown;
      try{data=JSON.parse(new TextDecoder().decode(bytes))}catch{throw new ApiError(response.status,'invalid_response','The server returned an unreadable response. Refresh or inspect service health.')}
      if(!response.ok){
        const e=(data as {error?:{code?:unknown;action?:unknown}})?.error;
        throw new ApiError(response.status,typeof e?.code==='string'?e.code.slice(0,128):'request_failed',typeof e?.action==='string'?e.action.slice(0,4096):'The request was rejected. Refresh the current state before retrying.');
      }
      if(signal.aborted)throw signal.reason;
      return {value:data as T,replayed:response.headers.get('Idempotent-Replayed')==='true',status:response.status};
    }catch(e){
      if(e instanceof ApiError)throw e;
      if(this.closed||options.signal?.aborted)throw new DOMException('Request cancelled','AbortError');
      throw new ApiError(0,'connection_lost','The response was not confirmed. Check connectivity and service health; a mutation may already have committed.');
    }finally{this.active--}
  }
}
export function pending(spec:RequestSpec):PendingRequest{return {method:spec.method,path:spec.path,body:JSON.stringify(spec.body),key:'console-'+crypto.randomUUID()}}
export function jobID(j:Job){return `${j.sequence}:${j.task}`}

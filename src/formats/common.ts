import { createHash } from 'node:crypto';
import { isUtf8 } from 'node:buffer';

export const BOUNDS = Object.freeze({ inputBytes:64*1024*1024, summary:100, viewBytes:4096,
  previewBytes:128, selectorBytes:4096, entries:100000, nesting:128, steps:500000,
  sqlitePages:8192, sqlitePayload:1024*1024, sqliteReturnedFields:256, sqliteFreeblocksPerPage:4096 });
export class FormatFailure extends Error {
  constructor(public readonly status:'unknown'|'error', message:string) { super(message); }
}
export function demand(ok:unknown, message:string):asserts ok { if(!ok) throw new FormatFailure('error',message); }
export function supported(ok:unknown,message:string):asserts ok { if(!ok) throw new FormatFailure('unknown',message); }
export const sha = (bytes:Buffer):string => createHash('sha256').update(bytes).digest('hex');
export function utf8(bytes:Buffer):string { demand(isUtf8(bytes),'invalid UTF-8'); return bytes.toString('utf8'); }
export function name(bytes:Buffer,offset:number,length:number):Record<string,unknown> {
  demand(offset>=0 && length>=0 && offset+length<=bytes.length,'name range outside artifact');
  const slice=bytes.subarray(offset,offset+length); demand(isUtf8(slice),'invalid UTF-8 name');
  let n=Math.min(length,128); while(n>0 && !isUtf8(slice.subarray(0,n))) n--;
  return {preview:slice.subarray(0,n).toString('utf8'),byteLength:length,sha256:sha(slice),range:{offset,length},truncated:n<length};
}
export function options(raw:unknown,key:string):{selector:string|undefined;offset:number;limit:number} {
  demand(raw===undefined || (raw!==null && typeof raw==='object' && !Array.isArray(raw)),'options must be an object');
  const o=(raw??{}) as Record<string,unknown>;
  demand(Object.keys(o).every(k=>[key,'offset','limit'].includes(k)),'unknown option');
  const selector=o[key]; demand(selector===undefined || typeof selector==='string','selector must be a string');
  demand(selector===undefined || (Buffer.byteLength(selector as string)<=4096 && (selector as string).length>0),'selector exceeds 4096 UTF-8 bytes or is empty');
  const offset=o.offset??0, limit=o.limit??(selector!==undefined && key!=='table'?4096:20);
  const max=selector!==undefined && key!=='table'?4096:100;
  demand(Number.isSafeInteger(offset) && Number(offset)>=0,'offset must be a nonnegative safe integer');
  demand(Number.isSafeInteger(limit) && Number(limit)>=1 && Number(limit)<=max,`limit must be 1..${max}`);
  return {selector:selector as string|undefined,offset:Number(offset),limit:Number(limit)};
}
export function inspect(bytes:Buffer,format:string,scope:string,fn:()=>Record<string,unknown>):Record<string,any> {
  const base={format,scope,equivalence:'UNKNOWN',untrustedArtifactData:true,originalUnchanged:true,
    source:{sha256:Buffer.isBuffer(bytes)?sha(bytes):null,byteLength:Buffer.isBuffer(bytes)?bytes.length:null},limits:BOUNDS};
  try { demand(Buffer.isBuffer(bytes),'input must be a Buffer'); supported(bytes.length<=BOUNDS.inputBytes,'input byte bound exceeded');
    return {...base,status:'ok',...fn()};
  } catch(e) { return {...base,status:e instanceof FormatFailure?e.status:'error',reason:e instanceof Error?e.message:'parse failure'}; }
}
export function view(bytes:Buffer,start:number,length:number,offset:number,limit:number):Record<string,unknown> {
  demand(Number.isSafeInteger(start) && Number.isSafeInteger(length) && start>=0 && length>=0 && start+length<=bytes.length,'data extent outside artifact');
  demand(offset<=length,'view offset beyond data'); const size=Math.min(limit,length-offset,4096);
  return {offset:start+offset,length:size,totalLength:length,base64:bytes.subarray(start+offset,start+offset+size).toString('base64'),
    sha256:sha(bytes.subarray(start,start+length)),truncated:offset+size<length};
}
export class Reader {
  pos:number;
  constructor(public readonly bytes:Buffer,start=0,public readonly end=bytes.length){this.pos=start;demand(start>=0&&end>=start&&end<=bytes.length,'reader range');}
  need(n:number):void {demand(Number.isSafeInteger(n)&&n>=0&&n<=this.end-this.pos,'truncated or out-of-bounds input');}
  u8():number{this.need(1);return this.bytes[this.pos++]!;}
  u32():number{this.need(4);const n=this.bytes.readUInt32LE(this.pos);this.pos+=4;return n;}
  u64():number{this.need(8);const n=this.bytes.readBigUInt64LE(this.pos);this.pos+=8;demand(n<=BigInt(Number.MAX_SAFE_INTEGER),'integer exceeds safe range');return Number(n);}
  skip(n:number):void{this.need(n);this.pos+=n;}
  leb():number {let n=0,m=1;for(let i=0;i<5;i++){const b=this.u8();demand(i<4||(b&0xf0)===0,'u32 LEB128 overflow');n+=(b&127)*m;if(!(b&128))return n;m*=128;}throw new FormatFailure('error','LEB128 overflow');}
  count():number{const n=this.leb();supported(n<=BOUNDS.entries,'entry count bound exceeded');return n;}
  wasmName():{offset:number;length:number}{const length=this.leb(),offset=this.pos;this.skip(length);demand(isUtf8(this.bytes.subarray(offset,offset+length)),'invalid UTF-8 name');return{offset,length};}
  done():void{demand(this.pos===this.end,'unexpected trailing section bytes');}
}

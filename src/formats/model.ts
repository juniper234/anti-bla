import { isUtf8 } from 'node:buffer';
import { BOUNDS, Reader, demand, inspect, name, options, sha, supported, utf8, view } from './common.js';
type Node={start:number;end:number;kind:number};
type Member={key:string;keyNode:Node;value:Node};
// A strict scanner indexes JSON byte ranges. Unrequested metadata values are never JSON.parse'd.
class JsonIndex {
  pos:number;steps=0;
  constructor(readonly b:Buffer,readonly start:number,readonly end:number){this.pos=start;demand(isUtf8(b.subarray(start,end)),'invalid JSON UTF-8');}
  white():void{while(this.pos<this.end&&[32,9,10,13].includes(this.b[this.pos]!))this.pos++;}
  string():Node {const start=this.pos;demand(this.b[this.pos++]===34,'expected JSON string');while(this.pos<this.end){const c=this.b[this.pos++]!;if(c===34)return{start,end:this.pos,kind:34};demand(c>=32,'control byte in JSON string');if(c===92){demand(this.pos<this.end,'truncated JSON escape');const e=this.b[this.pos++]!;if(e===117){demand(this.pos+4<=this.end,'truncated Unicode escape');for(let i=0;i<4;i++)demand(/[0-9a-fA-F]/.test(String.fromCharCode(this.b[this.pos++]!)),'invalid Unicode escape');}else demand([34,92,47,98,102,110,114,116].includes(e),'invalid JSON escape');}}throw new Error('unterminated JSON string');}
  value(depth=0):Node {supported(depth<=128,'JSON nesting bound exceeded');supported(++this.steps<=500000,'JSON token bound exceeded');this.white();const start=this.pos,c=this.b[this.pos];
    if(c===34)return this.string();
    if(c===123||c===91){this.pos++;this.white();const close=c===123?125:93,keys=new Set<string>();if(this.b[this.pos]===close){this.pos++;return{start,end:this.pos,kind:c};}
      while(true){if(c===123){this.white();const key=this.string();const decoded=this.decode(key,4096);demand(!keys.has(decoded),'duplicate JSON field');keys.add(decoded);this.white();demand(this.b[this.pos++]===58,'missing JSON colon');}this.value(depth+1);this.white();const x=this.b[this.pos++];if(x===close)break;demand(x===44,'missing JSON comma/closing delimiter');}
      return{start,end:this.pos,kind:c};}
    if(c===116||c===102||c===110){const text=c===116?'true':c===102?'false':'null';demand(this.b.subarray(this.pos,this.pos+text.length).equals(Buffer.from(text)),'invalid JSON literal');this.pos+=text.length;return{start,end:this.pos,kind:c};}
    // Avoid catastrophic regex or a full header projection: number token is at most 128 bytes.
    let stop=this.pos;while(stop<this.end&&[45,43,46,69,101,48,49,50,51,52,53,54,55,56,57].includes(this.b[stop]!))stop++;
    demand(stop>this.pos&&stop-this.pos<=128,'invalid/overlong JSON number');const t=this.b.toString('ascii',this.pos,stop);demand(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(t),'invalid JSON number');this.pos=stop;return{start,end:stop,kind:48};
  }
  decode(n:Node,max=4096):string{supported(n.end-n.start<=max+2,'JSON name/value decode bound exceeded');const s=JSON.parse(this.b.toString('utf8',n.start,n.end));demand(typeof s==='string','expected JSON string');demand(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(s),'invalid Unicode scalar');supported(Buffer.byteLength(s)<=max,'decoded string bound exceeded');return s;}
  members(n:Node):Member[]{demand(n.kind===123,'expected JSON object');this.pos=n.start+1;this.white();const out:Member[]=[];if(this.b[this.pos]===125)return out;
    while(this.pos<n.end){supported(out.length<100000,'JSON member bound exceeded');this.white();const keyNode=this.string(),key=this.decode(keyNode);this.white();demand(this.b[this.pos++]===58,'JSON colon');const value=this.value();out.push({key,keyNode,value});this.white();const c=this.b[this.pos++];if(c===125)break;demand(c===44,'JSON comma');}return out;}
  integers(n:Node,max:number):number[]{demand(n.kind===91,'expected integer array');supported(n.end-n.start<=max*20+2,'integer array byte bound');const a:unknown=JSON.parse(this.b.toString('utf8',n.start,n.end));demand(Array.isArray(a)&&a.length<=max&&a.every(x=>Number.isSafeInteger(x)&&x>=0),'invalid nonnegative safe-integer array');
    const text=this.b.toString('ascii',n.start,n.end);demand(/^[\[\],\s0-9]*$/.test(text),'integer tokens require nonnegative integer notation');return a as number[];}
}
type Tensor={name:Record<string,unknown>;key:string;dtype:string;shape:number[];offset:number;length:number;descriptor:{offset:number;length:number};extras:Array<Record<string,unknown>>};
type Parsed={format:string;tensors:Tensor[];metadata:object;layoutIssue?:string;recovery?:{base:number;tensors:Tensor[]}};
const safeTypes:Record<string,number>={BOOL:1,U8:1,I8:1,I16:2,U16:2,F16:2,BF16:2,I32:4,U32:4,F32:4,I64:8,U64:8,F64:8};
function product(shape:number[],size:number):number{let n=BigInt(size);if(shape.includes(0))return 0;for(const x of shape){n*=BigInt(x);demand(n<=BigInt(Number.MAX_SAFE_INTEGER),'tensor shape extent overflow');}return Number(n);}
function logicalName(b:Buffer,j:JsonIndex,m:Member):Record<string,unknown>{const data=Buffer.from(m.key);return{...name(data,0,data.length),range:{offset:m.keyNode.start,length:m.keyNode.end-m.keyNode.start},encoding:'JSON string, range includes quotes'};}
export function inspectModel(bytes:Buffer,raw?:{tensor?:string;offset?:number;limit?:number}):object {
  return inspect(bytes,'model','structural tensor descriptors and bounded stored values; inference, source and global model behavior UNKNOWN',()=>{
    const o=options(raw,'tensor');const parsed=bytes.subarray(0,4).equals(Buffer.from([0x47,0x47,0x55,0x46]))?gguf(bytes):safetensors(bytes),tensors=parsed.tensors;
    const summary=(t:Tensor)=>({name:t.name,dtype:t.dtype,shape:t.shape,dataRange:{offset:t.offset,length:t.length},descriptor:t.descriptor});
    const result:Record<string,unknown>={format:parsed.format,metadata:parsed.metadata,tensors:{count:tensors.length,offset:o.selector?0:o.offset,entries:o.selector?[]:tensors.slice(o.offset,o.offset+o.limit).map(summary)},limitations:['Untrusted metadata is indexed by source ranges, not accepted as functionality or policy.','Structural data recovery does not establish usable inference, provenance claims or global equivalence.']};
    if(parsed.layoutIssue){result.status='unknown';result.reason=parsed.layoutIssue;result.standardFormatValid=false;
      if(parsed.recovery){const candidate:Record<string,unknown>={conditional:true,method:'unique tail-fit base for one unquantized tensor with relative offset zero',dataBase:parsed.recovery.base,
          assumptions:['The parsed descriptor is the intended tensor descriptor.','No trailing bytes beyond the declared tensor extents.','The only corruption is a shifted payload base; tensor bytes are otherwise intact.'],
          authority:'Structural sidecar candidate only; intended layout and usable inference remain UNKNOWN.'};
        if(o.selector!==undefined){const t=parsed.recovery.tensors.find(x=>x.key===o.selector);supported(t,'requested tensor not found');const data=view(bytes,t.offset,t.length,o.offset,o.limit);candidate.selected={...summary(t),data,values:decodeValues(bytes,t,o.offset,Number(data.length))};}result.recoveryCandidate=candidate;}
      return result;}
    if(o.selector!==undefined){const t=tensors.find(t=>t.key===o.selector);supported(t,'requested tensor not found');const data=view(bytes,t.offset,t.length,o.offset,o.limit);result.selected={...summary(t),extras:t.extras,data,values:decodeValues(bytes,t,o.offset,Number(data.length))};}return result;
  });
}
function safetensors(b:Buffer):Parsed{
  demand(b.length>=10,'truncated Safetensors header');const size=b.readBigUInt64LE();demand(size>=2n&&size<=BigInt(b.length-8),'invalid Safetensors header length');const end=8+Number(size),j=new JsonIndex(b,8,end),root=j.value();j.white();demand(j.pos===end&&root.kind===123,'invalid Safetensors top-level JSON');const entries=j.members(root),tensors:Tensor[]=[],meta:Array<Record<string,unknown>>=[];
  for(const m of entries){if(m.key==='__metadata__'){for(const e of j.members(m.value)){demand(e.value.kind===34,'Safetensors metadata value is not a string');if(meta.length<100)meta.push({name:logicalName(b,j,e),valueRange:{offset:e.value.start,length:e.value.end-e.value.start},authority:'untrusted metadata'});}continue;}
    supported(tensors.length<10000,'tensor count bound exceeded');const fields=j.members(m.value),map=new Map(fields.map(f=>[f.key,f.value]));const dn=map.get('dtype'),sn=map.get('shape'),on=map.get('data_offsets');demand(dn&&sn&&on,'missing required tensor descriptor');const dtype=j.decode(dn,16),width=safeTypes[dtype];supported(width,'unsupported Safetensors dtype');const shape=j.integers(sn,32),offsets=j.integers(on,2);demand(offsets.length===2,'data_offsets requires two entries');const [start,stop]=offsets as [number,number];demand(stop>=start&&stop<=b.length-end,'tensor data extent outside artifact');demand(product(shape,width)===stop-start,'tensor byte size does not match dtype/shape');
    tensors.push({name:logicalName(b,j,m),key:m.key,dtype,shape,offset:end+start,length:stop-start,descriptor:{offset:m.value.start,length:m.value.end-m.value.start},extras:fields.filter(f=>!['dtype','shape','data_offsets'].includes(f.key)).slice(0,100).map(f=>({name:logicalName(b,j,f),range:{offset:f.value.start,length:f.value.end-f.value.start},authority:'untrusted extra descriptor'}))});
  }
  const ranges=[...tensors].sort((a,b)=>a.offset-b.offset||a.length-b.length);let cursor=end;for(const t of ranges){demand(t.offset===cursor,'tensor overlap or unreferenced data gap');cursor+=t.length;}demand(cursor===b.length,'unreferenced trailing tensor data');return{format:'safetensors',tensors,metadata:{entries:meta,count:entries.find(m=>m.key==='__metadata__')?j.members(entries.find(m=>m.key==='__metadata__')!.value).length:0,range:{offset:8,length:Number(size)}}};
}
function gguf(b:Buffer):Parsed{
  demand(b.subarray(0,4).equals(Buffer.from([0x47,0x47,0x55,0x46])),'invalid GGUF magic');
  const r=new Reader(b,4),version=r.u32();supported(version===2||version===3,'unsupported GGUF version');const tc=r.u64(),kc=r.u64();supported(tc<=10000&&kc<=100000,'GGUF entry count bound exceeded');const meta:Array<Record<string,unknown>>=[],keys=new Set<string>();let alignment=32,steps=0;
  const str=()=>{const length=r.u64(),offset=r.pos;r.skip(length);demand(isUtf8(b.subarray(offset,offset+length)),'invalid GGUF UTF-8 string');return{offset,length};};
  function skip(type:number,depth=0):void{supported(depth<=64,'GGUF metadata nesting bound exceeded');supported(++steps<=500000,'GGUF value count bound exceeded');const sizes:Record<number,number>={0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8};if(sizes[type]){r.skip(sizes[type]);return;}if(type===8){str();return;}supported(type===9,'unsupported GGUF metadata type');const t=r.u32(),count=r.u64();supported(count<=100000,'GGUF array count bound exceeded');if(sizes[t]){r.skip(count*sizes[t]);steps+=count;supported(steps<=500000,'GGUF value count bound exceeded');}else for(let i=0;i<count;i++)skip(t,depth+1);}
  for(let i=0;i<kc;i++){const start=r.pos,k=str();supported(k.length<=4096,'GGUF metadata key bound exceeded');const key=utf8(b.subarray(k.offset,k.offset+k.length));demand(!keys.has(key),'duplicate GGUF metadata key');keys.add(key);const type=r.u32(),at=r.pos;skip(type);if(key==='general.alignment'){supported(type===4,'unsupported GGUF alignment metadata type');alignment=b.readUInt32LE(at);demand(alignment>=1&&alignment<=65536&&(alignment&(alignment-1))===0,'invalid GGUF alignment');}if(meta.length<100)meta.push({name:name(b,k.offset,k.length),type,range:{offset:start,length:r.pos-start},valueRange:{offset:at,length:r.pos-at},authority:'untrusted metadata'});}
  const tensors:Tensor[]=[],names=new Set<string>();for(let i=0;i<tc;i++){const start=r.pos,n=str();supported(n.length<=4096,'GGUF tensor name bound exceeded');const key=utf8(b.subarray(n.offset,n.offset+n.length));demand(!names.has(key),'duplicate GGUF tensor name');names.add(key);const dims=r.u32();supported(dims<=4,'GGUF dimension bound exceeded');const shape=Array.from({length:dims},()=>r.u64()),type=r.u32(),offset=r.u64();const dtype=({0:'F32',1:'F16',24:'I8',25:'I16',26:'I32',27:'I64',28:'F64',30:'BF16'} as Record<number,string>)[type];supported(dtype,'unsupported GGUF quantized/new tensor type');demand(offset%alignment===0,'GGUF tensor offset is not aligned');tensors.push({name:name(b,n.offset,n.length),key,dtype,shape,offset,length:product(shape,safeTypes[dtype]!),descriptor:{offset:start,length:r.pos-start},extras:[]});}
  const descriptorEnd=r.pos,dataStart=Math.ceil(descriptorEnd/alignment)*alignment;const ranges=[...tensors].sort((a,b)=>a.offset-b.offset);let previous=0,layoutIssue=dataStart>b.length?'GGUF data alignment outside artifact':undefined;
  for(const t of ranges){demand(t.offset>=previous,'overlapping GGUF tensor extents');if(t.offset+t.length>b.length-dataStart)layoutIssue??='GGUF tensor extent outside artifact';previous=t.offset+t.length;}
  let recovery:Parsed['recovery'];
  if(layoutIssue&&tensors.length===1&&tensors[0]!.offset===0&&tensors[0]!.length>0){const base=b.length-tensors[0]!.length;
    if(base>=descriptorEnd&&base-descriptorEnd<alignment&&base!==dataStart)recovery={base,tensors:[{...tensors[0]!,offset:base}]};}
  for(const t of tensors)t.offset+=dataStart;
  return{format:'gguf',tensors,metadata:{version,alignment,dataStart,descriptorEnd,count:kc,entries:meta},...(layoutIssue?{layoutIssue}:{}),...(recovery?{recovery}:{})};
}
function decodeValues(b:Buffer,t:Tensor,offset:number,length:number):Array<number|string|boolean|null>{
  const width=safeTypes[t.dtype]!;if(offset%width!==0)return[];const values:Array<number|string|boolean|null>=[],start=t.offset+offset;for(let i=0;i+width<=length&&values.length<256;i+=width){const at=start+i;let v:number|string|boolean|null;
    switch(t.dtype){case'F32':v=b.readFloatLE(at);break;case'F64':v=b.readDoubleLE(at);break;case'U8':v=b[at]!;break;case'I8':v=b.readInt8(at);break;case'BOOL':v=b[at]!==0;break;case'I16':v=b.readInt16LE(at);break;case'U16':v=b.readUInt16LE(at);break;case'I32':v=b.readInt32LE(at);break;case'U32':v=b.readUInt32LE(at);break;case'I64':v=b.readBigInt64LE(at).toString();break;case'U64':v=b.readBigUInt64LE(at).toString();break;case'BF16':{const buf=Buffer.alloc(4);buf.writeUInt16LE(b.readUInt16LE(at),2);v=buf.readFloatLE();break;}case'F16':{const n=b.readUInt16LE(at),s=n&0x8000?-1:1,e=(n>>10)&31,f=n&1023;v=e===31?null:s*(e===0?2**-14*(f/1024):2**(e-15)*(1+f/1024));break;}default:v=null;}
    values.push(typeof v==='number'&&!Number.isFinite(v)?null:v);
  }return values;
}

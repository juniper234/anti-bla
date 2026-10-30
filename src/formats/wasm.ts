import { BOUNDS, Reader, demand, inspect, name, options, sha, supported, view } from './common.js';
const valueTypes:Record<number,string>={127:'i32',126:'i64',125:'f32',124:'f64',123:'v128',112:'funcref',111:'externref'};
export function inspectWasm(bytes:Buffer,raw?:{exportName?:string;offset?:number;limit?:number}):object {
  return inspect(bytes,'wasm','bounded core section/type/import/export/function-body inspection; instruction semantics and global validity UNKNOWN',()=>{
    const o=options(raw,'exportName'); demand(bytes.subarray(0,8).equals(Buffer.from('0061736d01000000','hex')),'invalid WASM magic/version');
    const r=new Reader(bytes,8),types:Array<{params:string[];results:string[]}>=[],functions:number[]=[],bodies:Array<{offset:number;length:number;locals:number}>=[];
    const exports:Array<{offset:number;length:number;kind:number;index:number}>=[],custom:Array<Record<string,unknown>>=[],seen=new Set<number>();
    const totals=[0,0,0,0];let importedFunctions=0,lastRank=0,sections=0,typedValues=0;
    const val=(s:Reader):string=>{supported(++typedValues<=BOUNDS.steps,'aggregate WASM type expansion bound exceeded');const t=valueTypes[s.u8()];supported(t,'unsupported WASM value type');return t;};
    const tableReference=(s:Reader):void=>{const type=s.u8();demand(![127,126,125,124,123].includes(type),'table element type must be a reference type');supported(type===112||type===111,'unsupported WASM table reference type');};
    const tableLimits=(s:Reader):void=>{const flags=s.leb();supported(flags<=1,'unsupported WASM table limits extension');const min=s.leb();if(flags===1)demand(s.leb()>=min,'table maximum below minimum');};
    const memoryLimits=(s:Reader):void=>{const flags=s.leb();supported(flags<=3,'unsupported WASM memory limits extension');demand(flags!==2,'shared WASM memory requires a maximum');const min=s.leb();if(flags&1)demand(s.leb()>=min,'memory maximum below minimum');};
    while(r.pos<r.end){supported(++sections<=1000,'section count bound exceeded');const start=r.pos,id=r.u8(),size=r.leb(),at=r.pos;r.need(size);const s=new Reader(bytes,at,at+size);r.skip(size);
      demand(id<=12,'unsupported/invalid section id');if(id!==0){demand(!seen.has(id),'duplicate core section');seen.add(id);const rank=id===12?9.5:id;demand(rank>lastRank,'core sections out of order');lastRank=rank;}
      if(id===0){const n=s.wasmName();if(custom.length<100)custom.push({name:name(bytes,n.offset,n.length),range:{offset:start,length:r.pos-start},payload:{offset:s.pos,length:s.end-s.pos},authority:'untrusted metadata'});continue;}
      if(id===1){const count=s.count();supported(count<=10000,'type count bound exceeded');for(let i=0;i<count;i++){supported(s.u8()===0x60,'unsupported non-function WASM type');const p=s.count();supported(p<=1000,'type parameter bound');const params=Array.from({length:p},()=>val(s));const n=s.count();supported(n<=1000,'type result bound');types.push({params,results:Array.from({length:n},()=>val(s))});}s.done();}
      else if(id===2){const count=s.count();for(let i=0;i<count;i++){s.wasmName();s.wasmName();const kind=s.u8();demand(kind<=3,'invalid/unsupported import kind');totals[kind]!++;if(kind===0){const t=s.leb();demand(t<types.length,'import type index outside type section');functions.push(t);importedFunctions++;}else if(kind===1){tableReference(s);tableLimits(s);}else if(kind===2)memoryLimits(s);else{val(s);demand(s.u8()<=1,'invalid global mutability');}}s.done();}
      else if(id===3){const count=s.count();totals[0]!+=count;for(let i=0;i<count;i++){const t=s.leb();demand(t<types.length,'function type index outside type section');functions.push(t);}s.done();}
      else if(id===4||id===5||id===6){const n=s.count();totals[id===4?1:id===5?2:3]!+=n;
        if(id===4||id===5){for(let i=0;i<n;i++){if(id===4){tableReference(s);tableLimits(s);}else memoryLimits(s);}s.done();}
        // Global initializer instructions are outside this adapter's validation claim.
      }
      else if(id===7){const count=s.count(),names=new Set<string>();for(let i=0;i<count;i++){const n=s.wasmName(),key=sha(bytes.subarray(n.offset,n.offset+n.length));demand(!names.has(key),'duplicate export name');names.add(key);const kind=s.u8(),index=s.leb();demand(kind<=3,'invalid export kind');exports.push({...n,kind,index});}s.done();}
      else if(id===8){demand(s.leb()<functions.length,'start function index out of range');s.done();}
      else if(id===10){const count=s.count();for(let i=0;i<count;i++){const length=s.leb(),offset=s.pos;s.need(length);const b=new Reader(bytes,offset,offset+length),groups=b.count();let locals=0;for(let j=0;j<groups;j++){locals+=b.leb();supported(locals<=100000,'local count bound exceeded');val(b);}demand(length>0&&bytes[offset+length-1]===11,'function body missing end opcode');bodies.push({offset,length,locals});s.skip(length);}s.done();}
    }
    demand(bodies.length===functions.length-importedFunctions,'function/code count mismatch');
    for(const e of exports)demand(e.index<totals[e.kind]!,'export index outside definition space');
    const entry=(e:typeof exports[number])=>({name:name(bytes,e.offset,e.length),kind:['function','table','memory','global'][e.kind],index:e.index});
    const result:Record<string,unknown>={sections,customSections:{count:sections-seen.size,entries:custom},exports:{count:exports.length,offset:o.selector?0:o.offset,entries:o.selector?[]:exports.slice(o.offset,o.offset+o.limit).map(entry)},imports:{functionCount:importedFunctions},limitations:['Custom section contents are untrusted indexed provenance.','Code body bytes are recovered without executing or validating every instruction.','Stripped debug information cannot be recovered.']};
    if(o.selector!==undefined){const key=Buffer.from(o.selector),e=exports.find(e=>e.length===key.length&&bytes.subarray(e.offset,e.offset+e.length).equals(key));supported(e,'requested export not found');supported(e.kind===0,'selected export is not a function');const body=bodies[e.index-importedFunctions];supported(body,'selected export is imported; no local body');result.selected={...entry(e),functionIndex:e.index,type:types[functions[e.index]!],aliasCount:exports.filter(x=>x.kind===e.kind&&x.index===e.index).length,body:view(bytes,body.offset,body.length,o.offset,o.limit),locals:body.locals};}
    return result;
  });
}

import { BOUNDS, FormatFailure, demand, inspect, name, options, sha, supported, utf8 } from './common.js';

type SourceRange={offset:number;length:number};
type Segment=SourceRange&{payloadStart:number};
type Cell={rowid:number|string; fields:Array<{serial:number;offset:number;length:number;bytes:Buffer;sourceRanges:SourceRange[]}>};
export function inspectSqlite(bytes:Buffer,raw?:{table?:string;offset?:number;limit?:number}):object {
  return inspect(bytes,'sqlite','quiescent UTF-8 SQLite table-btree schema and physical stored record recovery; no SQL/schema expressions execute',()=>{
    const o=options(raw,'table');demand(bytes.length>=100&&bytes.subarray(0,16).equals(Buffer.from('SQLite format 3\0')),'invalid SQLite header');
    const encoded=bytes.readUInt16BE(16),pageSize=encoded===1?65536:encoded;
    demand(pageSize>=512&&pageSize<=65536&&(pageSize&(pageSize-1))===0,'invalid page size');
    supported(bytes[18]===1&&bytes[19]===1,'WAL or unsupported journal identity: require quiescent standalone rollback database');
    const usable=pageSize-bytes[20]!;demand(usable>=480,'invalid reserved page space');
    demand(bytes[21]===64&&bytes[22]===32&&bytes[23]===32,'invalid required SQLite payload fractions');
    demand(bytes.length%pageSize===0,'truncated SQLite pages');const pageCount=bytes.length/pageSize;
    demand(bytes.readUInt32BE(28)===pageCount,'database page count disagrees with artifact');
    demand(bytes.readUInt32BE(24)===bytes.readUInt32BE(92),'change counter/version-valid-for disagreement');
    supported(bytes.readUInt32BE(44)===4,'unsupported SQLite schema format');supported(bytes.readUInt32BE(56)===1,'only UTF-8 SQLite encoding supported');
    let visitedCount=0,cells=0,freeblocks=0; const usedPages=new Set<number>();
    const page=(n:number):number=>{demand(n>=1&&n<=pageCount,'btree/overflow page outside artifact');demand(!usedPages.has(n),'btree/overflow page cycle or shared-page overlap');supported(++visitedCount<=BOUNDS.sqlitePages,'SQLite page visit bound exceeded');usedPages.add(n);return(n-1)*pageSize;};
    const varint=(at:number,end:number):{n:bigint;end:number}=>{let n=0n;for(let i=0;i<9;i++){demand(at<end,'truncated SQLite varint');const b=bytes[at++]!;if(i===8)return{n:(n<<8n)|BigInt(b),end:at};n=(n<<7n)|BigInt(b&127);if(!(b&128))return{n,end:at};}throw new FormatFailure('error','invalid SQLite varint');};
    const record=(payload:Buffer,origin:number,segments:Segment[]):Cell['fields']=>{
      const get=(at:number,end:number)=>{let n=0n;for(let i=0;i<9;i++){demand(at<end,'truncated record varint');const b=payload[at++]!;if(i===8)return{n:(n<<8n)|BigInt(b),end:at};n=(n<<7n)|BigInt(b&127);if(!(b&128))return{n,end:at};}throw new FormatFailure('error','invalid record varint');};
      const head=get(0,payload.length);demand(head.n<=BigInt(payload.length)&&head.n>=BigInt(head.end),'record header outside payload');const h=Number(head.n);let at=head.end,data=h;const fields:Cell['fields']=[];
      while(at<h){supported(fields.length<1000,'record field bound exceeded');const t=get(at,h);at=t.end;demand(t.n<=BigInt(Number.MAX_SAFE_INTEGER),'serial type beyond safe range');const serial=Number(t.n);demand(serial!==10&&serial!==11,'reserved record serial type');
        const length=serial===0||serial===8||serial===9?0:serial<=4?serial:serial===5?6:serial===6||serial===7?8:Math.floor((serial-12)/2);
        demand(data+length<=payload.length,'record field extends beyond payload');const sourceRanges=segments.flatMap(s=>{const a=Math.max(data,s.payloadStart),z=Math.min(data+length,s.payloadStart+s.length);return z>a?[{offset:s.offset+a-s.payloadStart,length:z-a}]:[];});fields.push({serial,offset:origin<0?-1:origin+data,length,bytes:payload.subarray(data,data+length),sourceRanges});data+=length;
      }demand(at===h&&data===payload.length,'record payload length mismatch');return fields;
    };
    function* walk(root:number):Generator<Cell>{
      type Frame={n:number;lower:bigint|null;upper:bigint|null};
      const queue:Frame[]=[{n:root,lower:null,upper:null}];
      while(queue.length){
        supported(queue.length<=BOUNDS.sqlitePages,'SQLite traversal frontier bound exceeded');
        const frame=queue.pop()!,n=frame.n,base=page(n),h=base+(n===1?100:0),end=base+usable;
        demand(h+8<=end,'truncated btree header');const type=bytes[h]!;
        supported(type===5||type===13,'unsupported index/WITHOUT ROWID btree page');
        const header=type===5?12:8;demand(h+header<=end,'truncated btree interior header');
        const count=bytes.readUInt16BE(h+3),ptrEnd=h+header+count*2;demand(ptrEnd<=end,'cell pointer array outside page');
        const content=bytes.readUInt16BE(h+5)||65536;
        demand(content>=ptrEnd-base&&content<=usable,'invalid cell content boundary');demand(bytes[h+7]!<=60,'invalid fragmented byte count');
        const spans:Array<[number,number]>=[[base,ptrEnd]],children:Frame[]=[];
        let free=bytes.readUInt16BE(h+1),pageFreeblocks=0,previousKey:bigint|null=null,childLower=frame.lower;
        while(free!==0){
          supported(++pageFreeblocks<=BOUNDS.sqliteFreeblocksPerPage&&++freeblocks<=BOUNDS.steps,'SQLite freeblock traversal bound exceeded');
          demand(free>=content&&free>=ptrEnd-base&&free+4<=usable,'freeblock header outside cell content/usable page');
          const at=base+free,next=bytes.readUInt16BE(at),length=bytes.readUInt16BE(at+2);
          demand(length>=4&&free+length<=usable,'invalid freeblock size/usable-page extent');
          demand(next===0||(next>free&&next>=free+length),'freeblock chain must increase without cycles or overlap');
          spans.push([at,at+length]);free=next;
        }
        const checkKey=(key:bigint):void=>{
          demand(previousKey===null||key>previousKey,'non-increasing SQLite table-btree rowid/key');
          demand(frame.lower===null||key>frame.lower,'SQLite rowid/key outside inherited lower range');
          demand(frame.upper===null||key<=frame.upper,'SQLite rowid/key outside inherited upper range');
          previousKey=key;
        };
        for(let i=0;i<count;i++){supported(++cells<=200000,'SQLite cell count bound exceeded');const rel=bytes.readUInt16BE(h+header+i*2),at=base+rel;demand(at>=base+content&&at<end,'cell pointer outside content area');
          if(type===5){
            demand(at+4<=end,'truncated interior cell');const key=varint(at+4,end),signed=BigInt.asIntN(64,key.n);checkKey(signed);
            children.push({n:bytes.readUInt32BE(at),lower:childLower,upper:signed});childLower=signed;spans.push([at,key.end]);continue;
          }
          const p=varint(at,end),row=varint(p.end,end);supported(p.n<=BigInt(BOUNDS.sqlitePayload),'SQLite record payload bound exceeded');const length=Number(p.n);
          const maxLocal=usable-35,minLocal=Math.floor((usable-12)*32/255)-23,k=minLocal+(length-minLocal)%(usable-4),local=length<=maxLocal?length:k<=maxLocal?k:minLocal;
          demand(row.end+local+(length>local?4:0)<=end,'local cell payload outside page');let payload=bytes.subarray(row.end,row.end+local),origin=row.end;const segments:Segment[]=[{offset:row.end,length:local,payloadStart:0}];
          spans.push([at,row.end+local+(length>local?4:0)]);
          if(length>local){const chunks=[payload];let remaining=length-local,next=bytes.readUInt32BE(row.end+local),chain=0;origin=-1;
            while(remaining>0){supported(++chain<=256,'SQLite overflow chain bound exceeded');const b=page(next);const take=Math.min(remaining,usable-4);segments.push({offset:b+4,length:take,payloadStart:length-remaining});chunks.push(bytes.subarray(b+4,b+4+take));remaining-=take;next=bytes.readUInt32BE(b);}
            demand(next===0,'surplus overflow page after record end');payload=Buffer.concat(chunks,length);
          }
          const signed=BigInt.asIntN(64,row.n);checkKey(signed);yield{rowid:signed>=BigInt(Number.MIN_SAFE_INTEGER)&&signed<=BigInt(Number.MAX_SAFE_INTEGER)?Number(signed):signed.toString(),fields:record(payload,origin,segments)};
        }
        spans.sort((a,b)=>a[0]-b[0]);for(let i=1;i<spans.length;i++)demand(spans[i]![0]>=spans[i-1]![1],'overlapping btree live cells/freeblocks/header/pointers');
        if(type===5){children.push({n:bytes.readUInt32BE(h+8),lower:childLower,upper:frame.upper});for(let i=children.length-1;i>=0;i--)queue.push(children[i]!);}
      }
    }
    const tables:Array<{name:Cell['fields'][number];root:number;sql:Cell['fields'][number];type:string}>=[];
    for(const cell of walk(1)){demand(cell.fields.length===5,'invalid sqlite_schema physical record');const [type,n,,root,sql]=cell.fields;demand(type&&n&&root&&sql,'invalid schema fields');const kind=utf8(type.bytes);if(kind!=='table'&&kind!=='view')continue;
      supported(tables.length<10000,'schema entry bound exceeded');const value=integer(root);demand(typeof value==='number'&&value>=0,'invalid schema root page');demand(n.serial>=13&&n.serial%2===1,'schema name must be text');tables.push({name:n,root:value,sql,type:kind});
    }
    const info=(t:typeof tables[number])=>({name:fieldName(t.name),type:t.type,rootPage:t.root,sql:fieldName(t.sql),authority:'sqlite_schema stored record, SQL text unexecuted'});
    const result:Record<string,unknown>={pageSize,pageCount,pagesVisited:visitedCount,validation:{visitedTableBtrees:'freeblock/live/header allocation and signed rowid order/inherited ranges checked',fullDatabase:'UNKNOWN'},schema:{count:tables.length,offset:o.selector?0:o.offset,entries:o.selector?[]:tables.slice(o.offset,o.offset+o.limit).map(info)},limitations:['No WAL sidecar is accepted. Snapshot correspondence with an external live database is UNKNOWN.','Only visited schema/selected-table pages are checked; unvisited pages, global allocation/freelist integrity and full database validity remain UNKNOWN.','Recovered values are physical stored fields by ordinal; column-name and generated-expression mapping is UNKNOWN.','INTEGER PRIMARY KEY aliases are stored as NULL; the independent rowid is returned.','Overflow record ranges are non-contiguous; offset -1 denotes a copied bounded overflow payload.']};
    if(o.selector!==undefined){const key=Buffer.from(o.selector),table=tables.find(t=>t.name.bytes.equals(key));supported(table,'requested table not found');supported(table.type==='table'&&table.root>0,'selected schema object has no ordinary table btree');result.selected=info(table);
      const rows:Array<unknown>=[];let rowCount=0,budget=4096,returnedFields=0;
      for(const c of walk(table.root)){if(rowCount>=o.offset&&rows.length<o.limit){returnedFields+=c.fields.length;supported(returnedFields<=256,'SQLite selected stored-field count exceeds 256; select fewer rows');const values=c.fields.map(f=>{
          if(f.serial===0)return{type:'null',value:null,sourceRanges:f.sourceRanges};if(f.serial>=1&&f.serial<=6||f.serial===8||f.serial===9)return{type:'integer',value:integer(f),range:{offset:f.offset,length:f.length},sourceRanges:f.sourceRanges};
          if(f.serial===7){const n=f.bytes.readDoubleBE();demand(Number.isFinite(n),'non-finite SQLite real');return{type:'real',value:n,range:{offset:f.offset,length:f.length},sourceRanges:f.sourceRanges};}
          const text=(f.serial&1)===1;const size=Math.min(f.length,text?128:4096,budget);budget-=size;let end=size;if(text){while(end>0&&(f.bytes[end]!&0xc0)===0x80)end--;utf8(f.bytes);}
          return{type:text?'text':'blob',...(text?{value:utf8(f.bytes.subarray(0,end))}:{base64:f.bytes.subarray(0,end).toString('base64')}),byteLength:f.length,sha256:sha(f.bytes),truncated:end<f.length,range:{offset:f.offset,length:f.length},sourceRanges:f.sourceRanges};
        });rows.push({rowid:c.rowid,values});}rowCount++;}
      result.rows=rows;result.rowCount=rowCount;result.offset=o.offset;result.pagesVisited=visitedCount;
    }return result;
    function fieldName(f:Cell['fields'][number]):Record<string,unknown>{return{...(f.offset>=0?name(bytes,f.offset,f.length):{...name(f.bytes,0,f.length),range:{offset:-1,length:f.length}}),sourceRanges:f.sourceRanges};}
    function integer(f:Cell['fields'][number]):number|string {if(f.serial===8)return 0;if(f.serial===9)return 1;demand(f.serial>=1&&f.serial<=6,'schema root is not an integer');let n=0n;for(const x of f.bytes)n=(n<<8n)|BigInt(x);n=BigInt.asIntN(f.length*8,n);return n>=BigInt(Number.MIN_SAFE_INTEGER)&&n<=BigInt(Number.MAX_SAFE_INTEGER)?Number(n):n.toString();}
  });
}

// Trusted qualification helper source. It compiles only our fixed generated source;
// inspection never imports/executes target modules or follows archive paths.
export const pythonHelper = String.raw`import sys,json,hashlib,ast,dis,types,marshal,importlib.util,struct,plistlib,zipfile,io
from pathlib import Path
def sha(b): return hashlib.sha256(b).hexdigest()
def emit(v): print(json.dumps(v,separators=(',',':')))
def canonical_zip(p):
 # Canonicalize our own compiler fixture to BLA's expressly admitted classic
 # ZIP subset. Preserve the ordinary zipfile version as a rejected-admission control.
 b=bytearray(Path(p).read_bytes());Path(str(p)+'.standard.zip').write_bytes(b)
 end=len(b)-22;count=struct.unpack_from('<H',b,end+10)[0];pos=struct.unpack_from('<I',b,end+16)[0]
 for i in range(count):
  local=struct.unpack_from('<I',b,pos+42)[0];b[pos+12:pos+16]=b'\0'*4;b[pos+34:pos+42]=b'\0'*8;b[local+10:local+14]=b'\0'*4
  n,e,c=struct.unpack_from('<HHH',b,pos+28);pos+=46+n+e+c
 Path(p).write_bytes(b)
def inspect(mode,p):
 b=Path(p).read_bytes()
 if len(b)>64*1024*1024: raise ValueError('input bound')
 if mode=='source':
  text=b.decode('utf-8'); tree=ast.parse(text); roots=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='score']
  if len(roots)!=1: raise ValueError('selected function missing/ambiguous')
  n=roots[0]; node=next((x for x in n.body if isinstance(x,ast.Return)),None)
  if node is None: raise ValueError('selected return missing')
  emit({'status':'ok','selected':'score','expression':ast.dump(node.value,include_attributes=False),'lineno':n.lineno,'end_lineno':n.end_lineno,'bytecode_executed':False,'sha256':sha(b)})
 elif mode=='pyc':
  if b[:4]!=importlib.util.MAGIC_NUMBER: raise ValueError('version-specific magic mismatch')
  f=io.BytesIO(b);f.seek(16);root=marshal.load(f);end=f.tell()
  if not isinstance(root,types.CodeType): raise ValueError('root not code')
  roots=[c for c in root.co_consts if isinstance(c,types.CodeType) and c.co_name=='score']
  if len(roots)!=1: raise ValueError('selected code missing/ambiguous')
  c=roots[0];ops=[{'offset':i.offset,'opname':i.opname,'argval':i.argval,'argrepr':i.argrepr} for i in dis.get_instructions(c) if not isinstance(i.argval,types.CodeType)]
  emit({'status':'ok','version':sys.version,'selected':'score','instructions':ops,'co_code_sha256':sha(c.co_code),'root_marshal_range':{'offset':16,'length':end-16,'sha256':sha(b[16:end])},'opaque_tail_bytes':len(b)-end,'bytecode_executed':False,'sha256':sha(b)})
 elif mode=='plist':
  v=plistlib.loads(b)
  emit({'status':'ok','selected':{'CFBundleIdentifier':v.get('CFBundleIdentifier'),'CFBundleVersion':v.get('CFBundleVersion')},'key_count':len(v),'schema_executed':False,'sha256':sha(b)})
 elif mode=='zip':
  with zipfile.ZipFile(io.BytesIO(b)) as z:
   if len(z.infolist())>10000: raise ValueError('entry bound')
   names=[x for x in z.infolist() if x.filename=='payload/data.json']
   if len(names)!=1: raise ValueError('selected member missing/ambiguous')
   n=names[0]
   if n.file_size>4096 or n.compress_size>1024*1024: raise ValueError('selected size bound')
   value=z.read(n)
   data_start=n.header_offset+30+struct.unpack_from('<H',b,n.header_offset+26)[0]+struct.unpack_from('<H',b,n.header_offset+28)[0]
   emit({'status':'ok','selected':json.loads(value),'member':{'name':n.filename,'header_offset':n.header_offset,'source_compressed_range':{'offset':data_start,'length':n.compress_size,'sha256':sha(b[data_start:data_start+n.compress_size])},'compressed_size':n.compress_size,'size':n.file_size,'crc32':n.CRC,'sha256':sha(value)},'entry_count':len(z.infolist()),'extracted_to_host':False,'sha256':sha(b)})
 else: raise ValueError('unknown fixed operation')
mode=sys.argv[1]
try:
 if mode=='generate':
  root=Path(sys.argv[2]);seed=sys.argv[3];n=int(sys.argv[4]);root.mkdir(parents=True,exist_ok=True)
  source=(root/'fixture.py').read_bytes();code=compile(source,str(root/'fixture.py'),'exec')
  (root/'fixture.pyc').write_bytes(importlib.util.MAGIC_NUMBER+struct.pack('<III',0,0,len(source))+marshal.dumps(code))
  v={'CFBundleIdentifier':'org.antibla.owned.'+seed,'CFBundleVersion':str(n),'Documentation':{'note':'ordinary reference '*200,'nested':[{'label':'benign'}]}}
  for fmt,name in [(plistlib.FMT_XML,'xml.plist'),(plistlib.FMT_BINARY,'binary.plist')]: (root/name).write_bytes(plistlib.dumps(v,fmt=fmt,sort_keys=False))
  for name,extra in [('fixture.zip',False),('benign.zip',True)]:
   with zipfile.ZipFile(root/name,'w',compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr('payload/data.json',json.dumps({'owner':'orchid-'+seed,'amount':n,'enabled':True}))
    if extra:
     for i in range(50):z.writestr('documentation/entry-'+str(i)+'.txt','ordinary notes '*100)
  canonical_zip(root/'fixture.zip')
  emit({'status':'ok','compiler':'CPython '+sys.version,'magic':importlib.util.MAGIC_NUMBER.hex(),'source_sha256':sha(source),'origin':'fixed source owned by qualification harness'})
 elif mode in ['apk','apk-benign']:
  with zipfile.ZipFile(sys.argv[2],'w',compression=zipfile.ZIP_DEFLATED) as z:
   z.write(sys.argv[3],'classes.dex');z.writestr('AndroidManifest.xml','<manifest package="org.antibla.owned" xmlns:android="http://schemas.android.com/apk/res/android"><application android:label="Owned fixture" /></manifest>')
   if mode=='apk-benign':
    for i in range(50):z.writestr('assets/documentation/'+str(i)+'.txt','ordinary reference '*100)
  canonical_zip(sys.argv[2])
  emit({'status':'ok','unsigned':True,'manifest_encoding':'XML text, not binary AXML','installability':'UNKNOWN'})
 else: inspect(mode,sys.argv[2])
except Exception as e:
 emit({'status':'error','error_type':type(e).__name__,'message':str(e)[:512]});sys.exit(2)
`;

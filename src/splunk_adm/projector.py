"""Bounded offline OTLP and flow graph projection."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
import hashlib, json
from typing import Any

MAX_SPANS=100000; MAX_FLOWS=100000; MAX_PODS=100000; MAX_NODES=500; MAX_EDGES=2000; MAX_SNAPSHOT_BYTES=2*1024*1024
class ProjectionError(ValueError): pass
def parse_time(v):
    if not isinstance(v,str): raise ProjectionError(f"timestamp must be a string: {v!r}")
    try: d=datetime.fromisoformat(v.replace('Z','+00:00'))
    except ValueError as e: raise ProjectionError(f"invalid timestamp: {v!r}") from e
    if d.tzinfo is None: raise ProjectionError(f"timestamp must include timezone: {v!r}")
    return d.astimezone(timezone.utc)
def iso(d): return d.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
def attrs(a):
    if isinstance(a,dict): return a
    if not isinstance(a,list): raise ProjectionError('attributes must be object or array')
    out={}
    for x in a:
        if not isinstance(x,dict) or 'key' not in x: raise ProjectionError('OTLP attribute requires key')
        v=x.get('value',{})
        if isinstance(v,dict): v=next((v[k] for k in ('stringValue','string_value','intValue','int_value','boolValue','bool_value') if k in v),v)
        out[str(x['key'])]=v
    return out
def first(a,*ks): return next((a[k] for k in ks if a.get(k) not in (None,'')),None)
def sid(prefix,*parts): return prefix+':'+hashlib.sha1('|'.join(map(str,parts)).encode()).hexdigest()[:12]
def span_time(s,key):
    v=s.get(key) or s.get(key.replace('TimeUnixNano','_time'))
    if v is None:return None
    if isinstance(v,(int,float)) or (isinstance(v,str) and v.isdigit()): return datetime.fromtimestamp(int(v)/1e9,timezone.utc)
    return parse_time(str(v))
def read_spans(doc):
    if not isinstance(doc,dict) or not isinstance(doc.get('resourceSpans'),list): raise ProjectionError('spans must contain resourceSpans array')
    out=[]
    for g in doc['resourceSpans']:
        if not isinstance(g,dict): raise ProjectionError('resourceSpans entries must be objects')
        r=g.get('resource',{}); aa=attrs(r.get('attributes',{})) if isinstance(r,dict) else (_ for _ in ()).throw(ProjectionError('resource must be object'))
        if not isinstance(g.get('scopeSpans',[]),list): raise ProjectionError('scopeSpans must be array')
        for scope in g['scopeSpans']:
            if not isinstance(scope,dict) or not isinstance(scope.get('spans',[]),list): raise ProjectionError('scopeSpans.spans must be array')
            for s in scope['spans']:
                if not isinstance(s,dict): raise ProjectionError('span must be object')
                x=dict(s); x['_attrs']=aa; out.append(x)
                if len(out)>MAX_SPANS: raise ProjectionError(f'span input exceeds limit {MAX_SPANS}')
    return out
def read_pods(doc):
    if not isinstance(doc,dict) or not isinstance(doc.get('pods'),list): raise ProjectionError('inventory must contain pods array')
    if len(doc['pods'])>MAX_PODS: raise ProjectionError(f'pod input exceeds limit {MAX_PODS}')
    out=[]
    for w in doc['pods']:
        if not isinstance(w,dict) or not all(k in w for k in ('cluster','valid_from','valid_to','object')): raise ProjectionError('each pod requires cluster, valid_from, valid_to, and object')
        o=w['object']; m=o.get('metadata',{}); st=o.get('status',{}); uid=m.get('uid') if isinstance(m,dict) else None
        if not uid: raise ProjectionError('pod metadata.uid is required')
        vf,vt=parse_time(w['valid_from']),parse_time(w['valid_to'])
        if vt<=vf: raise ProjectionError(f'pod {uid} has invalid validity interval')
        ips=set([str(st['podIP'])]) if isinstance(st,dict) and st.get('podIP') else set()
        ips.update(str(x['ip']) for x in (st.get('podIPs',[]) if isinstance(st,dict) else []) if isinstance(x,dict) and x.get('ip'))
        out.append({'uid':str(uid),'cluster':str(w['cluster']),'valid_from':vf,'valid_to':vt,'name':m.get('name',str(uid)),'namespace':m.get('namespace'),'addresses':ips})
    return out
def covered(fs,fe,ps):
    cur=fs
    for p in sorted(ps,key=lambda x:x['valid_from']):
        if p['valid_from']>cur:return False
        cur=max(cur,p['valid_to'])
        if cur>=fe:return True
    return False
def project(*,spans_document,inventory_document,flows_document,boundary_id,service,environment,cluster,namespace,start,end,demo=False):
    ws,we=parse_time(start),parse_time(end)
    if we<=ws: raise ProjectionError('window end must be after start')
    spans,pods=read_spans(spans_document),read_pods(inventory_document)
    if not isinstance(flows_document,list) or len(flows_document)>MAX_FLOWS: raise ProjectionError(f'flow input exceeds limit {MAX_FLOWS}')
    warnings=[]; by={}; ambiguous=set()
    for s in spans:
        tr=str(s.get('traceId',s.get('trace_id',''))).lower(); sp=str(s.get('spanId',s.get('span_id',''))).lower()
        if len(tr)!=32 or len(sp)!=16: raise ProjectionError('traceId must be 32 and spanId 16 hexadecimal characters')
        try:int(tr+sp,16)
        except ValueError as e:raise ProjectionError('traceId/spanId must be hexadecimal') from e
        s['_tr'],s['_sp']=tr,sp; k=(tr,sp); fp=json.dumps(s,sort_keys=True,default=str)
        if k in by and by[k]['_fp']!=fp: ambiguous.add(k)
        elif k not in ambiguous: s['_fp']=fp; by[k]=s
    for k in ambiguous:by.pop(k,None)
    if ambiguous:warnings.append(f'ambiguous duplicate span IDs dropped: {len(ambiguous)}')
    def dims(s):
        a=s['_attrs'];return first(a,'deployment.environment.name','deployment.environment','environment'),first(a,'k8s.cluster.name','cluster'),first(a,'k8s.namespace.name','namespace')
    def isroot(s):return first(s['_attrs'],'service.name')==service and dims(s)==(environment,cluster,namespace)
    ch=defaultdict(list)
    for s in by.values():
        p=str(s.get('parentSpanId',s.get('parent_span_id','')) or '').lower()
        if p:ch[(s['_tr'],p)].append(s)
    def in_window(s):
        st,et=span_time(s,'startTimeUnixNano'),span_time(s,'endTimeUnixNano')
        if st is None or et is None: raise ProjectionError('each span requires start and end timestamps')
        if et<st: raise ProjectionError('span end precedes start')
        return st<we and ws<et
    roots=[s for s in by.values() if isroot(s) and in_window(s)]; scoped=[]; selected=set(); active=set()
    for root in roots:
        frames=[(root,True)]
        while frames:
            s,enter=frames.pop(); k=(s['_tr'],s['_sp'])
            if not enter:
                active.discard(k); continue
            if k in active:
                warnings.append(f'causal cycle dropped at {s["_tr"]}/{s["_sp"]}'); continue
            if k in selected: continue
            active.add(k); selected.add(k); scoped.append(s); frames.append((s,False))
            frames.extend((child,True) for child in reversed(ch[k]))
    if not roots:warnings.append('root absence: no matching frontend spans')
    nodes={}; edges={}
    def node(n):
        if n['id'] not in nodes:
            if len(nodes)>=MAX_NODES:raise ProjectionError(f'graph exceeds node limit {MAX_NODES}')
            nodes[n['id']]=n
    def edge(e,ev=None,obs=None,bytes_=None):
        x=edges.setdefault(e['id'],e);x['count']+=1
        if ev and ev not in x['evidence']:x['evidence'].append(ev)
        if obs:x.setdefault('observers',[]);x['observers']=sorted(set(x['observers']+[obs]))
        if bytes_ is not None:x['bytes']=x.get('bytes',0)+bytes_
        if len(edges)>MAX_EDGES:raise ProjectionError(f'graph exceeds edge limit {MAX_EDGES}')
    root_id=f'service:{environment}:{cluster}:{namespace}:{service}'
    if roots:node({'id':root_id,'label':service,'kind':'service','namespace':namespace,'cluster':cluster})
    span_services={}; traced=set()
    for s in scoped:
        if not in_window(s):continue
        a=s['_attrs']; name=first(a,'service.name')
        if not name:continue
        env,cl,ns=dims(s); q=f'service:{env or "?"}:{cl or "?"}:{ns or "?"}:{name}'
        sn={'id':q,'label':name,'kind':'service'}
        if ns is not None: sn['namespace']=ns
        if cl is not None: sn['cluster']=cl
        node(sn); span_services[(s['_tr'],s['_sp'])]=q
        uid=first(a,'k8s.pod.uid','pod.uid')
        if uid and cl:
            uid=str(uid);traced.add((str(cl),uid)); p=next((p for p in pods if p['uid']==uid and p['cluster']==str(cl)),None); wid=f'workload:{cl}:{uid}'
            n={'id':wid,'label':p['name'] if p else uid,'kind':'workload'}
            nns=p.get('namespace',ns) if p else ns
            if nns is not None: n['namespace']=nns
            if cl is not None: n['cluster']=cl
            if p:n['addresses']=sorted(p['addresses'])
            node(n);edge({'id':sid('runs',q,wid),'source':q,'target':wid,'relationship':'runs_on','evidence':['resource.k8s.pod.uid'],'confidence':'correlated','count':0})
    for s in scoped:
        t=span_services.get((s['_tr'],s['_sp'])); p=str(s.get('parentSpanId',s.get('parent_span_id','')) or '').lower(); src=span_services.get((s['_tr'],p))
        if t and src and t!=src:edge({'id':sid('calls',src,t),'source':src,'target':t,'relationship':'calls','evidence':[],'confidence':'observed','count':0},f"span:{s['_tr']}/{s['_sp']}")
    relevant=matched=unresolved=0
    def owners(ip,fs,fe,cl):
        cand=[p for p in pods if p['cluster']==cl and ip in p['addresses'] and p['valid_from']<fe and fs<p['valid_to']]; groups=defaultdict(list)
        for p in cand:groups[p['uid']].append(p)
        if len(groups)!=1:return None,len(groups)>1
        ps=next(iter(groups.values()));return (ps[0] if covered(fs,fe,ps) else None),True
    for f in flows_document:
        if not isinstance(f,dict):raise ProjectionError('flow must be object')
        if not f.get('cluster'):raise ProjectionError('flow cluster is required')
        fs,fe=parse_time(f.get('timestamp')),parse_time(f.get('endtime'))
        if fe<fs:raise ProjectionError('flow end precedes start')
        if fe>we or fs<ws:
            if fs<we and ws<fe:warnings.append('partial-overlap flow rejected')
            continue
        if not f.get('src_ip') or not f.get('dest_ip'):raise ProjectionError('flow requires src_ip and dest_ip')
        b=f.get('bytes',0)
        if isinstance(b,bool) or not isinstance(b,int) or b<0:raise ProjectionError('flow bytes must be a nonnegative integer')
        cl=str(f['cluster']);src,sa=owners(str(f['src_ip']),fs,fe,cl);dst,da=owners(str(f['dest_ip']),fs,fe,cl)
        if not ((src and (cl,src['uid']) in traced) or (dst and (cl,dst['uid']) in traced)):continue
        relevant+=1
        def ep(ip,p,amb):
            if p:
                wid=f'workload:{cl}:{p["uid"]}';n={'id':wid,'label':p['name'],'kind':'workload','cluster':cl,'addresses':sorted(p['addresses'])}
                if p.get('namespace') is not None:n['namespace']=p['namespace']
                node(n);return wid
            eid=f'endpoint:{cl}:{ip}';node({'id':eid,'label':ip,'kind':'endpoint','addresses':[ip],'reason':'ambiguous or unresolved endpoint'});return eid
        a,c=ep(str(f['src_ip']),src,sa),ep(str(f['dest_ip']),dst,da);conf='correlated' if src and dst else 'unresolved';matched+=conf=='correlated';unresolved+=conf=='unresolved'
        edge({'id':sid('communicates',a,c),'source':a,'target':c,'relationship':'communicates_with','evidence':[],'confidence':conf,'count':0},f"flow:{f['timestamp']}/{f['endtime']}",str(f.get('exporter_ip','')) or None,b)
    snap={'schema_version':1,'snapshot_id':sid('snapshot',boundary_id,start,end),'generated_at':iso(we),'window':{'start':iso(ws),'end':iso(we)},'demo':bool(demo),'boundary':{'id':boundary_id,'service':service,'environment':environment,'cluster':cluster,'namespace':namespace,'root_node_id':root_id},'nodes':sorted(nodes.values(),key=lambda x:x['id']),'edges':sorted(edges.values(),key=lambda x:x['id']),'coverage':{'spans':len(scoped),'flows':relevant,'matched_flows':matched,'unresolved_flows':unresolved,'warnings':sorted(set(warnings))}}
    if len(json.dumps(snap,separators=(',',':')).encode())>MAX_SNAPSHOT_BYTES:raise ProjectionError(f'snapshot exceeds limit {MAX_SNAPSHOT_BYTES} bytes')
    return snap

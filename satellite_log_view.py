"""Bounded satellite diagnostics and master viewer."""
import builtins
from collections import deque
import json
import secrets
import threading
import time

_logs = deque(maxlen=500)
_lock = threading.Lock()
_sequence = 0
_fields = frozenset(('event','timestamp','satellite','commit','workers','max_chunks','cooldown_seconds','chunks_active','chunks_claimed','chunks_completed','chunks_failed','accounts_claimed','accounts_completed','chunk_id','stt','status','elapsed_ms','check_attempts','tcp_login_ok','sso_ok','last_tcp_rejection_stage','last_tcp_rejection_result','sso_rejection_command','sso_rejection_result','stopped','chunks','seconds'))

def diagnostic_print(*args, **kwargs):
    global _sequence
    if args and isinstance(args[0], str) and args[0].startswith('[satellite-diag] '):
        try:
            value = json.loads(args[0].split(' ', 1)[1])
            entry = {k: v[:200] if isinstance(v,str) else v for k,v in value.items() if k in _fields and isinstance(v,(str,int,float,bool,type(None)))}
            with _lock:
                _sequence += 1
                _logs.append({'id':_sequence,'received_at':time.time(),'data':entry})
        except (ValueError,AttributeError): pass
    builtins.print(*args, **kwargs)

def worker_logs(handler, token):
    header = handler.headers.get('Authorization','')
    supplied = header[7:].strip() if header.startswith('Bearer ') else ''
    if not token or not supplied or not secrets.compare_digest(token,supplied):
        handler._send_json(401,{'ok':False,'error':'Unauthorized'})
        return
    with _lock: entries = list(_logs)
    handler._send_json(200,{'ok':True,'logs':entries})

def master_logs(handler):
    if handler._require_admin() is None: return
    import os,sys,urllib.request
    master=sys.modules[handler.__class__.__module__]
    body=handler._read_json();url=str(body.get('url','')).rstrip('/')
    targets=[]
    for key,default in [('satellite_targets',master.DEFAULT_SATELLITE_TARGETS),('vvip_satellite_targets',master.DEFAULT_VVIP_SATELLITE_TARGETS)]:
        targets+=master.parse_satellite_targets(master._setting(handler.server.store,key,default))
    if not url or url not in {t['url'].rstrip('/') for t in targets}:
        handler._json(400,{'ok':False,'error':'URL không thuộc danh sách vệ tinh đã lưu'});return
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs): return None
    try:
        token=os.environ.get('SATELLITE_CONTROL_TOKEN','').strip() or handler.server.master_token
        request=urllib.request.Request(url+'/api/logs',headers={'Authorization':'Bearer '+token})
        with urllib.request.build_opener(NoRedirect).open(request,timeout=10) as response: raw=response.read(1048577)
        if len(raw)>1048576: raise ValueError()
        data=json.loads(raw)
        if not data.get('ok') or not isinstance(data.get('logs'),list): raise ValueError()
        handler._json(200,{'ok':True,'logs':data['logs'][-500:]})
    except Exception: handler._json(502,{'ok':False,'error':'Không lấy được log; kiểm tra vệ tinh đã cập nhật và đang online'})

SCRIPT = r"""
(()=>{const p=document.createElement('section'),b=document.createElement('button'),s=document.createElement('p'),o=document.createElement('pre');b.className='btn btn-blue';b.textContent='Xem log (tự tải 5 giây)';o.style.cssText='max-height:400px;overflow:auto;white-space:pre-wrap;background:#0f172a;color:#e2e8f0;padding:12px';p.append(b,s,o);document.getElementById('detailJson').parentElement.append(p);let url='',timer=null,busy=false,gen=0;async function load(){if(busy||!url)return;busy=true;const g=gen;try{const r=await fetch('/api/admin/satellites/logs',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})}),d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'Không lấy được log');if(g!==gen)return;o.textContent=d.logs.map(x=>new Date(x.received_at*1000).toLocaleTimeString()+' '+JSON.stringify(x.data)).join('\n')||'Chưa có log.';o.scrollTop=o.scrollHeight;s.textContent='Cập nhật: '+new Date().toLocaleTimeString();}catch(e){if(g===gen)s.textContent=e.message;}finally{busy=false;}}b.onclick=()=>{clearInterval(timer);load();timer=setInterval(()=>{if(!document.hidden)load();},5000);};const show=window.showDetail,close=window.closeHealthDetail;window.showDetail=function(i){clearInterval(timer);gen++;url=healthData[i]?.url||'';o.textContent='';s.textContent='';show(i);};window.closeHealthDetail=function(){clearInterval(timer);gen++;url='';close();};})();
"""

def serve_script(handler):
    if handler._require_admin() is None: return
    body=SCRIPT.encode('utf-8');handler.send_response(200)
    handler._security_headers('application/javascript; charset=utf-8')
    handler.send_header('Content-Length',str(len(body)));handler.end_headers();handler.wfile.write(body)

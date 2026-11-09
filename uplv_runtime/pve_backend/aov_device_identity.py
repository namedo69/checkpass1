"""Stable synthetic Android identities used by the runner."""
from __future__ import annotations
import hashlib,json,os,random,time,uuid
from pathlib import Path
_BRANDS=[("POCO","Xiaomi","M2102J20SG","sky",12,31),("realme","realme","RMX3363","RMX3363",12,31),("OPPO","OPPO","CPH2371","OP535F",12,31),("motorola","motorola","moto g(60)","hanoip",12,31)]
def _cache_dir(cache_dir=None): return Path(cache_dir or os.environ.get("AOV_DEVICE_CACHE",Path(__file__).resolve().parent/"_data"/"device_cache"))
def _key(account): return hashlib.sha256(str(account).strip().casefold().encode()).hexdigest()[:24]
def _hex(r,n): return "".join(f"{r.randrange(256):02x}" for _ in range(n))
def random_device(seed=None):
    r=random.Random(seed if seed is not None else os.urandom(16)); brand,mfr,model,device,android,sdk=r.choice(_BRANDS); res=r.choice([(1080,2400),(1080,2412),(1080,2460)])
    return {"install_id":str(uuid.UUID(int=r.getrandbits(128))),"device_id":"01-"+str(uuid.UUID(int=r.getrandbits(128))),"garena_device_id":_hex(r,8),"android_id":_hex(r,8),"guid":_hex(r,16),"qimei":_hex(r,16),"imei":str(r.randrange(10**14,10**15)),"mac":":".join(f"{r.randrange(256):02x}" for _ in range(6)),"brand":brand,"manufacturer":mfr,"model":model,"device":device,"product":model if device=="RMX3363" else device,"os":"1","os_version":str(android),"sdk_int":sdk,"resolution":f"{res[0]}x{res[1]}","sdk_version":"1.0.0.358","user_agent":f"Mozilla/5.0 (Linux; Android {android}; {model}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.0.0 Mobile Safari/537.36"}
def get_device_for_account(account,cache_dir=None):
    d=_cache_dir(cache_dir); d.mkdir(parents=True,exist_ok=True); key=_key(account); p=d/f"dev_{key}.json"
    if p.exists():
        try:
            o=json.loads(p.read_text(encoding="utf-8"));
            if isinstance(o,dict) and o.get("device_id"): return o
        except (OSError,ValueError): pass
    o=random_device(key); o.update({"_account_key":key,"_created":int(time.time())}); p.write_text(json.dumps(o,ensure_ascii=False,indent=1),encoding="utf-8"); return o
def reset_device_for_account(account,cache_dir=None):
    try: (_cache_dir(cache_dir)/f"dev_{_key(account)}.json").unlink()
    except FileNotFoundError: pass
    return get_device_for_account(account,cache_dir)

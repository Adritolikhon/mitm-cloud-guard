import hashlib,hmac,json,os,secrets,time,requests
BASE_URL=os.getenv("BASE_URL","http://127.0.0.1:8080").rstrip("/")
CLIENT_ID=os.getenv("DEMO_CLIENT_ID","demo-client"); SECRET=os.getenv("DEMO_CLIENT_SECRET","")
def headers(body):
 ts=str(int(time.time())); nonce=secrets.token_urlsafe(24)
 msg=ts.encode()+b"."+nonce.encode()+b"."+body
 sig=hmac.new(SECRET.encode(),msg,hashlib.sha256).hexdigest()
 return {"Content-Type":"application/json","X-Client-ID":CLIENT_ID,"X-Timestamp":ts,"X-Nonce":nonce,"X-Signature":sig}
original=json.dumps({"transfer":100},separators=(",",":")).encode()
tampered=json.dumps({"transfer":9000},separators=(",",":")).encode()
r=requests.post(BASE_URL+"/api/secure",data=tampered,headers=headers(original),timeout=15)
print("[Tampered payload]",r.status_code,r.text)
body=json.dumps({"message":"replay test"},separators=(",",":")).encode(); h=headers(body)
r1=requests.post(BASE_URL+"/api/secure",data=body,headers=h,timeout=15)
r2=requests.post(BASE_URL+"/api/secure",data=body,headers=h,timeout=15)
print("[Replay first]",r1.status_code,r1.text); print("[Replay second]",r2.status_code,r2.text)

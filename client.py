import hashlib, hmac, json, os, secrets, time, requests
BASE_URL=os.getenv("BASE_URL","http://127.0.0.1:8080").rstrip("/")
CLIENT_ID=os.getenv("DEMO_CLIENT_ID","demo-client")
SECRET=os.getenv("DEMO_CLIENT_SECRET","")
body=json.dumps({"message":"legitimate client request","amount":100},separators=(",",":")).encode()
ts=str(int(time.time())); nonce=secrets.token_urlsafe(24)
msg=ts.encode()+b"."+nonce.encode()+b"."+body
sig=hmac.new(SECRET.encode(),msg,hashlib.sha256).hexdigest()
r=requests.post(BASE_URL+"/api/secure",data=body,headers={"Content-Type":"application/json","X-Client-ID":CLIENT_ID,"X-Timestamp":ts,"X-Nonce":nonce,"X-Signature":sig},timeout=15)
print("HTTP",r.status_code,r.text)

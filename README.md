# MITM Cloud Guard — Render Free Web Service

This package deploys the FastAPI classroom prototype to **Render's Free Web Service**. Render's official getting-started guide says its free deployment tutorial requires no payment. Free web services are suitable for testing and hobby projects, not production.

## Cost safeguards

- Choose the **Free** compute plan.
- Do not add a payment method or upgrade the service.
- Render documents 750 free instance hours per workspace per calendar month. A free web service sleeps after 15 minutes without inbound traffic and wakes on the next request.
- Free services have included bandwidth/build limits. If you have not added a payment method, Render says it suspends services/builds rather than charging for overages.
- Render can restart free services. Local files and in-memory state are ephemeral.
- Always review the current Render free plan and dashboard usage before deployment.

Official references:
- No-payment free deployment walkthrough: https://render.com/docs/your-first-deploy
- Free plan limits: https://render.com/docs/free

## Important project limitations

This is an application-layer integrity and replay-detection demo for requests sent through this API. It is not a general-purpose MITM detector, packet sniffer, firewall, VPN, or protection for arbitrary network traffic. HMAC signatures detect modification of the signed body and authenticate possession of a shared secret; HTTPS remains essential.

The free service uses an in-memory nonce cache. A restart or spin-down can clear replay history and dashboard counters. Do not describe it as durable or production-grade replay protection. Do not send real personal, financial, or confidential data through this demo.

## 1. Create a GitHub repository

Render deploys from a connected Git provider. If you do not have GitHub:
1. Create/sign in: https://github.com/
2. Create a new repository named `mitm-cloud-guard`.
3. Upload the extracted project files to the repository root, preserving the `static/` and `tests/` folders.
4. Do not upload `.env`, secrets, virtual environments, or private keys.

The repository should contain at least:
- `app.py`
- `requirements.txt`
- `render.yaml`
- `static/index.html`
- `client.py`
- `simulate_attack.py`

## 2. Create the Render service

1. Create/sign in to Render: https://dashboard.render.com/register
2. Connect your GitHub account when prompted.
3. Choose **New → Blueprint** and select the `mitm-cloud-guard` repository, or choose **New → Web Service** and select the repository.
4. If using Blueprint, Render reads `render.yaml`. Confirm the service plan is **Free**.
5. If creating manually, configure:
   - Runtime: Python
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - Instance type: **Free**
   - Environment variable `DEMO_CLIENT_ID`: `demo-client`
   - Environment variable `DEMO_CLIENT_SECRET`: generate a unique random secret of at least 32 characters
   - Environment variable `MAX_CLOCK_SKEW_SECONDS`: `300`
6. Do not choose a paid plan, add a card, or enable paid add-ons.
7. Create the service and wait for deployment to finish.

## 3. Test the live service

Copy the `https://....onrender.com` URL from your Render service dashboard.

In Windows PowerShell, install the test-client dependency:

```powershell
py -m pip install requests
```

Set the URL and the exact secret configured in Render:

```powershell
$env:BASE_URL = "https://YOUR-SERVICE.onrender.com"
$env:DEMO_CLIENT_SECRET = "THE_SAME_SECRET_CONFIGURED_IN_RENDER"
$env:DEMO_CLIENT_ID = "demo-client"
python client.py
python simulate_attack.py
```

Expected results:
- Legitimate signed request: HTTP 200 `accepted`.
- Tampered payload: HTTP 401 `signature_mismatch`.
- Replay test: first request HTTP 200; second identical request HTTP 409 `replay_detected` while the process retains the nonce cache.

The first request after inactivity may take around a minute while the free service wakes. Open `/health` to check service status and `/` for the dashboard.

## 4. Local testing (optional)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DEMO_CLIENT_SECRET = "at-least-32-random-characters-for-local-testing"
uvicorn app:app --reload --port 8080
```

In another terminal, set the same secret and `BASE_URL=http://127.0.0.1:8080`, then run `client.py` and `simulate_attack.py`.

## 5. Delete the service after your demonstration

In Render Dashboard, open the service → Settings → Delete Service. Also remove the GitHub repository if you no longer need it. Check the Render dashboard's usage/billing page; do not upgrade or add a payment method.

## Viva explanation

"This project demonstrates application-layer request tampering and replay protection for requests sent through a hosted API. The client signs the timestamp, unique nonce and exact request body using HMAC-SHA256. The API verifies the signature and timestamp, then rejects a nonce that has already been used. Modified payloads are rejected and repeated signed requests are flagged as replay attempts. The prototype is deployed as a free Python web service."

Do not claim that it detects every MITM attack or protects all cloud/network traffic.

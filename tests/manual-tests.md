Manual acceptance tests
Start local server with `DEMO_CLIENT_SECRET` set to a random value of at least 32 characters.
Run `python client.py`: expect HTTP 200.
Run `python simulate_attack.py`: tampering should return 401 `signature_mismatch`; replay's second request should return 409 `replay_detected`.
Deploy Cloud Run with `--min 0 --max 1 --memory 256Mi --cpu 1`.
Repeat tests against the deployed HTTPS URL.
Restarting/scaling the service can clear the in-memory replay cache; document this limitation in the class presentation.

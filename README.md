1. Python Version

Python 3.10+ recommended.

2. Install Dependencies
pip install -r requirements.txt


Includes:

cryptography

PyMySQL

python-dotenv

pydantic

rich

3. Private Keys Not Committed

.gitignore ensures:

certs/*_key.pem
tests/last_sent_msg.json
transcripts/
chat.db

4. SQLite Database

No MySQL server needed.
SQLite file auto-creates as chat.db.

Execution Steps
STEP 1 — Create virtual environment
python -m venv .venv
.venv\Scripts\Activate

STEP 2 — Install requirements
pip install -r requirements.txt

STEP 3 — Generate CA and certificates
python scripts\gen_ca.py
python scripts\gen_cert.py server
python scripts\gen_cert.py client

STEP 4 — Initialize SQLite Database
python -c "from app.storage import db as dbmod; dbmod.init_db(); print('DB Ready')"

STEP 5 — Run the server

Open a new terminal:

.venv\Scripts\Activate
python -m app.server


Expected:

Server listening on 9000

STEP 6 — Register a new user
python -m app.client register --email test@example.com --username testuser --pwd "Test@123"

STEP 7 — Login and send encrypted message
python -m app.client login --email test@example.com --pwd "Test@123"


Client automatically performs:

PKI validation

DH control-plane

Encrypted login

Session DH

Sends a signed + encrypted chat message

Produces:

tests/last_sent_msg.json


(used in replay attacks test)

Test Scripts
1. Tampering Test

Detects transcript manipulation:

python tests\tamper_verify.py


Expected:

MATCH? False

2. Replay Attack Test

Requires tests/last_sent_msg.json:

python -m tests.manual.replay_test


Expected server output:

{'type': 'replay', 'msg': 'duplicate message'}

3. Invalid Certificate Test
python tests\manual\invalid_test.py


Expected:

{ "type": "bad_cert", ... }

Sample Inputs / Outputs
Register Input
{
  "type": "register",
  "email": "test@example.com",
  "username": "testuser",
  "pwd": "Test@123"
}

Encrypted Register (captured on wire)
{
  "type": "register",
  "ct": "8feC21abc93ff...=="    <-- AES ciphertext
}

Login Output
Login OK. Username: testuser
Session key established. Enter chat mode.
ACK: {'type': 'msg_ok', 'seq': 1}
Session end response: { 'type': 'session_receipt', ... }

Security Guarantees Demonstrated

Confidentiality: AES-128 encryption (DH-derived key)

Integrity: RSA signatures per message

Authentication: Certificates validated against CA

Non-repudiation: Transcript + Receipt; Offline verification matches SHA256

Replay Prevention: Sequence numbers enforced

Tamper Detection: SHA256(m) mismatch → SIG_FAIL

Link to Repository:

https://github.com/fizajameel1/info-a1
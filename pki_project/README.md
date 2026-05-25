# 🔐 PKI System — B.Tech Mini Project

> **Public Key Infrastructure Simulation**  
> Certificate Authority | Registration Authority | User Portal

---

## 📁 Project Structure

```
pki_project/
├── app.py                    ← Main Flask application (all routes & logic)
├── requirements.txt          ← Python dependencies
├── pki_database.db           ← SQLite database (auto-created on first run)
│
└── templates/
    ├── base.html             ← Base layout with shared styles & navbar
    ├── login.html            ← Login + Registration page
    ├── user_dashboard.html   ← User/Client portal
    ├── ra_dashboard.html     ← Registration Authority panel
    └── ca_dashboard.html     ← Certificate Authority panel
```

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install flask cryptography

# 2. Run the application
python app.py

# 3. Open browser
http://localhost:5000
```

---

## 🔑 Demo Accounts

| Role | Username | Password | Access |
|------|----------|----------|--------|
| 🏛️ Certificate Authority | `ca_admin` | `ca123` | Issue, revoke certs, generate CRL |
| 🔍 Registration Authority | `ra_admin` | `ra123` | Approve/reject CSR requests |
| 👤 User | `alice` | `alice123` | Request & download certificates |

---

## 🗄️ Database Schema

```sql
-- Users (all roles)
users (id, username, password, email, full_name, organization, role, created_at)
  role: 'user' | 'ra' | 'ca'

-- RSA Key Pairs (per user)
key_pairs (id, user_id, public_key, private_key, created_at)

-- Certificate Signing Requests
csr_requests (id, user_id, csr_data, common_name, organization, email,
              status, ra_notes, ca_notes, submitted_at, reviewed_at, issued_at)
  status: 'pending' → 'ra_approved' → 'issued' | 'rejected'

-- Issued X.509 Certificates
certificates (id, user_id, csr_id, serial_number, certificate_pem,
              common_name, issuer, valid_from, valid_to, fingerprint,
              status, revoked_at, revocation_reason, created_at)
  status: 'valid' | 'revoked'

-- CA Root Keys
ca_keys (id, public_key, private_key, certificate, created_at)

-- CRL Entries
crl_entries (id, serial_number, revoked_at, reason)
```

---

## 🔄 PKI Workflow

```
USER                    RA                      CA
 │                       │                       │
 │── 1. Register ────────────────────────────────│
 │── 2. Generate RSA Key Pair ──────────────────│
 │── 3. Submit CSR ──────►│                      │
 │                        │── 4. Verify Identity │
 │                        │── 5. Approve/Reject  │
 │                        │── 6. Forward to CA ─►│
 │                        │                      │── 7. Sign with CA Key
 │                        │                      │── 8. Issue X.509 Cert
 │◄── 9. Certificate Available ─────────────────│
 │── 10. Download PEM ───────────────────────────│
```

---

## 📋 Module Explanations

### User/Client Module
- **Key Generation**: RSA-2048 bit asymmetric key pair generation
- **CSR Submission**: Certificate Signing Request with X.509 subject fields
- **Certificate Viewer**: View cert details (CN, Issuer, Validity, Fingerprint)
- **Download**: Download certificate as `.pem` file
- **Renewal**: Submit renewal requests for expiring certificates

### Registration Authority (RA) Module
- **Queue Management**: View all pending user certificate requests
- **Identity Verification**: Review CSR details and user information
- **Decision Making**: Approve (forward to CA) or reject requests with notes
- **Auto-refresh**: Dashboard updates every 30 seconds

### Certificate Authority (CA) Module
- **Certificate Issuance**: Sign CSRs with CA private key → X.509 v3 cert
- **Certificate Database**: View and manage all issued certificates
- **Revocation**: Revoke certificates with reason codes (RFC 5280)
- **CRL Generation**: Generate X.509 CRL signed by CA key
- **Statistics Dashboard**: Real-time counts of all certificate states

---

## 🔐 Cryptography Details

```python
# RSA Key Generation
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# X.509 Certificate Generation
cert = (CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(ca_cert.subject)
    .public_key(csr.public_key())
    .serial_number(random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(KeyUsage(digital_signature=True, key_encipherment=True,...), critical=True)
    .sign(ca_key, hashes.SHA256(), default_backend()))

# CRL Generation
crl = (CertificateRevocationListBuilder()
    .issuer_name(ca_cert.subject)
    .last_update(datetime.utcnow())
    .next_update(datetime.utcnow() + timedelta(days=7))
    .add_revoked_certificate(revoked_entry)
    .sign(ca_key, hashes.SHA256(), default_backend()))
```

---

## 🛠️ Technologies Used

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.x + Flask |
| Cryptography | Python `cryptography` library (PyCA) |
| Database | SQLite (upgradeable to MySQL) |
| Frontend | HTML5 + CSS3 + Vanilla JavaScript |
| Key Algorithm | RSA-2048 |
| Certificate Standard | X.509 v3 |
| Signature Algorithm | SHA-256 with RSA |
| Session Management | Flask server-side sessions |

---

## 📊 API Endpoints

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| POST | `/api/user/generate-keypair` | User | Generate RSA key pair |
| POST | `/api/user/submit-csr` | User | Submit certificate request |
| GET | `/api/user/certificates` | User | Get user's certificates |
| GET | `/api/user/csr-status` | User | Get request status |
| GET | `/api/ra/requests` | RA | Get pending requests |
| POST | `/api/ra/review/<id>` | RA | Approve/reject request |
| GET | `/api/ca/pending-requests` | CA | Get RA-approved requests |
| POST | `/api/ca/issue-cert/<id>` | CA | Sign and issue certificate |
| GET | `/api/ca/all-certificates` | CA | Get all certificates |
| POST | `/api/ca/revoke/<id>` | CA | Revoke a certificate |
| GET | `/api/ca/generate-crl` | CA | Generate CRL |

---

## 📝 Upgrading to MySQL

Replace the `get_db()` function in `app.py`:

```python
import mysql.connector

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="pki_user",
        password="pki_pass",
        database="pki_db"
    )
```

Then update `requirements.txt`:
```
flask==3.0.0
cryptography==42.0.0
mysql-connector-python==8.3.0
```

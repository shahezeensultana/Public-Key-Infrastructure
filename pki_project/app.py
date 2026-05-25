"""
PKI Mini Project - Main Application
B.Tech Demonstration Project
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import CertificateRevocationListBuilder, RevokedCertificateBuilder
import datetime, os, json, io, base64, hashlib, uuid, sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'pki_demo_secret_key_2024'

DB_PATH = 'pki_database.db'

# ─────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            organization TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS key_pairs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS csr_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            csr_data TEXT NOT NULL,
            common_name TEXT,
            organization TEXT,
            email TEXT,
            status TEXT DEFAULT 'pending',
            ra_notes TEXT,
            ca_notes TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            issued_at TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            csr_id INTEGER,
            serial_number TEXT UNIQUE,
            certificate_pem TEXT NOT NULL,
            common_name TEXT,
            issuer TEXT DEFAULT 'PKI-CA',
            valid_from TIMESTAMP,
            valid_to TIMESTAMP,
            fingerprint TEXT,
            status TEXT DEFAULT 'valid',
            revoked_at TIMESTAMP,
            revocation_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(csr_id) REFERENCES csr_requests(id)
        );
        CREATE TABLE IF NOT EXISTS ca_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            certificate TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS crl_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT,
            revoked_at TIMESTAMP,
            reason TEXT
        );
    ''')
    # Create default accounts
    c.execute("SELECT COUNT(*) FROM users WHERE role='ca'")
    if c.fetchone()[0] == 0:
        for u in [
            ('ca_admin','ca123','ca@pki.local','CA Administrator','PKI Authority','ca'),
            ('ra_admin','ra123','ra@pki.local','RA Administrator','PKI Authority','ra'),
            ('alice','alice123','alice@example.com','Alice Johnson','Example Corp','user'),
        ]:
            c.execute("INSERT OR IGNORE INTO users (username,password,email,full_name,organization,role) VALUES (?,?,?,?,?,?)", u)
    conn.commit()
    # Ensure CA key pair exists
    c.execute("SELECT COUNT(*) FROM ca_keys")
    if c.fetchone()[0] == 0:
        generate_ca_keypair(conn)
    conn.close()

def generate_ca_keypair(conn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    # Self-signed CA cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PKI-CA Root"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo Authority"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256(), default_backend()))
    priv_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    conn.execute("INSERT INTO ca_keys (public_key, private_key, certificate) VALUES (?,?,?)", (pub_pem, priv_pem, cert_pem))
    conn.commit()

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') != role:
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_ca_key_and_cert():
    conn = get_db()
    row = conn.execute("SELECT * FROM ca_keys ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    key = serialization.load_pem_private_key(row['private_key'].encode(), password=None, backend=default_backend())
    cert = x509.load_pem_x509_certificate(row['certificate'].encode(), default_backend())
    return key, cert

# ─────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'ca': return redirect(url_for('ca_dashboard'))
        if role == 'ra': return redirect(url_for('ra_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        d = request.get_json()
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (d['username'], d['password'])).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            return jsonify({'success': True, 'role': user['role']})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        d = request.get_json()
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username,password,email,full_name,organization,role) VALUES (?,?,?,?,?,?)",
                (d['username'], d['password'], d['email'], d['full_name'], d.get('organization',''), 'user'))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'success': False, 'message': 'Username already exists'})
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─────────────────────────────────────────
# USER MODULE
# ─────────────────────────────────────────
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/api/user/generate-keypair', methods=['POST'])
@login_required
def generate_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    conn = get_db()
    conn.execute("INSERT INTO key_pairs (user_id, public_key, private_key) VALUES (?,?,?)", (session['user_id'], pub_pem, priv_pem))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'public_key': pub_pem, 'private_key': priv_pem})

@app.route('/api/user/submit-csr', methods=['POST'])
@login_required
def submit_csr():
    d = request.get_json()
    conn = get_db()
    kp = conn.execute("SELECT * FROM key_pairs WHERE user_id=? ORDER BY id DESC LIMIT 1", (session['user_id'],)).fetchone()
    if not kp:
        conn.close()
        return jsonify({'success': False, 'message': 'Generate a key pair first'})
    key = serialization.load_pem_private_key(kp['private_key'].encode(), password=None, backend=default_backend())
    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    csr = (x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, d.get('common_name', user['full_name'])),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, d.get('organization', user['organization'] or 'Individual')),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, d.get('email', user['email'])),
            x509.NameAttribute(NameOID.COUNTRY_NAME, d.get('country', 'IN')),
        ]))
        .sign(key, hashes.SHA256(), default_backend()))
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    conn.execute("INSERT INTO csr_requests (user_id, csr_data, common_name, organization, email, status) VALUES (?,?,?,?,?,?)",
        (session['user_id'], csr_pem, d.get('common_name', user['full_name']), d.get('organization', ''), d.get('email', user['email']), 'pending'))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'csr': csr_pem})

@app.route('/api/user/certificates')
@login_required
def user_certificates():
    conn = get_db()
    certs = conn.execute("SELECT * FROM certificates WHERE user_id=? ORDER BY created_at DESC", (session['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(c) for c in certs])

@app.route('/api/user/csr-status')
@login_required
def csr_status():
    conn = get_db()
    csrs = conn.execute("SELECT * FROM csr_requests WHERE user_id=? ORDER BY submitted_at DESC", (session['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(c) for c in csrs])

@app.route('/api/user/download-cert/<int:cert_id>')
@login_required
def download_cert(cert_id):
    conn = get_db()
    cert = conn.execute("SELECT * FROM certificates WHERE id=? AND user_id=?", (cert_id, session['user_id'])).fetchone()
    conn.close()
    if not cert:
        return jsonify({'error': 'Not found'}), 404
    buf = io.BytesIO(cert['certificate_pem'].encode())
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"certificate_{cert['serial_number'][:8]}.pem", mimetype='application/x-pem-file')

@app.route('/api/user/renew-cert/<int:cert_id>', methods=['POST'])
@login_required
def renew_cert(cert_id):
    conn = get_db()
    old = conn.execute("SELECT * FROM certificates WHERE id=? AND user_id=?", (cert_id, session['user_id'])).fetchone()
    csr = conn.execute("SELECT * FROM csr_requests WHERE id=?", (old['csr_id'],)).fetchone()
    if not old:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    conn.execute("INSERT INTO csr_requests (user_id, csr_data, common_name, organization, email, status) VALUES (?,?,?,?,?,?)",
        (session['user_id'], csr['csr_data'], old['common_name'], csr['organization'], csr['email'], 'pending'))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Renewal request submitted'})

# ─────────────────────────────────────────
# RA MODULE
# ─────────────────────────────────────────
@app.route('/ra/dashboard')
@login_required
def ra_dashboard():
    if session.get('role') != 'ra':
        return redirect(url_for('login'))
    return render_template('ra_dashboard.html')

@app.route('/api/ra/requests')
@login_required
def ra_get_requests():
    if session.get('role') not in ('ra', 'ca'):
        return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db()
    reqs = conn.execute("""
        SELECT r.*, u.full_name, u.email as user_email, u.organization as user_org
        FROM csr_requests r JOIN users u ON r.user_id=u.id
        WHERE r.status IN ('pending','ra_approved')
        ORDER BY r.submitted_at DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in reqs])

@app.route('/api/ra/review/<int:req_id>', methods=['POST'])
@login_required
def ra_review(req_id):
    if session.get('role') != 'ra':
        return jsonify({'error': 'Unauthorized'}), 403
    d = request.get_json()
    action = d.get('action')  # 'approve' or 'reject'
    status = 'ra_approved' if action == 'approve' else 'rejected'
    conn = get_db()
    conn.execute("UPDATE csr_requests SET status=?, ra_notes=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?",
        (status, d.get('notes', ''), req_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ─────────────────────────────────────────
# CA MODULE
# ─────────────────────────────────────────
@app.route('/ca/dashboard')
@login_required
def ca_dashboard():
    if session.get('role') != 'ca':
        return redirect(url_for('login'))
    return render_template('ca_dashboard.html')

@app.route('/api/ca/pending-requests')
@login_required
def ca_pending():
    if session.get('role') != 'ca':
        return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db()
    reqs = conn.execute("""
        SELECT r.*, u.full_name, u.email as user_email
        FROM csr_requests r JOIN users u ON r.user_id=u.id
        WHERE r.status='ra_approved'
        ORDER BY r.submitted_at DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in reqs])

@app.route('/api/ca/issue-cert/<int:req_id>', methods=['POST'])
@login_required
def issue_cert(req_id):
    if session.get('role') != 'ca':
        return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db()
    req = conn.execute("SELECT * FROM csr_requests WHERE id=?", (req_id,)).fetchone()
    if not req or req['status'] != 'ra_approved':
        conn.close()
        return jsonify({'error': 'Invalid request'}), 400
    ca_key, ca_cert = get_ca_key_and_cert()
    csr = x509.load_pem_x509_csr(req['csr_data'].encode(), default_backend())
    serial = x509.random_serial_number()
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    serial_hex = format(serial, 'x').upper()
    conn.execute("UPDATE csr_requests SET status='issued', issued_at=CURRENT_TIMESTAMP WHERE id=?", (req_id,))
    conn.execute("INSERT INTO certificates (user_id,csr_id,serial_number,certificate_pem,common_name,valid_from,valid_to,fingerprint) VALUES (?,?,?,?,?,?,?,?)",
        (req['user_id'], req_id, serial_hex, cert_pem, req['common_name'], now.isoformat(), (now+datetime.timedelta(days=365)).isoformat(), fp))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'serial': serial_hex, 'fingerprint': fp})

@app.route('/api/ca/all-certificates')
@login_required
def ca_all_certs():
    if session.get('role') != 'ca':
        return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db()
    certs = conn.execute("""
        SELECT c.*, u.full_name, u.username
        FROM certificates c JOIN users u ON c.user_id=u.id
        ORDER BY c.created_at DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(c) for c in certs])

@app.route('/api/ca/revoke/<int:cert_id>', methods=['POST'])
@login_required
def revoke_cert(cert_id):
    if session.get('role') != 'ca':
        return jsonify({'error': 'Unauthorized'}), 403
    d = request.get_json()
    conn = get_db()
    cert = conn.execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
    conn.execute("UPDATE certificates SET status='revoked', revoked_at=CURRENT_TIMESTAMP, revocation_reason=? WHERE id=?",
        (d.get('reason', 'unspecified'), cert_id))
    conn.execute("INSERT INTO crl_entries (serial_number, revoked_at, reason) VALUES (?,CURRENT_TIMESTAMP,?)",
        (cert['serial_number'], d.get('reason', 'unspecified')))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/ca/generate-crl')
@login_required
def generate_crl():
    if session.get('role') != 'ca':
        return jsonify({'error': 'Unauthorized'}), 403
    ca_key, ca_cert = get_ca_key_and_cert()
    conn = get_db()
    revoked = conn.execute("SELECT * FROM certificates WHERE status='revoked'").fetchall()
    conn.close()
    builder = CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.utcnow())
    builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=7))
    for r in revoked:
        rev = (RevokedCertificateBuilder()
            .serial_number(int(r['serial_number'], 16))
            .revocation_date(datetime.datetime.utcnow())
            .build(default_backend()))
        builder = builder.add_revoked_certificate(rev)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()
    return jsonify({'success': True, 'crl': crl_pem, 'revoked_count': len(revoked)})

@app.route('/api/ca/stats')
@login_required
def ca_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    valid = conn.execute("SELECT COUNT(*) FROM certificates WHERE status='valid'").fetchone()[0]
    revoked = conn.execute("SELECT COUNT(*) FROM certificates WHERE status='revoked'").fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM csr_requests WHERE status IN ('pending','ra_approved')").fetchone()[0]
    users = conn.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0]
    conn.close()
    return jsonify({'total': total, 'valid': valid, 'revoked': revoked, 'pending': pending, 'users': users})

@app.route('/api/user/stats')
@login_required
def user_stats():
    conn = get_db()
    certs = conn.execute("SELECT COUNT(*) FROM certificates WHERE user_id=? AND status='valid'", (session['user_id'],)).fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM csr_requests WHERE user_id=? AND status IN ('pending','ra_approved')", (session['user_id'],)).fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM certificates WHERE user_id=?", (session['user_id'],)).fetchone()[0]
    conn.close()
    return jsonify({'active_certs': certs, 'pending_requests': pending, 'total_certs': total})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

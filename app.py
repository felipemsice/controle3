import os, json, sqlite3, secrets, hashlib, base64
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
import jwt
import sendgrid
from sendgrid.helpers.mail import Mail

app = Flask(__name__, static_folder='static')

# ── CONFIG ──────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, 'despesas.db')
PHOTOS_DIR = os.path.join(BASE_DIR, 'photos')
os.makedirs(PHOTOS_DIR, exist_ok=True)

SECRET_KEY      = os.environ.get('SECRET_KEY', 'dev-secret-mude-em-producao')
SENDGRID_KEY    = os.environ.get('SENDGRID_KEY', '')
FROM_EMAIL      = os.environ.get('FROM_EMAIL', 'felipe.silva.841189@gmail.com')
ADM_EMAIL       = os.environ.get('ADM_EMAIL',  'felipe.silva.841189@gmail.com')
ADM_PASSWORD    = os.environ.get('ADM_PASSWORD', 'Admin@2025!')

# ── BANCO DE DADOS ───────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL,
            email     TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            verified  INTEGER DEFAULT 0,
            active    INTEGER DEFAULT 1,
            created   TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS despesas (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER NOT NULL,
            cat      TEXT NOT NULL,
            val      REAL NOT NULL,
            date     TEXT,
            time     TEXT,
            ts       INTEGER,
            photo    TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS tokens (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            email   TEXT NOT NULL,
            code    TEXT NOT NULL,
            type    TEXT NOT NULL,
            expires TEXT NOT NULL
        );
    ''')
    db.commit()
    db.close()

# ── HELPERS ──────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def send_email(to, subject, body):
    if not SENDGRID_KEY:
        print(f"EMAIL para {to}: {subject}\n{body}")
        return
    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_KEY)
        msg = Mail(from_email=FROM_EMAIL, to_emails=to,
                   subject=subject, html_content=body)
        sg.client.mail.send.post(request_body=msg.get())
    except Exception as e:
        print(f"Erro ao enviar email: {e}")

def make_token(user_id, role='user'):
    payload = {
        'sub': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token ausente'}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            g.user_id = payload['sub']
            g.role    = payload.get('role', 'user')
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Sessão expirada'}), 401
        except Exception:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

def require_adm(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token ausente'}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('role') != 'adm':
                return jsonify({'error': 'Acesso negado'}), 403
            g.user_id = payload['sub']
            g.role    = 'adm'
        except Exception:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

# ── ROTAS ESTÁTICAS ─────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/admin')
def adm_page():
    return send_from_directory('static/admin', 'index.html')

# ── AUTH: CADASTRO ───────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    d = request.get_json()
    name  = d.get('name','').strip()
    email = d.get('email','').strip().lower()
    pw    = d.get('password','')
    if not name or not email or not pw:
        return jsonify({'error': 'Preencha todos os campos'}), 400
    if len(pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    db = get_db()
    if db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
        return jsonify({'error': 'E-mail já cadastrado'}), 409
    db.execute('INSERT INTO users (name,email,password) VALUES (?,?,?)',
               (name, email, hash_password(pw)))
    db.commit()
    code = secrets.token_hex(3).upper()
    expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    db.execute('DELETE FROM tokens WHERE email=? AND type=?', (email, 'verify'))
    db.execute('INSERT INTO tokens (email,code,type,expires) VALUES (?,?,?,?)',
               (email, code, 'verify', expires))
    db.commit()
    send_email(email, 'Confirme seu cadastro — Despesas Pessoais',
        f'''<div style="font-family:sans-serif;max-width:400px;margin:auto;padding:32px">
        <h2 style="color:#0F6E56">Bem-vindo, {name}!</h2>
        <p>Use o código abaixo para confirmar seu e-mail:</p>
        <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#1D9E75;text-align:center;padding:24px 0">{code}</div>
        <p style="color:#999;font-size:13px">Válido por 24 horas.</p></div>''')
    return jsonify({'ok': True, 'message': 'Verifique seu e-mail'})

# ── AUTH: VERIFICAR E-MAIL ───────────────────────────────
@app.route('/api/auth/verify', methods=['POST'])
def verify_email():
    d     = request.get_json()
    email = d.get('email','').strip().lower()
    code  = d.get('code','').strip().upper()
    db    = get_db()
    row   = db.execute(
        'SELECT * FROM tokens WHERE email=? AND code=? AND type=?',
        (email, code, 'verify')).fetchone()
    if not row:
        return jsonify({'error': 'Código inválido'}), 400
    if datetime.utcnow().isoformat() > row['expires']:
        return jsonify({'error': 'Código expirado'}), 400
    db.execute('UPDATE users SET verified=1 WHERE email=?', (email,))
    db.execute('DELETE FROM tokens WHERE email=? AND type=?', (email, 'verify'))
    db.commit()
    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    token = make_token(user['id'])
    return jsonify({'ok': True, 'token': token, 'name': user['name']})

# ── AUTH: LOGIN ──────────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
def login():
    d     = request.get_json()
    email = d.get('email','').strip().lower()
    pw    = d.get('password','')
    db    = get_db()
    user  = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not user or user['password'] != hash_password(pw):
        return jsonify({'error': 'E-mail ou senha incorretos'}), 401
    if not user['verified']:
        return jsonify({'error': 'Confirme seu e-mail antes de entrar', 'unverified': True}), 403
    if not user['active']:
        return jsonify({'error': 'Conta desativada'}), 403
    token = make_token(user['id'])
    return jsonify({'ok': True, 'token': token, 'name': user['name']})

# ── AUTH: RECUPERAR SENHA ────────────────────────────────
@app.route('/api/auth/forgot', methods=['POST'])
def forgot():
    email = request.get_json().get('email','').strip().lower()
    db    = get_db()
    user  = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not user:
        return jsonify({'ok': True})
    code    = secrets.token_hex(3).upper()
    expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    db.execute('DELETE FROM tokens WHERE email=? AND type=?', (email, 'reset'))
    db.execute('INSERT INTO tokens (email,code,type,expires) VALUES (?,?,?,?)',
               (email, code, 'reset', expires))
    db.commit()
    send_email(email, 'Redefinição de senha — Despesas Pessoais',
        f'''<div style="font-family:sans-serif;max-width:400px;margin:auto;padding:32px">
        <h2 style="color:#0F6E56">Redefinir senha</h2>
        <p>Use o código temporário abaixo:</p>
        <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#1D9E75;text-align:center;padding:24px 0">{code}</div>
        <p style="color:#999;font-size:13px">Válido por 15 minutos.</p></div>''')
    return jsonify({'ok': True})

@app.route('/api/auth/reset', methods=['POST'])
def reset_password():
    d       = request.get_json()
    email   = d.get('email','').strip().lower()
    code    = d.get('code','').strip().upper()
    new_pw  = d.get('password','')
    if len(new_pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    db  = get_db()
    row = db.execute(
        'SELECT * FROM tokens WHERE email=? AND code=? AND type=?',
        (email, code, 'reset')).fetchone()
    if not row:
        return jsonify({'error': 'Código inválido'}), 400
    if datetime.utcnow().isoformat() > row['expires']:
        return jsonify({'error': 'Código expirado'}), 400
    db.execute('UPDATE users SET password=? WHERE email=?',
               (hash_password(new_pw), email))
    db.execute('DELETE FROM tokens WHERE email=? AND type=?', (email, 'reset'))
    db.commit()
    return jsonify({'ok': True})

# ── DESPESAS ─────────────────────────────────────────────
@app.route('/api/despesas', methods=['GET'])
@require_auth
def get_despesas():
    db   = get_db()
    rows = db.execute(
        'SELECT * FROM despesas WHERE user_id=? ORDER BY ts DESC', (g.user_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/despesas', methods=['POST'])
@require_auth
def add_despesa():
    d  = request.get_json()
    db = get_db()
    db.execute(
        'INSERT INTO despesas (user_id,cat,val,date,time,ts) VALUES (?,?,?,?,?,?)',
        (g.user_id, d['cat'], d['val'], d.get('date'), d.get('time'), d.get('ts')))
    db.commit()
    row = db.execute('SELECT last_insert_rowid() as id').fetchone()
    return jsonify({'ok': True, 'id': row['id']})

@app.route('/api/despesas/<int:eid>', methods=['DELETE'])
@require_auth
def delete_despesa(eid):
    db  = get_db()
    row = db.execute(
        'SELECT * FROM despesas WHERE id=? AND user_id=?', (eid, g.user_id)
    ).fetchone()
    if not row:
        return jsonify({'error': 'Não encontrado'}), 404
    if row['photo']:
        p = os.path.join(PHOTOS_DIR, row['photo'])
        if os.path.exists(p): os.remove(p)
    db.execute('DELETE FROM despesas WHERE id=?', (eid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/despesas/clear', methods=['POST'])
@require_auth
def clear_despesas():
    db   = get_db()
    rows = db.execute(
        'SELECT photo FROM despesas WHERE user_id=?', (g.user_id,)
    ).fetchall()
    for r in rows:
        if r['photo']:
            p = os.path.join(PHOTOS_DIR, r['photo'])
            if os.path.exists(p): os.remove(p)
    db.execute('DELETE FROM despesas WHERE user_id=?', (g.user_id,))
    db.commit()
    return jsonify({'ok': True})

# ── FOTOS ────────────────────────────────────────────────
@app.route('/api/photo', methods=['POST'])
@require_auth
def upload_photo():
    d       = request.get_json()
    eid     = d.get('id')
    img_b64 = d.get('image','')
    db      = get_db()
    row     = db.execute(
        'SELECT * FROM despesas WHERE id=? AND user_id=?', (eid, g.user_id)
    ).fetchone()
    if not row:
        return jsonify({'error': 'Não encontrado'}), 404
    if not img_b64:
        if row['photo']:
            p = os.path.join(PHOTOS_DIR, row['photo'])
            if os.path.exists(p): os.remove(p)
        db.execute('UPDATE despesas SET photo=NULL WHERE id=?', (eid,))
        db.commit()
        return jsonify({'ok': True})
    if ',' in img_b64:
        img_b64 = img_b64.split(',')[1]
    filename = f"{g.user_id}_{eid}.jpg"
    with open(os.path.join(PHOTOS_DIR, filename), 'wb') as f:
        f.write(base64.b64decode(img_b64))
    db.execute('UPDATE despesas SET photo=? WHERE id=?', (filename, eid))
    db.commit()
    return jsonify({'ok': True, 'photo': filename})

@app.route('/api/photo/<filename>', methods=['GET'])
@require_auth
def get_photo(filename):
    if not filename.startswith(f"{g.user_id}_"):
        return jsonify({'error': 'Acesso negado'}), 403
    return send_from_directory(PHOTOS_DIR, filename)

# ── ADM: LOGIN ───────────────────────────────────────────
@app.route('/api/adm/login', methods=['POST'])
def adm_login():
    d  = request.get_json()
    if d.get('email','').lower() == ADM_EMAIL.lower() and d.get('password') == ADM_PASSWORD:
        token = make_token('adm', role='adm')
        return jsonify({'ok': True, 'token': token})
    return jsonify({'error': 'Credenciais incorretas'}), 401

# ── ADM: USUÁRIOS ────────────────────────────────────────
@app.route('/api/adm/users', methods=['GET'])
@require_adm
def adm_users():
    db   = get_db()
    rows = db.execute(
        'SELECT id,name,email,verified,active,created FROM users ORDER BY created DESC'
    ).fetchall()
    result = []
    for r in rows:
        u = dict(r)
        count = db.execute(
            'SELECT COUNT(*) as c FROM despesas WHERE user_id=?', (r['id'],)
        ).fetchone()['c']
        u['despesas_count'] = count
        result.append(u)
    return jsonify(result)

@app.route('/api/adm/users/<int:uid>', methods=['DELETE'])
@require_adm
def adm_delete_user(uid):
    db   = get_db()
    rows = db.execute('SELECT photo FROM despesas WHERE user_id=?', (uid,)).fetchall()
    for r in rows:
        if r['photo']:
            p = os.path.join(PHOTOS_DIR, r['photo'])
            if os.path.exists(p): os.remove(p)
    db.execute('DELETE FROM despesas WHERE user_id=?', (uid,))
    db.execute('DELETE FROM users WHERE id=?', (uid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/adm/users/<int:uid>/toggle', methods=['POST'])
@require_adm
def adm_toggle_user(uid):
    db  = get_db()
    row = db.execute('SELECT active FROM users WHERE id=?', (uid,)).fetchone()
    if not row:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    new_status = 0 if row['active'] else 1
    db.execute('UPDATE users SET active=? WHERE id=?', (new_status, uid))
    db.commit()
    return jsonify({'ok': True, 'active': new_status})

# ── INIT ─────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

init_db()

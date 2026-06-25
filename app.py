import os, sqlite3, secrets, hashlib, base64
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
import jwt
from twilio.rest import Client

app = Flask(__name__, static_folder='static')

# ── CONFIG ──────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, 'despesas.db')
PHOTOS_DIR = os.path.join(BASE_DIR, 'photos')
os.makedirs(PHOTOS_DIR, exist_ok=True)

SECRET_KEY      = os.environ.get('SECRET_KEY', 'dev-secret-mude-em-producao')
TWILIO_SID      = os.environ.get('TWILIO_SID', '')
TWILIO_TOKEN    = os.environ.get('TWILIO_TOKEN', '')
TWILIO_VERIFY   = os.environ.get('TWILIO_VERIFY', '')
ADM_PHONE       = os.environ.get('ADM_PHONE', '')
ADM_PASSWORD    = os.environ.get('ADM_PASSWORD', 'Admin@2025!')

def twilio_client():
    return Client(TWILIO_SID, TWILIO_TOKEN)

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
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            phone    TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            active   INTEGER DEFAULT 1,
            created  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS despesas (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cat     TEXT NOT NULL,
            val     REAL NOT NULL,
            date    TEXT,
            time    TEXT,
            ts      INTEGER,
            photo   TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')
    db.commit()
    db.close()

# ── HELPERS ──────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def fmt_phone(phone):
    phone = phone.strip().replace(' ','').replace('-','').replace('(','').replace(')','')
    if not phone.startswith('+'): phone = '+55' + phone.lstrip('0')
    return phone

def send_sms_code(phone):
    try:
        twilio_client().verify.v2.services(TWILIO_VERIFY).verifications.create(
            to=phone, channel='sms')
        return True
    except Exception as e:
        print(f"Erro ao enviar SMS: {e}")
        return False

def check_sms_code(phone, code):
    try:
        result = twilio_client().verify.v2.services(TWILIO_VERIFY).verification_checks.create(
            to=phone, code=code)
        return result.status == 'approved'
    except Exception as e:
        print(f"Erro ao verificar código: {e}")
        return False

def make_token(user_id, role='user'):
    payload = {'sub': user_id, 'role': role,
                'exp': datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token: return jsonify({'error': 'Token ausente'}), 401
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
        if not token: return jsonify({'error': 'Token ausente'}), 401
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
    d     = request.get_json()
    name  = d.get('name','').strip()
    phone = fmt_phone(d.get('phone',''))
    pw    = d.get('password','')
    if not name or not phone or not pw:
        return jsonify({'error': 'Preencha todos os campos'}), 400
    if len(pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    db = get_db()
    existing = db.execute('SELECT id,verified FROM users WHERE phone=?', (phone,)).fetchone()
    if existing:
        if existing['verified']:
            return jsonify({'error': 'Telefone já cadastrado'}), 409
        # Reenviar código se não verificou ainda
        if send_sms_code(phone):
            return jsonify({'ok': True, 'message': 'Código reenviado por SMS'})
        return jsonify({'error': 'Erro ao enviar SMS'}), 500
    db.execute('INSERT INTO users (name,phone,password) VALUES (?,?,?)',
               (name, phone, hash_password(pw)))
    db.commit()
    if send_sms_code(phone):
        return jsonify({'ok': True, 'message': 'Código enviado por SMS'})
    return jsonify({'error': 'Erro ao enviar SMS'}), 500

# ── AUTH: VERIFICAR SMS ──────────────────────────────────
@app.route('/api/auth/verify', methods=['POST'])
def verify_phone():
    d     = request.get_json()
    phone = fmt_phone(d.get('phone',''))
    code  = d.get('code','').strip()
    if not check_sms_code(phone, code):
        return jsonify({'error': 'Código inválido ou expirado'}), 400
    db = get_db()
    db.execute('UPDATE users SET verified=1 WHERE phone=?', (phone,))
    db.commit()
    user = db.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

# ── AUTH: LOGIN ──────────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
def login():
    d     = request.get_json()
    phone = fmt_phone(d.get('phone',''))
    pw    = d.get('password','')
    db    = get_db()
    user  = db.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
    if not user or user['password'] != hash_password(pw):
        return jsonify({'error': 'Telefone ou senha incorretos'}), 401
    if not user['verified']:
        send_sms_code(phone)
        return jsonify({'error': 'Confirme seu telefone', 'unverified': True}), 403
    if not user['active']:
        return jsonify({'error': 'Conta desativada'}), 403
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

# ── AUTH: RECUPERAR SENHA ────────────────────────────────
@app.route('/api/auth/forgot', methods=['POST'])
def forgot():
    phone = fmt_phone(request.get_json().get('phone',''))
    db    = get_db()
    user  = db.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
    if not user:
        return jsonify({'ok': True})
    if send_sms_code(phone):
        return jsonify({'ok': True})
    return jsonify({'error': 'Erro ao enviar SMS'}), 500

@app.route('/api/auth/reset', methods=['POST'])
def reset_password():
    d      = request.get_json()
    phone  = fmt_phone(d.get('phone',''))
    code   = d.get('code','').strip()
    new_pw = d.get('password','')
    if len(new_pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    if not check_sms_code(phone, code):
        return jsonify({'error': 'Código inválido ou expirado'}), 400
    db = get_db()
    db.execute('UPDATE users SET password=? WHERE phone=?', (hash_password(new_pw), phone))
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
    db.execute('INSERT INTO despesas (user_id,cat,val,date,time,ts) VALUES (?,?,?,?,?,?)',
               (g.user_id, d['cat'], d['val'], d.get('date'), d.get('time'), d.get('ts')))
    db.commit()
    row = db.execute('SELECT last_insert_rowid() as id').fetchone()
    return jsonify({'ok': True, 'id': row['id']})

@app.route('/api/despesas/<int:eid>', methods=['DELETE'])
@require_auth
def delete_despesa(eid):
    db  = get_db()
    row = db.execute('SELECT * FROM despesas WHERE id=? AND user_id=?', (eid, g.user_id)).fetchone()
    if not row: return jsonify({'error': 'Não encontrado'}), 404
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
    rows = db.execute('SELECT photo FROM despesas WHERE user_id=?', (g.user_id,)).fetchall()
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
    row     = db.execute('SELECT * FROM despesas WHERE id=? AND user_id=?', (eid, g.user_id)).fetchone()
    if not row: return jsonify({'error': 'Não encontrado'}), 404
    if not img_b64:
        if row['photo']:
            p = os.path.join(PHOTOS_DIR, row['photo'])
            if os.path.exists(p): os.remove(p)
        db.execute('UPDATE despesas SET photo=NULL WHERE id=?', (eid,))
        db.commit()
        return jsonify({'ok': True})
    if ',' in img_b64: img_b64 = img_b64.split(',')[1]
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
    d = request.get_json()
    if d.get('phone','').strip() == ADM_PHONE and d.get('password') == ADM_PASSWORD:
        return jsonify({'ok': True, 'token': make_token('adm', role='adm')})
    return jsonify({'error': 'Credenciais incorretas'}), 401

# ── ADM: USUÁRIOS ────────────────────────────────────────
@app.route('/api/adm/users', methods=['GET'])
@require_adm
def adm_users():
    db   = get_db()
    rows = db.execute('SELECT id,name,phone,verified,active,created FROM users ORDER BY created DESC').fetchall()
    result = []
    for r in rows:
        u = dict(r)
        u['despesas_count'] = db.execute(
            'SELECT COUNT(*) as c FROM despesas WHERE user_id=?', (r['id'],)
        ).fetchone()['c']
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
    if not row: return jsonify({'error': 'Não encontrado'}), 404
    new = 0 if row['active'] else 1
    db.execute('UPDATE users SET active=? WHERE id=?', (new, uid))
    db.commit()
    return jsonify({'ok': True, 'active': new})

# ── INIT ─────────────────────────────────────────────────
init_db()
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

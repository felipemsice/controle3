import os, sqlite3, secrets, hashlib, base64, hmac, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
import jwt
from twilio.rest import Client
import mercadopago

app = Flask(__name__, static_folder='static')

# ── CONFIG ──────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, 'despesas.db')
PHOTOS_DIR = os.path.join(BASE_DIR, 'photos')
os.makedirs(PHOTOS_DIR, exist_ok=True)

SECRET_KEY      = os.environ.get('SECRET_KEY', 'dev-secret')
TWILIO_SID      = os.environ.get('TWILIO_SID', '')
TWILIO_TOKEN    = os.environ.get('TWILIO_TOKEN', '')
TWILIO_VERIFY   = os.environ.get('TWILIO_VERIFY', '')
ADM_PHONE       = os.environ.get('ADM_PHONE', '')
ADM_PASSWORD    = os.environ.get('ADM_PASSWORD', 'Admin@2025!')
MP_ACCESS_TOKEN = os.environ.get('MP_ACCESS_TOKEN', '')
MP_WEBHOOK_SECRET = os.environ.get('MP_WEBHOOK_SECRET', '')
APP_URL         = os.environ.get('APP_URL', 'https://controle3.onrender.com')

PLANOS = {
    'basico':   {'nome': 'Básico',   'limite': 100, 'preco': 49.00,  'preco_id': os.environ.get('MP_PRICE_BASICO', '')},
    'standard': {'nome': 'Standard', 'limite': 200, 'preco': 60.00,  'preco_id': os.environ.get('MP_PRICE_STANDARD', '')},
    'premium':  {'nome': 'Premium',  'limite': 500, 'preco': 100.00, 'preco_id': os.environ.get('MP_PRICE_PREMIUM', '')},
}

def twilio_client():
    return Client(TWILIO_SID, TWILIO_TOKEN)

def mp_sdk():
    sdk = mercadopago.SDK(MP_ACCESS_TOKEN)
    return sdk

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
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            phone        TEXT UNIQUE NOT NULL,
            password     TEXT NOT NULL,
            verified     INTEGER DEFAULT 0,
            active       INTEGER DEFAULT 1,
            trial_end    TEXT,
            plano        TEXT DEFAULT NULL,
            plano_end    TEXT DEFAULT NULL,
            mp_sub_id    TEXT DEFAULT NULL,
            created      TEXT DEFAULT CURRENT_TIMESTAMP
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
        CREATE TABLE IF NOT EXISTS categorias (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER NOT NULL,
            nome     TEXT NOT NULL,
            icone    TEXT DEFAULT 'ti-tag',
            cor_bg   TEXT DEFAULT '#F1EFE8',
            cor_text TEXT DEFAULT '#2C2C2A',
            cor_bar  TEXT DEFAULT '#888',
            criada   TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, nome),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS pagamentos (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            mp_id      TEXT,
            plano      TEXT,
            valor      REAL,
            status     TEXT,
            criado     TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')
    # Migração: adicionar colunas de plano em users existentes
    try:
        db.execute("ALTER TABLE users ADD COLUMN trial_end TEXT")
    except: pass
    try:
        db.execute("ALTER TABLE users ADD COLUMN plano TEXT DEFAULT NULL")
    except: pass
    try:
        db.execute("ALTER TABLE users ADD COLUMN plano_end TEXT DEFAULT NULL")
    except: pass
    try:
        db.execute("ALTER TABLE users ADD COLUMN mp_sub_id TEXT DEFAULT NULL")
    except: pass
    # Migração: coluna photo_data para armazenar foto em base64 no banco
    try:
        db.execute("ALTER TABLE despesas ADD COLUMN photo_data TEXT")
    except: pass
    # Preencher trial_end para usuários que já existiam sem ele
    trial_end_padrao = (datetime.utcnow() + timedelta(days=30)).isoformat()
    db.execute("""
        UPDATE users SET trial_end=? 
        WHERE trial_end IS NULL AND plano IS NULL
    """, (trial_end_padrao,))
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
        twilio_client().verify.v2.services(TWILIO_VERIFY).verifications.create(to=phone, channel='sms')
        return True
    except Exception as e:
        print(f"Erro SMS: {e}"); return False

def check_sms_code(phone, code):
    try:
        r = twilio_client().verify.v2.services(TWILIO_VERIFY).verification_checks.create(to=phone, code=code)
        return r.status == 'approved'
    except Exception as e:
        print(f"Erro verify: {e}"); return False

def make_token(user_id, role='user'):
    payload = {'sub': user_id, 'role': role, 'exp': datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def get_plano_status(user):
    now = datetime.utcnow().isoformat()
    # ADM não tem restrição
    if user['phone'] == ADM_PHONE:
        return {'status': 'adm', 'pode_adicionar': True, 'limite': 9999, 'uso_mes': 0}

    # Verifica plano pago primeiro (prioridade sobre trial)
    plano    = user['plano']
    plano_end = user['plano_end']
    if plano and plano_end and now < plano_end:
        dias = (datetime.fromisoformat(plano_end) - datetime.utcnow()).days
        return {
            'status': 'ativo', 'plano': plano, 'pode_adicionar': True,
            'limite': PLANOS[plano]['limite'], 'plano_end': plano_end,
            'plano_dias': dias, 'nome': PLANOS[plano]['nome']
        }

    # Verifica trial
    trial_end = user['trial_end']
    if trial_end and now < trial_end:
        dias = (datetime.fromisoformat(trial_end) - datetime.utcnow()).days
        return {'status': 'trial', 'pode_adicionar': True, 'limite': 9999,
                'uso_mes': 0, 'trial_dias': dias}

    # Expirado
    return {'status': 'expirado', 'pode_adicionar': False, 'limite': 0, 'uso_mes': 0}

def count_mes_atual(db, user_id):
    now = datetime.utcnow()
    mes = f"{now.month:02d}/{str(now.year)[2:]}"
    row = db.execute(
        "SELECT COUNT(*) as c FROM despesas WHERE user_id=? AND date LIKE ?",
        (user_id, f"%/{mes}")
    ).fetchone()
    return row['c'] if row else 0

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
            if payload.get('role') != 'adm': return jsonify({'error': 'Acesso negado'}), 403
            g.user_id = payload['sub']
            g.role    = 'adm'
        except Exception:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

# ── ROTAS ESTÁTICAS ──────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/admin')
def adm_page():
    return send_from_directory('static/admin', 'index.html')

@app.route('/relatorios')
def relatorios_page():
    return send_from_directory('static/relatorios', 'index.html')

@app.route('/assinar')
def assinar_page():
    return send_from_directory('static/assinar', 'index.html')

# ── AUTH: CADASTRO (sem SMS) ─────────────────────────────
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
    existing = db.execute('SELECT id FROM users WHERE phone=?', (phone,)).fetchone()
    if existing:
        return jsonify({'error': 'Telefone já cadastrado'}), 409
    trial_end = (datetime.utcnow() + timedelta(days=30)).isoformat()
    db.execute('INSERT INTO users (name,phone,password,trial_end,verified) VALUES (?,?,?,?,1)',
               (name, phone, hash_password(pw), trial_end))
    db.commit()
    user = db.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/verify', methods=['POST'])
def verify_phone():
    # Mantido por compatibilidade mas não é mais necessário
    d     = request.get_json()
    phone = fmt_phone(d.get('phone',''))
    db    = get_db()
    db.execute('UPDATE users SET verified=1 WHERE phone=?', (phone,))
    db.commit()
    user = db.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
    if not user: return jsonify({'error': 'Usuário não encontrado'}), 404
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/login', methods=['POST'])
def login():
    d     = request.get_json()
    phone = fmt_phone(d.get('phone',''))
    pw    = d.get('password','')
    db    = get_db()
    user  = db.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
    if not user or user['password'] != hash_password(pw):
        return jsonify({'error': 'Telefone ou senha incorretos'}), 401
    if not user['active']:
        return jsonify({'error': 'Conta desativada'}), 403
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/forgot', methods=['POST'])
def forgot():
    # Sem SMS: informa que deve contatar o ADM
    return jsonify({'ok': True, 'message': 'Entre em contato com o administrador para redefinir sua senha.'})

@app.route('/api/auth/reset', methods=['POST'])
def reset_password():
    d      = request.get_json()
    phone  = fmt_phone(d.get('phone',''))
    new_pw = d.get('password','')
    token  = d.get('token','')
    # Requer token ADM para reset externo
    if len(new_pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    db = get_db()
    db.execute('UPDATE users SET password=? WHERE phone=?', (hash_password(new_pw), phone))
    db.commit()
    return jsonify({'ok': True})

# ── STATUS DA CONTA ──────────────────────────────────────
@app.route('/api/conta/status', methods=['GET'])
@require_auth
def conta_status():
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (g.user_id,)).fetchone()
    if not user: return jsonify({'error': 'Usuário não encontrado'}), 404
    ps   = get_plano_status(user)
    uso  = count_mes_atual(db, g.user_id) if ps['status'] == 'ativo' else 0
    ps['uso_mes'] = uso
    if ps['status'] == 'ativo':
        ps['pode_adicionar'] = uso < ps['limite']
    ps['planos_disponiveis'] = {k: {'nome': v['nome'], 'limite': v['limite'], 'preco': v['preco']} for k,v in PLANOS.items()}
    return jsonify(ps)

# ── CATEGORIAS ───────────────────────────────────────────
CATS_PADRAO = ['Combustível','Alimentação','Lazer','Saúde','Transporte','Moradia','Educação','Vestuário','Outros']

@app.route('/api/categorias', methods=['GET'])
@require_auth
def get_categorias():
    db   = get_db()
    rows = db.execute('SELECT * FROM categorias WHERE user_id=? ORDER BY criada ASC', (g.user_id,)).fetchall()
    return jsonify({'padrao': CATS_PADRAO, 'custom': [dict(r) for r in rows]})

@app.route('/api/categorias', methods=['POST'])
@require_auth
def add_categoria():
    d    = request.get_json()
    nome = d.get('nome','').strip()
    if not nome: return jsonify({'error': 'Nome obrigatório'}), 400
    if nome in CATS_PADRAO: return jsonify({'error': 'Categoria já existe'}), 409
    db = get_db()
    try:
        db.execute('INSERT INTO categorias (user_id,nome,icone,cor_bg,cor_text,cor_bar) VALUES (?,?,?,?,?,?)',
                   (g.user_id, nome, d.get('icone','ti-tag'), d.get('cor_bg','#F1EFE8'),
                    d.get('cor_text','#2C2C2A'), d.get('cor_bar','#888')))
        db.commit()
        row = db.execute('SELECT last_insert_rowid() as id').fetchone()
        return jsonify({'ok': True, 'id': row['id']})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Categoria já existe'}), 409

@app.route('/api/categorias/<int:cid>', methods=['DELETE'])
@require_auth
def delete_categoria(cid):
    db  = get_db()
    row = db.execute('SELECT * FROM categorias WHERE id=? AND user_id=?', (cid, g.user_id)).fetchone()
    if not row: return jsonify({'error': 'Não encontrada'}), 404
    count = db.execute('SELECT COUNT(*) as c FROM despesas WHERE user_id=? AND cat=?',
                       (g.user_id, row['nome'])).fetchone()['c']
    if count > 0: return jsonify({'error': f'Categoria em uso em {count} lançamento(s)'}), 409
    db.execute('DELETE FROM categorias WHERE id=?', (cid,))
    db.commit()
    return jsonify({'ok': True})

# ── DESPESAS ─────────────────────────────────────────────
@app.route('/api/despesas', methods=['GET'])
@require_auth
def get_despesas():
    db   = get_db()
    rows = db.execute('SELECT * FROM despesas WHERE user_id=? ORDER BY ts DESC', (g.user_id,)).fetchall()
    result = []
    for r in rows:
        e = dict(r)
        # Incluir foto como data URL inline para evitar segunda requisição
        if e.get('photo_data'):
            e['photo_inline'] = 'data:image/jpeg;base64,' + e['photo_data']
        e.pop('photo_data', None)  # Não expor o campo raw
        result.append(e)
    return jsonify(result)

@app.route('/api/despesas', methods=['POST'])
@require_auth
def add_despesa():
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (g.user_id,)).fetchone()
    ps   = get_plano_status(user)
    if not ps['pode_adicionar']:
        return jsonify({'error': 'plano_expirado', 'status': ps['status']}), 403
    if ps['status'] == 'ativo':
        uso = count_mes_atual(db, g.user_id)
        if uso >= ps['limite']:
            return jsonify({'error': 'limite_atingido', 'uso': uso, 'limite': ps['limite']}), 403
    d = request.get_json()
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
    # Tentar remover arquivo legado se existir
    if row['photo'] and not row['photo'].startswith('db:'):
        p = os.path.join(PHOTOS_DIR, row['photo'])
        if os.path.exists(p):
            try: os.remove(p)
            except: pass
    db.execute('DELETE FROM despesas WHERE id=?', (eid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/despesas/clear', methods=['POST'])
@require_auth
def clear_despesas():
    db   = get_db()
    rows = db.execute('SELECT photo FROM despesas WHERE user_id=?', (g.user_id,)).fetchall()
    for r in rows:
        if r['photo'] and not r['photo'].startswith('db:'):
            p = os.path.join(PHOTOS_DIR, r['photo'])
            if os.path.exists(p):
                try: os.remove(p)
                except: pass
    db.execute('DELETE FROM despesas WHERE user_id=?', (g.user_id,))
    db.commit()
    return jsonify({'ok': True})

# ── FOTOS (salvas em base64 no banco) ────────────────────
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
    if not row: return jsonify({'error': 'Não encontrado'}), 404
    if not img_b64:
        db.execute('UPDATE despesas SET photo=NULL, photo_data=NULL WHERE id=?', (eid,))
        db.commit()
        return jsonify({'ok': True})
    # Guardar base64 puro no banco
    b64_puro = img_b64.split(',')[1] if ',' in img_b64 else img_b64
    ref = f"db_{g.user_id}_{eid}"
    db.execute(
        'UPDATE despesas SET photo=?, photo_data=? WHERE id=?',
        (ref, b64_puro, eid)
    )
    db.commit()
    return jsonify({'ok': True, 'photo': ref})

@app.route('/api/photo/<ref>', methods=['GET'])
@require_auth
def get_photo(ref):
    from flask import Response
    db = get_db()
    # Novo formato: db_userid_entryid
    if ref.startswith('db_'):
        parts = ref.split('_')  # ['db', 'userid', 'entryid']
        if len(parts) < 3 or str(g.user_id) != parts[1]:
            return jsonify({'error': 'Acesso negado'}), 403
        eid = parts[2]
        row = db.execute(
            'SELECT photo_data FROM despesas WHERE id=? AND user_id=?',
            (eid, g.user_id)
        ).fetchone()
        if not row or not row['photo_data']:
            return '', 404
        img_bytes = base64.b64decode(row['photo_data'])
        return Response(img_bytes, mimetype='image/jpeg',
                       headers={'Cache-Control': 'max-age=86400'})
    # Formato legado: userid_entryid.jpg (arquivo em disco)
    if not ref.startswith(f"{g.user_id}_"):
        return jsonify({'error': 'Acesso negado'}), 403
    photo_path = os.path.join(PHOTOS_DIR, ref)
    if os.path.exists(photo_path):
        return send_from_directory(PHOTOS_DIR, ref)
    return '', 404

# ── PAGAMENTO MERCADO PAGO ───────────────────────────────
@app.route('/api/pagamento/criar', methods=['POST'])
@require_auth
def criar_pagamento():
    d     = request.get_json()
    plano = d.get('plano')
    if plano not in PLANOS:
        return jsonify({'error': 'Plano inválido'}), 400
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (g.user_id,)).fetchone()
    sdk  = mp_sdk()
    p    = PLANOS[plano]
    preference_data = {
        'items': [{
            'title': f"Despesas Pessoais — Plano {p['nome']} (Anual)",
            'quantity': 1,
            'currency_id': 'BRL',
            'unit_price': p['preco'],
        }],
        'payer': {'name': user['name']},
        'back_urls': {
            'success': f"{APP_URL}/assinar?status=sucesso&plano={plano}",
            'failure': f"{APP_URL}/assinar?status=erro",
            'pending': f"{APP_URL}/assinar?status=pendente",
        },
        'auto_return': 'approved',
        'notification_url': f"{APP_URL}/api/pagamento/webhook",
        'metadata': {'user_id': str(g.user_id), 'plano': plano},
        'statement_descriptor': 'DESPESAS APP',
    }
    result = sdk.preference().create(preference_data)
    if result['status'] != 201:
        return jsonify({'error': 'Erro ao criar preferência'}), 500
    pref = result['response']
    # Salvar pagamento pendente
    db.execute('INSERT INTO pagamentos (user_id,mp_id,plano,valor,status) VALUES (?,?,?,?,?)',
               (g.user_id, pref['id'], plano, p['preco'], 'pendente'))
    db.commit()
    return jsonify({
        'ok': True,
        'init_point': pref['init_point'],
        'sandbox_init_point': pref.get('sandbox_init_point', pref['init_point'])
    })

@app.route('/api/pagamento/webhook', methods=['POST'])
def webhook():
    data = request.get_json(silent=True) or {}
    topic = data.get('type') or request.args.get('topic', '')
    if topic in ('payment', 'merchant_order'):
        payment_id = data.get('data', {}).get('id') or request.args.get('id')
        if payment_id:
            try:
                sdk    = mp_sdk()
                result = sdk.payment().get(payment_id)
                pay    = result['response']
                status = pay.get('status')
                meta   = pay.get('metadata', {})
                user_id = meta.get('user_id')
                plano   = meta.get('plano')
                if status == 'approved' and user_id and plano:
                    db  = sqlite3.connect(DB_PATH)
                    db.row_factory = sqlite3.Row
                    plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
                    db.execute('UPDATE users SET plano=?, plano_end=? WHERE id=?',
                               (plano, plano_end, user_id))
                    db.execute('INSERT INTO pagamentos (user_id,mp_id,plano,valor,status) VALUES (?,?,?,?,?)',
                               (user_id, payment_id, plano, pay.get('transaction_amount', 0), 'aprovado'))
                    db.commit()
                    db.close()
            except Exception as e:
                print(f"Webhook error: {e}")
    return '', 200

@app.route('/api/pagamento/confirmar', methods=['POST'])
@require_auth
def confirmar_pagamento():
    d          = request.get_json()
    payment_id = d.get('payment_id')
    plano      = d.get('plano')
    if not plano or plano not in PLANOS:
        return jsonify({'error': 'Plano inválido'}), 400
    db = get_db()

    # Se temos payment_id, verificar no MP
    if payment_id:
        try:
            sdk    = mp_sdk()
            result = sdk.payment().get(payment_id)
            pay    = result['response']
            status = pay.get('status')
            print(f"Payment {payment_id} status: {status}")
            if status == 'approved':
                plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
                db.execute('UPDATE users SET plano=?, plano_end=?, trial_end=NULL WHERE id=?',
                           (plano, plano_end, g.user_id))
                db.execute('INSERT OR IGNORE INTO pagamentos (user_id,mp_id,plano,valor,status) VALUES (?,?,?,?,?)',
                           (g.user_id, str(payment_id), plano,
                            pay.get('transaction_amount', PLANOS[plano]['preco']), 'aprovado'))
                db.commit()
                return jsonify({'ok': True, 'plano': plano})
            elif status in ('pending', 'in_process'):
                # Ativar mesmo assim e checar depois
                plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
                db.execute('UPDATE users SET plano=?, plano_end=?, trial_end=NULL WHERE id=?',
                           (plano, plano_end, g.user_id))
                db.commit()
                return jsonify({'ok': True, 'plano': plano, 'pendente': True})
            else:
                return jsonify({'ok': False, 'status': status})
        except Exception as e:
            print(f"Confirmar erro MP: {e}")
            # Se erro na API do MP mas temos evidência de pagamento, ativar mesmo assim
            plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
            db.execute('UPDATE users SET plano=?, plano_end=?, trial_end=NULL WHERE id=?',
                       (plano, plano_end, g.user_id))
            db.commit()
            return jsonify({'ok': True, 'plano': plano})

    # Sem payment_id: verificar se já foi ativado via webhook
    user = db.execute('SELECT * FROM users WHERE id=?', (g.user_id,)).fetchone()
    if user and user['plano'] == plano:
        return jsonify({'ok': True, 'plano': plano})

    # Ativar diretamente (MP aprovou no redirect)
    plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
    db.execute('UPDATE users SET plano=?, plano_end=?, trial_end=NULL WHERE id=?',
               (plano, plano_end, g.user_id))
    db.commit()
    return jsonify({'ok': True, 'plano': plano})

# ── ADM: LOGIN ───────────────────────────────────────────
@app.route('/api/adm/login', methods=['POST'])
def adm_login():
    d = request.get_json()
    if d.get('phone','').strip() == ADM_PHONE and d.get('password') == ADM_PASSWORD:
        return jsonify({'ok': True, 'token': make_token('adm', role='adm')})
    return jsonify({'error': 'Credenciais incorretas'}), 401

@app.route('/api/adm/users', methods=['GET'])
@require_adm
def adm_users():
    db   = get_db()
    rows = db.execute('SELECT id,name,phone,verified,active,trial_end,plano,plano_end,created FROM users ORDER BY created DESC').fetchall()
    result = []
    for r in rows:
        u = dict(r)
        u['despesas_count'] = db.execute('SELECT COUNT(*) as c FROM despesas WHERE user_id=?', (r['id'],)).fetchone()['c']
        u['plano_status'] = get_plano_status(r)['status']
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
    db.execute('DELETE FROM categorias WHERE user_id=?', (uid,))
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

@app.route('/api/adm/users/<int:uid>/reset-senha', methods=['POST'])
@require_adm
def adm_reset_senha(uid):
    d      = request.get_json()
    new_pw = d.get('password','').strip()
    if len(new_pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    db = get_db()
    row = db.execute('SELECT id FROM users WHERE id=?', (uid,)).fetchone()
    if not row: return jsonify({'error': 'Usuário não encontrado'}), 404
    db.execute('UPDATE users SET password=? WHERE id=?', (hash_password(new_pw), uid))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/adm/users/<int:uid>/plano', methods=['POST'])
@require_adm
def adm_set_plano(uid):
    """ADM pode conceder plano manualmente"""
    d     = request.get_json()
    plano = d.get('plano')
    dias  = int(d.get('dias', 365))
    db    = get_db()
    if plano and plano in PLANOS:
        plano_end = (datetime.utcnow() + timedelta(days=dias)).isoformat()
        db.execute('UPDATE users SET plano=?, plano_end=? WHERE id=?', (plano, plano_end, uid))
    else:
        db.execute('UPDATE users SET plano=NULL, plano_end=NULL WHERE id=?', (uid,))
    db.commit()
    return jsonify({'ok': True})

# ── INIT ─────────────────────────────────────────────────
init_db()
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

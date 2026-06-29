import os, hashlib, base64, json, secrets, string
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g, Response
import jwt
import mercadopago
import requests as http_requests
from supabase import create_client, Client as SupabaseClient

app = Flask(__name__, static_folder='static')

# ── CONFIG ───────────────────────────────────────────────
SECRET_KEY      = os.environ.get('SECRET_KEY', 'dev-secret')
ADM_EMAIL       = os.environ.get('ADM_EMAIL', 'felipep_s@yahoo.com.br')
ADM_PASSWORD    = os.environ.get('ADM_PASSWORD', 'Admin@2025!')
MP_ACCESS_TOKEN = os.environ.get('MP_ACCESS_TOKEN', '')
APP_URL         = os.environ.get('APP_URL', 'https://controle3.onrender.com')
SUPABASE_URL    = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY    = os.environ.get('SUPABASE_KEY', '')
RESEND_API_KEY  = os.environ.get('RESEND_API_KEY', '')
EMAIL_FROM      = os.environ.get('EMAIL_FROM', 'noreply@nexapi.com.br')

PLANOS = {
    'basico': {
        'nome': 'Básico', 'limite': 50, 'preco': 39.90,
        'fotos': False, 'relatorios': False, 'categorias_custom': False,
        'descricao': 'Até 50 lançamentos/mês'
    },
    'standard': {
        'nome': 'Standard', 'limite': 150, 'preco': 69.90,
        'fotos': True, 'relatorios': True, 'categorias_custom': False,
        'descricao': 'Até 150 lançamentos/mês'
    },
    'premium': {
        'nome': 'Premium', 'limite': 999999, 'preco': 119.90,
        'fotos': True, 'relatorios': True, 'categorias_custom': True,
        'descricao': 'Lançamentos ilimitados'
    },
}

# ── SUPABASE CLIENT ──────────────────────────────────────
def get_sb() -> SupabaseClient:
    return create_client(SUPABASE_URL, SUPABASE_KEY)

# ── HELPERS ──────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def make_token(user_id, role='user'):
    payload = {'sub': user_id, 'role': role, 'exp': datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def twilio_client():
    return Client(TWILIO_SID, TWILIO_TOKEN)

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

def mp_sdk():
    return mercadopago.SDK(MP_ACCESS_TOKEN)

# ── EMAIL (Resend) ────────────────────────────────────────
def gerar_codigo():
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def send_email(to, subject, html):
    try:
        r = http_requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {RESEND_API_KEY}', 'Content-Type': 'application/json'},
            json={'from': f'Despesas Pessoais <{EMAIL_FROM}>', 'to': [to], 'subject': subject, 'html': html}
        )
        return r.status_code == 200
    except Exception as e:
        print(f"Erro email: {e}"); return False

def email_verificacao(to, nome, codigo):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0a0f;color:#f0f0f0;border-radius:12px;padding:32px;border:1px solid rgba(0,212,255,.2)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px;font-weight:700;color:#00d4ff">π NexaPI</div>
        <div style="font-size:13px;color:#606070;margin-top:4px">Despesas Pessoais</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#fff;margin-bottom:8px">Olá, {nome}!</h2>
      <p style="color:#a0a0b0;font-size:14px;line-height:1.6;margin-bottom:24px">
        Use o código abaixo para verificar seu e-mail e ativar sua conta:
      </p>
      <div style="background:#14141e;border:1px solid rgba(0,212,255,.3);border-radius:10px;padding:20px;text-align:center;margin-bottom:24px">
        <div style="font-size:36px;font-weight:700;color:#00d4ff;letter-spacing:10px">{codigo}</div>
        <div style="font-size:12px;color:#606070;margin-top:8px">Válido por 15 minutos</div>
      </div>
      <p style="color:#606070;font-size:12px;text-align:center">
        Se não criou uma conta no Despesas Pessoais, ignore este email.
      </p>
      <div style="border-top:1px solid rgba(255,255,255,.06);margin-top:24px;padding-top:16px;text-align:center">
        <a href="https://www.nexapi.com.br" style="color:#00d4ff;font-size:12px;text-decoration:none">www.nexapi.com.br</a>
      </div>
    </div>"""
    return send_email(to, 'Código de verificação — Despesas Pessoais', html)

def email_reset_senha(to, nome, codigo):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0a0f;color:#f0f0f0;border-radius:12px;padding:32px;border:1px solid rgba(0,212,255,.2)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px;font-weight:700;color:#00d4ff">π NexaPI</div>
        <div style="font-size:13px;color:#606070;margin-top:4px">Despesas Pessoais</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#fff;margin-bottom:8px">Redefinir senha</h2>
      <p style="color:#a0a0b0;font-size:14px;line-height:1.6;margin-bottom:24px">
        Olá {nome}, use o código abaixo para redefinir sua senha:
      </p>
      <div style="background:#14141e;border:1px solid rgba(255,165,2,.3);border-radius:10px;padding:20px;text-align:center;margin-bottom:24px">
        <div style="font-size:36px;font-weight:700;color:#ffa502;letter-spacing:10px">{codigo}</div>
        <div style="font-size:12px;color:#606070;margin-top:8px">Válido por 15 minutos</div>
      </div>
      <p style="color:#606070;font-size:12px;text-align:center">
        Se não solicitou a redefinição, ignore este email.
      </p>
      <div style="border-top:1px solid rgba(255,255,255,.06);margin-top:24px;padding-top:16px;text-align:center">
        <a href="https://www.nexapi.com.br" style="color:#00d4ff;font-size:12px;text-decoration:none">www.nexapi.com.br</a>
      </div>
    </div>"""
    return send_email(to, 'Redefinir senha — Despesas Pessoais', html)

def make_token(user_id, role='user'):
    payload = {'sub': user_id, 'role': role, 'exp': datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def get_plano_status(user):
    if str(user.get('email','')) == ADM_EMAIL:
        return {'status': 'adm', 'pode_adicionar': True, 'limite': 9999, 'uso_mes': 0,
                'fotos': True, 'relatorios': True, 'categorias_custom': True}

    def dt_to_naive(s):
        if not s: return None
        s = str(s).replace('Z','+00:00')
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo: return dt.replace(tzinfo=None)
            return dt
        except: return None

    now = datetime.utcnow()

    # Plano pago tem prioridade
    plano     = user.get('plano')
    plano_end = dt_to_naive(user.get('plano_end'))
    if plano and plano_end and now < plano_end:
        dias = (plano_end - now).days
        p    = PLANOS.get(plano, {})
        return {
            'status': 'ativo', 'plano': plano, 'pode_adicionar': True,
            'limite': p.get('limite', 100), 'plano_end': str(plano_end),
            'plano_dias': dias, 'nome': p.get('nome', plano),
            'fotos': p.get('fotos', False),
            'relatorios': p.get('relatorios', False),
            'categorias_custom': p.get('categorias_custom', False),
        }

    # Trial: acesso limitado a 10 lançamentos/mês
    trial_end = dt_to_naive(user.get('trial_end'))
    if trial_end and now < trial_end:
        dias = (trial_end - now).days
        return {'status': 'trial', 'pode_adicionar': True, 'limite': 10,
                'uso_mes': 0, 'trial_dias': dias,
                'fotos': True, 'relatorios': True, 'categorias_custom': True}

    return {'status': 'expirado', 'pode_adicionar': False, 'limite': 0, 'uso_mes': 0,
            'fotos': False, 'relatorios': False, 'categorias_custom': False}

def count_mes_atual(user_id):
    sb  = get_sb()
    now = datetime.utcnow()
    mes = f"{now.month:02d}/{str(now.year)[2:]}"
    res = sb.table('despesas').select('id', count='exact').eq('user_id', user_id).like('date', f'%/{mes}').execute()
    return res.count or 0

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

# ── AUTH ─────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    d     = request.get_json()
    name  = d.get('name','').strip()
    email = d.get('email','').strip().lower()
    pw    = d.get('password','')
    if not name or not email or not pw:
        return jsonify({'error': 'Preencha todos os campos'}), 400
    if '@' not in email:
        return jsonify({'error': 'Email inválido'}), 400
    if len(pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    sb = get_sb()
    existing = sb.table('users').select('id,verified').eq('email', email).execute()
    if existing.data:
        user = existing.data[0]
        if user['verified']:
            return jsonify({'error': 'Email já cadastrado'}), 409
        codigo = gerar_codigo()
        exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        sb.table('users').update({'verify_code': codigo, 'verify_exp': exp, 'name': name}).eq('id', user['id']).execute()
        email_verificacao(email, name, codigo)
        return jsonify({'ok': True, 'message': 'Código reenviado'})
    trial_end = (datetime.utcnow() + timedelta(days=30)).isoformat()
    codigo    = gerar_codigo()
    exp       = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    res = sb.table('users').insert({
        'name': name, 'email': email,
        'password': hash_password(pw),
        'trial_end': trial_end, 'verified': False, 'active': True,
        'verify_code': codigo, 'verify_exp': exp
    }).execute()
    email_verificacao(email, name, codigo)
    return jsonify({'ok': True, 'message': 'Código enviado por email'})

@app.route('/api/auth/verify', methods=['POST'])
def verify_email():
    d      = request.get_json()
    email  = d.get('email','').strip().lower()
    codigo = d.get('code','').strip()
    sb     = get_sb()
    res    = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error': 'Email não encontrado'}), 404
    user = res.data[0]
    now  = datetime.utcnow().isoformat()
    if user.get('verify_code') != codigo:
        return jsonify({'error': 'Código incorreto'}), 400
    if user.get('verify_exp') and now > user['verify_exp']:
        return jsonify({'error': 'Código expirado. Solicite novo cadastro.'}), 400
    sb.table('users').update({'verified': True, 'verify_code': None, 'verify_exp': None}).eq('id', user['id']).execute()
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/login', methods=['POST'])
def login():
    d     = request.get_json()
    email = d.get('email','').strip().lower()
    pw    = d.get('password','')
    sb    = get_sb()
    res   = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error': 'Email ou senha incorretos'}), 401
    user = res.data[0]
    if user['password'] != hash_password(pw):
        return jsonify({'error': 'Email ou senha incorretos'}), 401
    if not user.get('verified'):
        codigo = gerar_codigo()
        exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        sb.table('users').update({'verify_code': codigo, 'verify_exp': exp}).eq('id', user['id']).execute()
        email_verificacao(email, user['name'], codigo)
        return jsonify({'error': 'Verifique seu email', 'unverified': True, 'email': email}), 403
    if not user.get('active', True):
        return jsonify({'error': 'Conta desativada'}), 403
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/forgot', methods=['POST'])
def forgot():
    d     = request.get_json()
    email = d.get('email','').strip().lower()
    sb    = get_sb()
    res   = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'ok': True})
    user   = res.data[0]
    codigo = gerar_codigo()
    exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    sb.table('users').update({'verify_code': codigo, 'verify_exp': exp}).eq('id', user['id']).execute()
    email_reset_senha(email, user['name'], codigo)
    return jsonify({'ok': True})

@app.route('/api/auth/reset', methods=['POST'])
def reset_password():
    d      = request.get_json()
    email  = d.get('email','').strip().lower()
    codigo = d.get('code','').strip()
    new_pw = d.get('password','')
    if len(new_pw) < 6: return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    sb  = get_sb()
    res = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error': 'Email não encontrado'}), 404
    user = res.data[0]
    now  = datetime.utcnow().isoformat()
    if user.get('verify_code') != codigo:
        return jsonify({'error': 'Código incorreto'}), 400
    if user.get('verify_exp') and now > user['verify_exp']:
        return jsonify({'error': 'Código expirado'}), 400
    sb.table('users').update({
        'password': hash_password(new_pw),
        'verify_code': None, 'verify_exp': None
    }).eq('id', user['id']).execute()
    return jsonify({'ok': True})

# ── STATUS DA CONTA ──────────────────────────────────────
@app.route('/api/conta/status', methods=['GET'])
@require_auth
def conta_status():
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    ps   = get_plano_status(user)
    if ps['status'] == 'ativo':
        uso = count_mes_atual(g.user_id)
        ps['uso_mes'] = uso
        ps['pode_adicionar'] = uso < ps['limite']
    ps['planos_disponiveis'] = {k: {'nome': v['nome'], 'limite': v['limite'], 'preco': v['preco']} for k,v in PLANOS.items()}
    return jsonify(ps)

# ── CATEGORIAS ───────────────────────────────────────────
CATS_PADRAO = ['Combustível','Alimentação','Lazer','Saúde','Transporte','Moradia','Educação','Vestuário','Outros']

@app.route('/api/categorias', methods=['GET'])
@require_auth
def get_categorias():
    sb   = get_sb()
    rows = sb.table('categorias').select('*').eq('user_id', g.user_id).order('criada').execute()
    return jsonify({'padrao': CATS_PADRAO, 'custom': rows.data})

@app.route('/api/categorias', methods=['POST'])
@require_auth
def add_categoria():
    d    = request.get_json()
    nome = d.get('nome','').strip()
    if not nome: return jsonify({'error': 'Nome obrigatório'}), 400
    if nome in CATS_PADRAO: return jsonify({'error': 'Categoria já existe'}), 409
    sb  = get_sb()
    res = sb.table('users').select('*').eq('id', g.user_id).execute()
    user = res.data[0] if res.data else {}
    ps   = get_plano_status(user)
    if not ps.get('categorias_custom', False):
        return jsonify({'error': 'sem_permissao', 'recurso': 'categorias_custom',
                        'plano_minimo': 'premium'}), 403
    existing = sb.table('categorias').select('id').eq('user_id', g.user_id).eq('nome', nome).execute()
    if existing.data: return jsonify({'error': 'Categoria já existe'}), 409
    res = sb.table('categorias').insert({
        'user_id': g.user_id, 'nome': nome,
        'icone': d.get('icone','ti-tag'),
        'cor_bg': d.get('cor_bg','#F1EFE8'),
        'cor_text': d.get('cor_text','#2C2C2A'),
        'cor_bar': d.get('cor_bar','#888')
    }).execute()
    return jsonify({'ok': True, 'id': res.data[0]['id']})

@app.route('/api/categorias/<int:cid>', methods=['DELETE'])
@require_auth
def delete_categoria(cid):
    sb  = get_sb()
    row = sb.table('categorias').select('*').eq('id', cid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrada'}), 404
    nome = row.data[0]['nome']
    count = sb.table('despesas').select('id', count='exact').eq('user_id', g.user_id).eq('cat', nome).execute()
    if count.count and count.count > 0:
        return jsonify({'error': f'Categoria em uso em {count.count} lançamento(s)'}), 409
    sb.table('categorias').delete().eq('id', cid).execute()
    return jsonify({'ok': True})

# ── DESPESAS ─────────────────────────────────────────────
@app.route('/api/despesas', methods=['GET'])
@require_auth
def get_despesas():
    sb   = get_sb()
    rows = sb.table('despesas').select('*').eq('user_id', g.user_id).order('ts', desc=True).execute()
    result = []
    for e in rows.data:
        if e.get('photo_data'):
            e['photo_inline'] = 'data:image/jpeg;base64,' + e['photo_data']
        e.pop('photo_data', None)
        result.append(e)
    return jsonify(result)

@app.route('/api/despesas', methods=['POST'])
@require_auth
def add_despesa():
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    ps   = get_plano_status(user)
    if not ps['pode_adicionar']:
        return jsonify({'error': 'plano_expirado', 'status': ps['status']}), 403
    # Verificar limite para plano ativo E trial (premium é ilimitado)
    if ps['status'] in ('ativo', 'trial') and ps.get('limite', 0) < 999999:
        uso = count_mes_atual(g.user_id)
        if uso >= ps['limite']:
            return jsonify({'error': 'limite_atingido', 'uso': uso, 'limite': ps['limite']}), 403
    d   = request.get_json()
    obs = (d.get('obs') or '').strip()[:300]
    ins = sb.table('despesas').insert({
        'user_id': g.user_id,
        'cat': d['cat'], 'val': d['val'],
        'date': d.get('date'), 'time': d.get('time'), 'ts': d.get('ts'),
        'obs': obs if obs else None
    }).execute()
    return jsonify({'ok': True, 'id': ins.data[0]['id']})

@app.route('/api/despesas/<int:eid>', methods=['PUT'])
@require_auth
def edit_despesa(eid):
    sb  = get_sb()
    row = sb.table('despesas').select('*').eq('id', eid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    d   = request.get_json()
    obs = (d.get('obs') or '').strip()[:300]
    sb.table('despesas').update({
        'cat': d['cat'], 'val': float(d['val']),
        'obs': obs if obs else None
    }).eq('id', eid).execute()
    return jsonify({'ok': True})

@app.route('/api/despesas/<int:eid>', methods=['DELETE'])
@require_auth
def delete_despesa(eid):
    sb  = get_sb()
    row = sb.table('despesas').select('*').eq('id', eid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    e = row.data[0]
    # Remover foto do storage se existir
    if e.get('photo_path'):
        try: sb.storage.from_('recibos').remove([e['photo_path']])
        except: pass
    sb.table('despesas').delete().eq('id', eid).execute()
    return jsonify({'ok': True})

@app.route('/api/despesas/clear', methods=['POST'])
@require_auth
def clear_despesas():
    sb   = get_sb()
    rows = sb.table('despesas').select('photo_path').eq('user_id', g.user_id).execute()
    paths = [r['photo_path'] for r in rows.data if r.get('photo_path')]
    if paths:
        try: sb.storage.from_('recibos').remove(paths)
        except: pass
    sb.table('despesas').delete().eq('user_id', g.user_id).execute()
    return jsonify({'ok': True})

# ── RECEITAS ─────────────────────────────────────────────
@app.route('/api/receitas', methods=['GET'])
@require_auth
def get_receitas():
    sb   = get_sb()
    rows = sb.table('receitas').select('*').eq('user_id', g.user_id).order('ts', desc=True).execute()
    return jsonify(rows.data or [])

@app.route('/api/receitas', methods=['POST'])
@require_auth
def add_receita():
    d   = request.get_json()
    sb  = get_sb()
    obs = (d.get('obs') or '').strip()[:300]
    ins = sb.table('receitas').insert({
        'user_id': g.user_id,
        'descricao': d.get('desc','Receita'), 'val': float(d['val']),
        'date': d.get('date'), 'time': d.get('time'), 'ts': d.get('ts'),
        'obs': obs if obs else None
    }).execute()
    return jsonify({'ok': True, 'id': ins.data[0]['id']})

@app.route('/api/receitas/<int:rid>', methods=['DELETE'])
@require_auth
def delete_receita(rid):
    sb  = get_sb()
    row = sb.table('receitas').select('id').eq('id', rid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    sb.table('receitas').delete().eq('id', rid).execute()
    return jsonify({'ok': True})

# ── METAS ─────────────────────────────────────────────────
@app.route('/api/metas', methods=['GET'])
@require_auth
def get_metas():
    sb   = get_sb()
    rows = sb.table('metas').select('*').eq('user_id', g.user_id).execute()
    return jsonify(rows.data or [])

@app.route('/api/metas', methods=['POST'])
@require_auth
def save_meta():
    d   = request.get_json()
    cat = d.get('cat','').strip()
    val = float(d.get('val', 0))
    if not cat or val <= 0: return jsonify({'error': 'Dados inválidos'}), 400
    sb  = get_sb()
    existing = sb.table('metas').select('id').eq('user_id', g.user_id).eq('cat', cat).execute()
    if existing.data:
        sb.table('metas').update({'val': val}).eq('id', existing.data[0]['id']).execute()
    else:
        sb.table('metas').insert({'user_id': g.user_id, 'cat': cat, 'val': val}).execute()
    return jsonify({'ok': True})

@app.route('/api/metas/<cat>', methods=['DELETE'])
@require_auth
def delete_meta(cat):
    sb = get_sb()
    sb.table('metas').delete().eq('user_id', g.user_id).eq('cat', cat).execute()
    return jsonify({'ok': True})

# ── CUPONS ────────────────────────────────────────────────
@app.route('/api/cupom/validar', methods=['POST'])
@require_auth
def validar_cupom():
    d    = request.get_json()
    code = d.get('code','').strip().upper()
    sb   = get_sb()
    row  = sb.table('cupons').select('*').eq('code', code).eq('ativo', True).execute()
    if not row.data: return jsonify({'error': 'Cupom inválido ou expirado'}), 404
    cupom = row.data[0]
    if cupom.get('usos_max') and cupom.get('usos_atual', 0) >= cupom['usos_max']:
        return jsonify({'error': 'Cupom esgotado'}), 410
    return jsonify({'ok': True, 'desconto': cupom['desconto'], 'tipo': cupom.get('tipo','pct')})

@app.route('/api/adm/cupons', methods=['GET'])
@require_adm
def adm_get_cupons():
    sb   = get_sb()
    rows = sb.table('cupons').select('*').order('criado', desc=True).execute()
    return jsonify(rows.data or [])

@app.route('/api/adm/cupons', methods=['POST'])
@require_adm
def adm_create_cupom():
    d  = request.get_json()
    sb = get_sb()
    sb.table('cupons').insert({
        'code':     d.get('code','').strip().upper(),
        'desconto': float(d.get('desconto', 10)),
        'tipo':     d.get('tipo', 'pct'),
        'usos_max': d.get('usos_max'),
        'usos_atual': 0,
        'ativo':    True
    }).execute()
    return jsonify({'ok': True})

@app.route('/api/adm/cupons/<code>/toggle', methods=['POST'])
@require_adm
def adm_toggle_cupom(code):
    sb  = get_sb()
    row = sb.table('cupons').select('ativo').eq('code', code).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    new = not row.data[0]['ativo']
    sb.table('cupons').update({'ativo': new}).eq('code', code).execute()
    return jsonify({'ok': True, 'ativo': new})

# ── RECORRENTES ──────────────────────────────────────────
@app.route('/api/recorrentes', methods=['GET'])
@require_auth
def get_recorrentes():
    sb   = get_sb()
    rows = sb.table('recorrentes').select('*').eq('user_id', g.user_id).eq('ativo', True).order('criado').execute()
    return jsonify(rows.data or [])

@app.route('/api/recorrentes', methods=['POST'])
@require_auth
def add_recorrente():
    d  = request.get_json()
    sb = get_sb()
    res = sb.table('recorrentes').insert({
        'user_id':   g.user_id,
        'cat':       d.get('cat'),
        'val':       float(d.get('val', 0)),
        'descricao': d.get('descricao',''),
        'dia_venc':  int(d.get('dia_venc', 1)),
        'ativo':     True
    }).execute()
    return jsonify({'ok': True, 'id': res.data[0]['id']})

@app.route('/api/recorrentes/<int:rid>', methods=['DELETE'])
@require_auth
def delete_recorrente(rid):
    sb  = get_sb()
    row = sb.table('recorrentes').select('id').eq('id', rid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    sb.table('recorrentes').update({'ativo': False}).eq('id', rid).execute()
    return jsonify({'ok': True})

@app.route('/api/recorrentes/lancar', methods=['POST'])
@require_auth
def lancar_recorrentes():
    """Lança as recorrentes do mês atual que ainda não foram lançadas"""
    sb   = get_sb()
    now  = datetime.utcnow()
    mes  = f"{now.month:02d}/{str(now.year)[2:]}"
    rows = sb.table('recorrentes').select('*').eq('user_id', g.user_id).eq('ativo', True).execute()
    lancados = 0
    for r in (rows.data or []):
        # Verificar se já foi lançado esse mês
        existe = sb.table('despesas').select('id').eq('user_id', g.user_id)\
            .eq('recorrente_id', r['id']).like('date', f"%/{mes}").execute()
        if existe.data: continue
        dia = min(int(r.get('dia_venc') or 1), 28)
        date_str = f"{dia:02d}/{mes}"
        sb.table('despesas').insert({
            'user_id':      g.user_id,
            'cat':          r['cat'],
            'val':          r['val'],
            'date':         date_str,
            'time':         '00:00',
            'ts':           int(now.timestamp() * 1000),
            'obs':          r.get('descricao') or 'Recorrente',
            'recorrente_id': r['id']
        }).execute()
        lancados += 1
    return jsonify({'ok': True, 'lancados': lancados})

# ── PARCELAMENTOS ─────────────────────────────────────────
@app.route('/api/parcelamentos', methods=['GET'])
@require_auth
def get_parcelamentos():
    sb   = get_sb()
    rows = sb.table('parcelamentos').select('*').eq('user_id', g.user_id).eq('ativo', True).order('criado').execute()
    return jsonify(rows.data or [])

@app.route('/api/parcelamentos', methods=['POST'])
@require_auth
def add_parcelamento():
    d      = request.get_json()
    sb     = get_sb()
    cat    = d.get('cat')
    desc   = d.get('descricao','')
    val    = float(d.get('val_parcela', 0))
    total  = int(d.get('total_parcelas', 1))
    inicio = d.get('data_inicio','')  # formato MM/YY
    if not cat or val <= 0 or total < 1:
        return jsonify({'error': 'Dados inválidos'}), 400
    # Criar o parcelamento
    res = sb.table('parcelamentos').insert({
        'user_id':        g.user_id,
        'cat':            cat,
        'descricao':      desc,
        'val_parcela':    val,
        'total_parcelas': total,
        'parcela_atual':  1,
        'data_inicio':    inicio,
        'ativo':          True
    }).execute()
    parc_id = res.data[0]['id']
    # Lançar todas as parcelas
    now = datetime.utcnow()
    if inicio:
        try:
            mes_i, ano_i = inicio.split('/')
            mes_atual = int(mes_i)
            ano_atual = 2000 + int(ano_i)
        except:
            mes_atual = now.month
            ano_atual = now.year
    else:
        mes_atual = now.month
        ano_atual = now.year
    for i in range(total):
        m = ((mes_atual - 1 + i) % 12) + 1
        a = ano_atual + ((mes_atual - 1 + i) // 12)
        date_str = f"01/{m:02d}/{str(a)[2:]}"
        sb.table('despesas').insert({
            'user_id':          g.user_id,
            'cat':              cat,
            'val':              val,
            'date':             date_str,
            'time':             '00:00',
            'ts':               int(now.timestamp() * 1000) + i,
            'obs':              f"{desc} ({i+1}/{total})",
            'parcelamento_id':  parc_id,
            'parcela_num':      i + 1
        }).execute()
    return jsonify({'ok': True, 'id': parc_id, 'parcelas_criadas': total})

@app.route('/api/parcelamentos/<int:pid>', methods=['DELETE'])
@require_auth
def delete_parcelamento(pid):
    sb  = get_sb()
    row = sb.table('parcelamentos').select('id').eq('id', pid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    # Remover parcelas futuras
    now = datetime.utcnow()
    mes = f"{now.month:02d}/{str(now.year)[2:]}"
    sb.table('despesas').delete().eq('user_id', g.user_id)\
        .eq('parcelamento_id', pid).execute()
    sb.table('parcelamentos').update({'ativo': False}).eq('id', pid).execute()
    return jsonify({'ok': True})

# ── OBSERVAÇÃO ───────────────────────────────────────────
@app.route('/api/obs', methods=['POST'])
@require_auth
def save_obs():
    d   = request.get_json()
    eid = d.get('id')
    obs = (d.get('obs') or '').strip()[:300]
    sb  = get_sb()
    row = sb.table('despesas').select('id').eq('id', eid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    sb.table('despesas').update({'obs': obs if obs else None}).eq('id', eid).execute()
    return jsonify({'ok': True})

# ── FOTOS (Supabase Storage) ──────────────────────────────
@app.route('/api/photo', methods=['POST'])
@require_auth
def upload_photo():
    d       = request.get_json()
    eid     = d.get('id')
    img_b64 = d.get('image','')
    sb      = get_sb()
    # Verificar permissão de fotos
    if img_b64:
        res  = sb.table('users').select('*').eq('id', g.user_id).execute()
        user = res.data[0] if res.data else {}
        ps   = get_plano_status(user)
        if not ps.get('fotos', False):
            return jsonify({'error': 'sem_permissao', 'recurso': 'fotos',
                            'plano_minimo': 'standard'}), 403
    row     = sb.table('despesas').select('*').eq('id', eid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    e = row.data[0]
    if not img_b64:
        if e.get('photo_path'):
            try: sb.storage.from_('recibos').remove([e['photo_path']])
            except: pass
        sb.table('despesas').update({'photo': None, 'photo_path': None, 'photo_data': None}).eq('id', eid).execute()
        return jsonify({'ok': True})
    b64_puro = img_b64.split(',')[1] if ',' in img_b64 else img_b64
    img_bytes = base64.b64decode(b64_puro)
    path = f"{g.user_id}/{eid}.jpg"
    try:
        # Upload para Supabase Storage
        sb.storage.from_('recibos').upload(
            path, img_bytes,
            file_options={'content-type': 'image/jpeg', 'upsert': 'true'}
        )
        # URL pública assinada (1 ano)
        signed = sb.storage.from_('recibos').create_signed_url(path, 31536000)
        photo_url = signed.get('signedURL') or signed.get('signedUrl','')
        sb.table('despesas').update({
            'photo': path,
            'photo_path': path,
            'photo_data': b64_puro  # fallback inline
        }).eq('id', eid).execute()
        return jsonify({'ok': True, 'photo': path, 'photo_inline': img_b64 if img_b64.startswith('data:') else 'data:image/jpeg;base64,'+b64_puro})
    except Exception as ex:
        print(f"Erro upload foto: {ex}")
        # Fallback: salvar base64 no banco mesmo
        ref = f"db_{g.user_id}_{eid}"
        sb.table('despesas').update({'photo': ref, 'photo_data': b64_puro}).eq('id', eid).execute()
        return jsonify({'ok': True, 'photo': ref, 'photo_inline': 'data:image/jpeg;base64,'+b64_puro})

@app.route('/api/photo/<path:ref>', methods=['GET'])
@require_auth
def get_photo(ref):
    sb = get_sb()
    if ref.startswith('db_'):
        parts = ref.split('_')
        if str(g.user_id) != parts[1]:
            return jsonify({'error': 'Acesso negado'}), 403
        eid = parts[2]
        row = sb.table('despesas').select('photo_data').eq('id', eid).eq('user_id', g.user_id).execute()
        if not row.data or not row.data[0].get('photo_data'):
            return '', 404
        img_bytes = base64.b64decode(row.data[0]['photo_data'])
        return Response(img_bytes, mimetype='image/jpeg', headers={'Cache-Control': 'max-age=86400'})
    # Supabase Storage: gerar URL assinada e redirecionar
    try:
        signed = sb.storage.from_('recibos').create_signed_url(ref, 3600)
        url = signed.get('signedURL') or signed.get('signedUrl','')
        if url:
            from flask import redirect
            return redirect(url)
    except Exception as ex:
        print(f"Erro get_photo: {ex}")
    return '', 404

# ── PAGAMENTO ────────────────────────────────────────────
@app.route('/api/pagamento/criar', methods=['POST'])
@require_auth
def criar_pagamento():
    d     = request.get_json()
    plano = d.get('plano')
    if plano not in PLANOS: return jsonify({'error': 'Plano inválido'}), 400
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    sdk  = mp_sdk()
    p    = PLANOS[plano]
    pref_data = {
        'items': [{'title': f"Despesas Pessoais — Plano {p['nome']} (Anual)",
                   'quantity': 1, 'currency_id': 'BRL', 'unit_price': p['preco']}],
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
    result = sdk.preference().create(pref_data)
    if result['status'] != 201: return jsonify({'error': 'Erro ao criar preferência'}), 500
    pref = result['response']
    sb.table('pagamentos').insert({'user_id': g.user_id, 'mp_id': pref['id'],
                                   'plano': plano, 'valor': p['preco'], 'status': 'pendente'}).execute()
    return jsonify({'ok': True, 'init_point': pref['init_point']})

@app.route('/api/pagamento/webhook', methods=['POST'])
def webhook():
    data  = request.get_json(silent=True) or {}
    topic = data.get('type') or request.args.get('topic','')
    if topic in ('payment', 'merchant_order'):
        payment_id = data.get('data',{}).get('id') or request.args.get('id')
        if payment_id:
            try:
                pay    = mp_sdk().payment().get(payment_id)['response']
                status = pay.get('status')
                meta   = pay.get('metadata', {})
                uid    = meta.get('user_id')
                plano  = meta.get('plano')
                if status == 'approved' and uid and plano:
                    sb        = get_sb()
                    plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
                    sb.table('users').update({'plano': plano, 'plano_end': plano_end, 'trial_end': None}).eq('id', uid).execute()
                    sb.table('pagamentos').insert({'user_id': uid, 'mp_id': str(payment_id),
                                                   'plano': plano, 'valor': pay.get('transaction_amount',0), 'status': 'aprovado'}).execute()
            except Exception as e:
                print(f"Webhook error: {e}")
    return '', 200

@app.route('/api/pagamento/confirmar', methods=['POST'])
@require_auth
def confirmar_pagamento():
    d          = request.get_json()
    payment_id = d.get('payment_id')
    plano      = d.get('plano')
    if not plano or plano not in PLANOS: return jsonify({'error': 'Plano inválido'}), 400
    sb        = get_sb()
    plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
    if payment_id:
        try:
            pay    = mp_sdk().payment().get(payment_id)['response']
            status = pay.get('status')
            print(f"Payment {payment_id} status: {status}")
            if status not in ('approved','pending','in_process'):
                return jsonify({'ok': False, 'status': status})
        except Exception as e:
            print(f"MP error: {e}")
    sb.table('users').update({'plano': plano, 'plano_end': plano_end, 'trial_end': None}).eq('id', g.user_id).execute()
    try:
        sb.table('pagamentos').insert({'user_id': g.user_id, 'mp_id': str(payment_id) if payment_id else None,
                                       'plano': plano, 'valor': PLANOS[plano]['preco'], 'status': 'aprovado'}).execute()
    except: pass
    return jsonify({'ok': True, 'plano': plano})

# ── ADM ──────────────────────────────────────────────────
@app.route('/api/adm/login', methods=['POST'])
def adm_login():
    d = request.get_json()
    if d.get('email','').strip().lower() == ADM_EMAIL and d.get('password') == ADM_PASSWORD:
        return jsonify({'ok': True, 'token': make_token('adm', role='adm')})
    return jsonify({'error': 'Credenciais incorretas'}), 401

@app.route('/api/adm/users', methods=['GET'])
@require_adm
def adm_users():
    sb   = get_sb()
    rows = sb.table('users').select('id,name,email,verified,active,trial_end,plano,plano_end,created_at').order('created_at', desc=True).execute()
    result = []
    for u in rows.data:
        count = sb.table('despesas').select('id', count='exact').eq('user_id', u['id']).execute()
        u['despesas_count'] = count.count or 0
        u['plano_status']   = get_plano_status(u)['status']
        u['created']        = u.pop('created_at', '')
        result.append(u)
    return jsonify(result)

@app.route('/api/adm/users/<uid>', methods=['DELETE'])
@require_adm
def adm_delete_user(uid):
    sb = get_sb()
    rows = sb.table('despesas').select('photo_path').eq('user_id', uid).execute()
    paths = [r['photo_path'] for r in rows.data if r.get('photo_path')]
    if paths:
        try: sb.storage.from_('recibos').remove(paths)
        except: pass
    sb.table('despesas').delete().eq('user_id', uid).execute()
    sb.table('categorias').delete().eq('user_id', uid).execute()
    sb.table('users').delete().eq('id', uid).execute()
    return jsonify({'ok': True})

@app.route('/api/adm/users/<uid>/toggle', methods=['POST'])
@require_adm
def adm_toggle_user(uid):
    sb  = get_sb()
    res = sb.table('users').select('active').eq('id', uid).execute()
    if not res.data: return jsonify({'error': 'Não encontrado'}), 404
    new = not res.data[0].get('active', True)
    sb.table('users').update({'active': new}).eq('id', uid).execute()
    return jsonify({'ok': True, 'active': new})

@app.route('/api/adm/users/<uid>/reset-senha', methods=['POST'])
@require_adm
def adm_reset_senha(uid):
    d      = request.get_json()
    new_pw = d.get('password','').strip()
    if len(new_pw) < 6: return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    sb = get_sb()
    sb.table('users').update({'password': hash_password(new_pw)}).eq('id', uid).execute()
    return jsonify({'ok': True})

@app.route('/api/adm/users/<uid>/plano', methods=['POST'])
@require_adm
def adm_set_plano(uid):
    d     = request.get_json()
    plano = d.get('plano')
    dias  = int(d.get('dias', 365))
    sb    = get_sb()
    if plano and plano in PLANOS:
        plano_end = (datetime.utcnow() + timedelta(days=dias)).isoformat()
        sb.table('users').update({'plano': plano, 'plano_end': plano_end}).eq('id', uid).execute()
    else:
        sb.table('users').update({'plano': None, 'plano_end': None}).eq('id', uid).execute()
    return jsonify({'ok': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

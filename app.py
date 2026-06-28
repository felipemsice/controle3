import os, hashlib, base64, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g, Response
import jwt
from twilio.rest import Client
import mercadopago
from supabase import create_client, Client as SupabaseClient

app = Flask(__name__, static_folder='static')

# ── CONFIG ───────────────────────────────────────────────
SECRET_KEY      = os.environ.get('SECRET_KEY', 'dev-secret')
TWILIO_SID      = os.environ.get('TWILIO_SID', '')
TWILIO_TOKEN    = os.environ.get('TWILIO_TOKEN', '')
TWILIO_VERIFY   = os.environ.get('TWILIO_VERIFY', '')
ADM_PHONE       = os.environ.get('ADM_PHONE', '')
ADM_PASSWORD    = os.environ.get('ADM_PASSWORD', 'Admin@2025!')
MP_ACCESS_TOKEN = os.environ.get('MP_ACCESS_TOKEN', '')
APP_URL         = os.environ.get('APP_URL', 'https://controle3.onrender.com')
SUPABASE_URL    = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY    = os.environ.get('SUPABASE_KEY', '')  # service_role key

PLANOS = {
    'basico':   {'nome': 'Básico',   'limite': 100,  'preco': 49.00},
    'standard': {'nome': 'Standard', 'limite': 200,  'preco': 60.00},
    'premium':  {'nome': 'Premium',  'limite': 500,  'preco': 100.00},
}

# ── SUPABASE CLIENT ──────────────────────────────────────
def get_sb() -> SupabaseClient:
    return create_client(SUPABASE_URL, SUPABASE_KEY)

# ── HELPERS ──────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def fmt_phone(phone):
    phone = phone.strip().replace(' ','').replace('-','').replace('(','').replace(')','')
    if not phone.startswith('+'): phone = '+55' + phone.lstrip('0')
    return phone

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

def make_token(user_id, role='user'):
    payload = {'sub': user_id, 'role': role, 'exp': datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def get_plano_status(user):
    now = datetime.utcnow().isoformat()
    if str(user.get('phone','')) == ADM_PHONE:
        return {'status': 'adm', 'pode_adicionar': True, 'limite': 9999, 'uso_mes': 0}
    plano     = user.get('plano')
    plano_end = user.get('plano_end')
    if plano and plano_end and now < plano_end:
        dias = (datetime.fromisoformat(plano_end) - datetime.utcnow()).days
        return {'status': 'ativo', 'plano': plano, 'pode_adicionar': True,
                'limite': PLANOS[plano]['limite'], 'plano_end': plano_end,
                'plano_dias': dias, 'nome': PLANOS[plano]['nome']}
    trial_end = user.get('trial_end')
    if trial_end and now < trial_end:
        dias = (datetime.fromisoformat(trial_end) - datetime.utcnow()).days
        return {'status': 'trial', 'pode_adicionar': True, 'limite': 9999,
                'uso_mes': 0, 'trial_dias': dias}
    return {'status': 'expirado', 'pode_adicionar': False, 'limite': 0, 'uso_mes': 0}

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
    phone = fmt_phone(d.get('phone',''))
    pw    = d.get('password','')
    if not name or not phone or not pw:
        return jsonify({'error': 'Preencha todos os campos'}), 400
    if len(pw) < 6:
        return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    sb = get_sb()
    existing = sb.table('users').select('id').eq('phone', phone).execute()
    if existing.data:
        return jsonify({'error': 'Telefone já cadastrado'}), 409
    trial_end = (datetime.utcnow() + timedelta(days=30)).isoformat()
    res = sb.table('users').insert({
        'name': name, 'phone': phone,
        'password': hash_password(pw),
        'trial_end': trial_end, 'verified': True, 'active': True
    }).execute()
    user = res.data[0]
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/verify', methods=['POST'])
def verify_phone():
    d     = request.get_json()
    phone = fmt_phone(d.get('phone',''))
    sb    = get_sb()
    sb.table('users').update({'verified': True}).eq('phone', phone).execute()
    user = sb.table('users').select('*').eq('phone', phone).execute().data
    if not user: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = user[0]
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/login', methods=['POST'])
def login():
    d     = request.get_json()
    phone = fmt_phone(d.get('phone',''))
    pw    = d.get('password','')
    sb    = get_sb()
    res   = sb.table('users').select('*').eq('phone', phone).execute()
    if not res.data: return jsonify({'error': 'Telefone ou senha incorretos'}), 401
    user = res.data[0]
    if user['password'] != hash_password(pw):
        return jsonify({'error': 'Telefone ou senha incorretos'}), 401
    if not user.get('active', True):
        return jsonify({'error': 'Conta desativada'}), 403
    return jsonify({'ok': True, 'token': make_token(user['id']), 'name': user['name']})

@app.route('/api/auth/forgot', methods=['POST'])
def forgot():
    return jsonify({'ok': True, 'message': 'Entre em contato com o administrador.'})

@app.route('/api/auth/reset', methods=['POST'])
def reset_password():
    d      = request.get_json()
    phone  = fmt_phone(d.get('phone',''))
    new_pw = d.get('password','')
    if len(new_pw) < 6: return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    sb = get_sb()
    sb.table('users').update({'password': hash_password(new_pw)}).eq('phone', phone).execute()
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
    sb = get_sb()
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
    if ps['status'] == 'ativo':
        uso = count_mes_atual(g.user_id)
        if uso >= ps['limite']:
            return jsonify({'error': 'limite_atingido', 'uso': uso, 'limite': ps['limite']}), 403
    d   = request.get_json()
    ins = sb.table('despesas').insert({
        'user_id': g.user_id,
        'cat': d['cat'], 'val': d['val'],
        'date': d.get('date'), 'time': d.get('time'), 'ts': d.get('ts')
    }).execute()
    return jsonify({'ok': True, 'id': ins.data[0]['id']})

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

# ── FOTOS (Supabase Storage) ──────────────────────────────
@app.route('/api/photo', methods=['POST'])
@require_auth
def upload_photo():
    d       = request.get_json()
    eid     = d.get('id')
    img_b64 = d.get('image','')
    sb      = get_sb()
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
    if d.get('phone','').strip() == ADM_PHONE and d.get('password') == ADM_PASSWORD:
        return jsonify({'ok': True, 'token': make_token('adm', role='adm')})
    return jsonify({'error': 'Credenciais incorretas'}), 401

@app.route('/api/adm/users', methods=['GET'])
@require_adm
def adm_users():
    sb   = get_sb()
    rows = sb.table('users').select('id,name,phone,verified,active,trial_end,plano,plano_end,created_at').order('created_at', desc=True).execute()
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

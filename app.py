import os, hashlib, hmac, base64, json, secrets, string, sys
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g, Response
import jwt
import bcrypt
import mercadopago
import requests as http_requests
from supabase import create_client, Client as SupabaseClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, static_folder='static')

# Rate limiter — protege endpoints sensíveis contra força bruta.
# storage_uri padrão é in-memory (por processo). Para múltiplos workers
# do Gunicorn, configure REDIS_URL para um limite compartilhado real.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ.get('REDIS_URL', 'memory://'),
    default_limits=[],
)

# ── CONFIG ───────────────────────────────────────────────
SECRET_KEY      = os.environ.get('SECRET_KEY')
ADM_EMAIL       = os.environ.get('ADM_EMAIL', 'felipep_s@yahoo.com.br')
ADM_PASSWORD    = os.environ.get('ADM_PASSWORD', 'Admin@2025!')
MP_ACCESS_TOKEN = os.environ.get('MP_ACCESS_TOKEN', '')
# Chave secreta do webhook do Mercado Pago (Painel MP → Webhooks → "Assinatura secreta").
# Usada para validar o header x-signature das notificações.
MP_WEBHOOK_SECRET = os.environ.get('MP_WEBHOOK_SECRET', '')
APP_URL         = os.environ.get('APP_URL', 'https://controle3.onrender.com')
SUPABASE_URL    = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY    = os.environ.get('SUPABASE_KEY', '')
RESEND_API_KEY  = os.environ.get('RESEND_API_KEY', '')
EMAIL_FROM      = os.environ.get('EMAIL_FROM', 'noreply@nexapi.com.br')

# Aborta o boot se a SECRET_KEY não estiver configurada — sem ela, qualquer
# um poderia forjar tokens JWT. Nunca cair em um valor default em produção.
if not SECRET_KEY:
    sys.stderr.write(
        '\n[FATAL] SECRET_KEY não definida. Configure a variável de ambiente '
        'SECRET_KEY (Render → Settings → Environment) antes de iniciar.\n\n'
    )
    sys.exit(1)

PLANOS = {
    'basico': {
        'nome': 'Básico', 'limite': 999999, 'preco': 39.90, 'periodo': 'anual',
        'fotos': False, 'relatorios': False, 'categorias_custom': False,
        'descricao': 'Lançamentos ilimitados — plano anual'
    },
    'standard': {
        'nome': 'Standard', 'limite': 999999, 'preco': 69.90, 'periodo': 'anual',
        'fotos': True, 'relatorios': True, 'categorias_custom': False,
        'descricao': 'Ilimitado + fotos de comprovante e relatórios — plano anual'
    },
    'premium': {
        'nome': 'Premium', 'limite': 999999, 'preco': 119.90, 'periodo': 'anual',
        'fotos': True, 'relatorios': True, 'categorias_custom': True,
        'descricao': 'Tudo incluso + categorias personalizadas — plano anual'
    },
}
# Tolerância na comparação de valores (centavos) para evitar rejeição por
# arredondamento de ponto flutuante ao validar o pagamento no webhook.
PRECO_TOLERANCIA = 0.02

# ── SUPABASE CLIENT ──────────────────────────────────────
def get_sb() -> SupabaseClient:
    return create_client(SUPABASE_URL, SUPABASE_KEY)

# ── HELPERS ──────────────────────────────────────────────
def hash_password(pw):
    """Gera hash bcrypt (novo padrão). Usado em cadastros e trocas de senha."""
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def _hash_sha256_legacy(pw):
    """Hash antigo (SHA-256 puro). Mantido apenas para reconhecer senhas
    criadas antes da migração para bcrypt — nunca usar para novos hashes."""
    return hashlib.sha256(pw.encode()).hexdigest()

def verify_password(pw, stored_hash):
    """Confere a senha contra o hash salvo, aceitando os dois formatos.

    Retorna (ok, novo_hash):
      - ok=True/False conforme a senha bate.
      - novo_hash: se a senha for válida MAS estiver no formato antigo
        (SHA-256), devolve um hash bcrypt novo para o chamador regravar no
        banco. Isso migra a base de forma transparente, sem pedir troca de
        senha ao usuário. Em senhas já bcrypt, novo_hash é None.
    """
    if not stored_hash:
        return False, None
    # Hashes bcrypt começam com $2a$/$2b$/$2y$
    if stored_hash.startswith('$2'):
        try:
            ok = bcrypt.checkpw(pw.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            ok = False
        return ok, None
    # Caso contrário, trata como hash SHA-256 legado (comparação em tempo constante)
    ok = hmac.compare_digest(stored_hash, _hash_sha256_legacy(pw))
    return ok, (hash_password(pw) if ok else None)

MAX_TENTATIVAS_CODIGO = 5

def checar_codigo(sb, tabela, row, codigo):
    """Valida um código de 6 dígitos (2FA/reset) contando tentativas erradas.

    Após MAX_TENTATIVAS_CODIGO erros, o código é invalidado (zerado) e o usuário
    precisa solicitar um novo — isso fecha a janela de força bruta mesmo que o
    atacante rode várias tentativas dentro do limite de rate por IP.

    Retorna (ok: bool, erro: str|None). 'tabela' é 'users' ou 'admins'.
    """
    now = datetime.utcnow().isoformat()
    if not row.get('verify_code'):
        return False, 'Código expirado ou inexistente. Solicite um novo.'
    if row.get('verify_exp') and now > row['verify_exp']:
        return False, 'Código expirado. Solicite um novo.'
    if not hmac.compare_digest(str(row.get('verify_code')), str(codigo)):
        tentativas = (row.get('verify_attempts') or 0) + 1
        if tentativas >= MAX_TENTATIVAS_CODIGO:
            sb.table(tabela).update({'verify_code': None, 'verify_exp': None,
                                     'verify_attempts': 0}).eq('id', row['id']).execute()
            return False, 'Muitas tentativas. O código foi invalidado — solicite um novo.'
        sb.table(tabela).update({'verify_attempts': tentativas}).eq('id', row['id']).execute()
        restantes = MAX_TENTATIVAS_CODIGO - tentativas
        return False, f'Código incorreto. Tentativas restantes: {restantes}.'
    # Acertou: zera o contador (o chamador limpa o código ao concluir a ação).
    if row.get('verify_attempts'):
        sb.table(tabela).update({'verify_attempts': 0}).eq('id', row['id']).execute()
    return True, None

def make_token(user_id, role='user', session_id=None):
    payload = {'sub': user_id, 'role': role, 'exp': datetime.utcnow() + timedelta(days=30)}
    if session_id:
        payload['sid'] = session_id
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

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

def email_novo_usuario_adm(nome, email_usuario):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0a0f;color:#f0f0f0;border-radius:12px;padding:32px;border:1px solid rgba(0,212,255,.2)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px;font-weight:700;color:#00d4ff">π NexaPI</div>
        <div style="font-size:13px;color:#606070;margin-top:4px">Despesas Pessoais · Notificação ADM</div>
      </div>
      <div style="background:#14141e;border:1px solid rgba(0,212,255,.2);border-radius:10px;padding:20px;margin-bottom:20px">
        <div style="font-size:13px;color:#606070;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px">🆕 Novo usuário verificado</div>
        <div style="font-size:18px;font-weight:700;color:#fff;margin-bottom:6px">{nome}</div>
        <div style="font-size:14px;color:#00d4ff">{email_usuario}</div>
        <div style="font-size:12px;color:#606070;margin-top:8px">Verificação 2FA concluída em {datetime.utcnow().strftime('%d/%m/%Y às %H:%M')} UTC</div>
      </div>
      <div style="text-align:center">
        <a href="{APP_URL}/admin" style="display:inline-block;background:linear-gradient(135deg,#00d4ff,#0099bb);color:#000;font-size:14px;font-weight:700;padding:12px 28px;border-radius:8px;text-decoration:none">
          Ver no painel ADM
        </a>
      </div>
      <div style="border-top:1px solid rgba(255,255,255,.06);margin-top:24px;padding-top:16px;text-align:center">
        <a href="https://www.nexapi.com.br" style="color:#00d4ff;font-size:12px;text-decoration:none">www.nexapi.com.br</a>
      </div>
    </div>"""
    return send_email(ADM_EMAIL, f'🆕 Novo usuário: {nome} — Despesas Pessoais', html)

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

def email_troca_senha(to, nome, codigo):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0a0f;color:#f0f0f0;border-radius:12px;padding:32px;border:1px solid rgba(0,212,255,.2)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px;font-weight:700;color:#00d4ff">π NexaPI</div>
        <div style="font-size:13px;color:#606070;margin-top:4px">Despesas Pessoais</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#fff;margin-bottom:8px">Confirmar troca de senha</h2>
      <p style="color:#a0a0b0;font-size:14px;line-height:1.6;margin-bottom:24px">
        Olá {nome}, use o código abaixo para confirmar a alteração da sua senha:
      </p>
      <div style="background:#14141e;border:1px solid rgba(0,212,255,.3);border-radius:10px;padding:20px;text-align:center;margin-bottom:24px">
        <div style="font-size:36px;font-weight:700;color:#00d4ff;letter-spacing:10px">{codigo}</div>
        <div style="font-size:12px;color:#606070;margin-top:8px">Válido por 15 minutos</div>
      </div>
      <p style="color:#606070;font-size:12px;text-align:center">
        Se não solicitou essa troca, ignore este email e sua senha permanecerá a mesma.
      </p>
      <div style="border-top:1px solid rgba(255,255,255,.06);margin-top:24px;padding-top:16px;text-align:center">
        <a href="https://www.nexapi.com.br" style="color:#00d4ff;font-size:12px;text-decoration:none">www.nexapi.com.br</a>
      </div>
    </div>"""
    return send_email(to, 'Confirmar troca de senha — Despesas Pessoais', html)

def email_reset_senha_adm(to, nome, codigo):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0a0f;color:#f0f0f0;border-radius:12px;padding:32px;border:1px solid rgba(0,212,255,.2)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px;font-weight:700;color:#00d4ff">π NexaPI</div>
        <div style="font-size:13px;color:#606070;margin-top:4px">Painel ADM · Despesas Pessoais</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#fff;margin-bottom:8px">Redefinir senha do painel ADM</h2>
      <p style="color:#a0a0b0;font-size:14px;line-height:1.6;margin-bottom:24px">
        Olá {nome}, use o código abaixo para redefinir sua senha de acesso ao painel administrativo:
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
    return send_email(to, 'Redefinir senha — Painel ADM', html)

def email_novo_adm(to, nome, senha_temp):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0a0f;color:#f0f0f0;border-radius:12px;padding:32px;border:1px solid rgba(0,212,255,.2)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px;font-weight:700;color:#00d4ff">π NexaPI</div>
        <div style="font-size:13px;color:#606070;margin-top:4px">Painel ADM · Despesas Pessoais</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#fff;margin-bottom:8px">Acesso ao painel administrativo</h2>
      <p style="color:#a0a0b0;font-size:14px;line-height:1.6;margin-bottom:24px">
        Olá {nome}, uma conta de administrador foi criada para você em <strong>{to}</strong>. Use a senha abaixo para o primeiro acesso e altere-a em seguida:
      </p>
      <div style="background:#14141e;border:1px solid rgba(0,212,255,.3);border-radius:10px;padding:20px;text-align:center;margin-bottom:24px">
        <div style="font-size:22px;font-weight:700;color:#00d4ff">{senha_temp}</div>
      </div>
      <p style="color:#606070;font-size:12px;text-align:center">
        Acesse em <a href="https://despesas.nexapi.com.br/admin" style="color:#00d4ff">despesas.nexapi.com.br/admin</a>
      </p>
    </div>"""
    return send_email(to, 'Acesso criado — Painel ADM', html)

def email_exclusao_conta(to, nome, codigo):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0a0f;color:#f0f0f0;border-radius:12px;padding:32px;border:1px solid rgba(255,71,87,.3)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px;font-weight:700;color:#00d4ff">π NexaPI</div>
        <div style="font-size:13px;color:#606070;margin-top:4px">Despesas Pessoais</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#ff4757;margin-bottom:8px">⚠️ Confirmar exclusão de conta</h2>
      <p style="color:#a0a0b0;font-size:14px;line-height:1.6;margin-bottom:24px">
        Olá {nome}, recebemos uma solicitação para <strong style="color:#ff4757">excluir permanentemente</strong> sua conta e todos os seus dados. Use o código abaixo para confirmar:
      </p>
      <div style="background:#14141e;border:1px solid rgba(255,71,87,.4);border-radius:10px;padding:20px;text-align:center;margin-bottom:24px">
        <div style="font-size:36px;font-weight:700;color:#ff4757;letter-spacing:10px">{codigo}</div>
        <div style="font-size:12px;color:#606070;margin-top:8px">Válido por 15 minutos</div>
      </div>
      <p style="color:#606070;font-size:12px;text-align:center">
        Essa ação não pode ser desfeita. Se não foi você, ignore este email — sua conta não será afetada.
      </p>
      <div style="border-top:1px solid rgba(255,255,255,.06);margin-top:24px;padding-top:16px;text-align:center">
        <a href="https://www.nexapi.com.br" style="color:#00d4ff;font-size:12px;text-decoration:none">www.nexapi.com.br</a>
      </div>
    </div>"""
    return send_email(to, '⚠️ Confirmar exclusão de conta — Despesas Pessoais', html)

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
            # Validar sessão única: o session_id do token precisa bater exatamente
            # com o que está salvo no banco. Se o usuário logar em outro lugar,
            # o banco é atualizado e este token (antigo) deixa de ser válido.
            # Tokens sem 'sid' (emitidos antes desta feature) também são invalidados,
            # forçando um único login limpo.
            token_sid = payload.get('sid')
            sb  = get_sb()
            res = sb.table('users').select('session_id').eq('id', g.user_id).execute()
            current_sid = res.data[0].get('session_id') if res.data else None
            if current_sid and token_sid != current_sid:
                return jsonify({'error': 'sessao_encerrada', 'message': 'Sua sessão foi encerrada porque sua conta foi acessada em outro dispositivo.'}), 401
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

@app.route('/termos')
def termos_page():
    return send_from_directory('static/termos', 'index.html')

@app.route('/privacidade')
def privacidade_page():
    return send_from_directory('static/privacidade', 'index.html')

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
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
        sb.table('users').update({'verify_code': codigo, 'verify_exp': exp, 'verify_attempts': 0, 'name': name}).eq('id', user['id']).execute()
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
@limiter.limit("8 per minute; 30 per hour")
def verify_email():
    d      = request.get_json()
    email  = d.get('email','').strip().lower()
    codigo = d.get('code','').strip()
    sb     = get_sb()
    res    = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error': 'Email não encontrado'}), 404
    user = res.data[0]
    ok, erro = checar_codigo(sb, 'users', user, codigo)
    if not ok:
        return jsonify({'error': erro}), 400
    new_session_id = secrets.token_hex(16)
    sb.table('users').update({'verified': True, 'verify_code': None, 'verify_exp': None, 'verify_attempts': 0, 'session_id': new_session_id}).eq('id', user['id']).execute()
    # Notificar ADM
    try: email_novo_usuario_adm(user['name'], user['email'])
    except: pass
    return jsonify({'ok': True, 'token': make_token(user['id'], session_id=new_session_id), 'name': user['name']})

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute; 50 per hour")
def login():
    d     = request.get_json()
    email = d.get('email','').strip().lower()
    pw    = d.get('password','')
    sb    = get_sb()
    res   = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error': 'Email ou senha incorretos'}), 401
    user = res.data[0]
    ok, novo_hash = verify_password(pw, user['password'])
    if not ok:
        return jsonify({'error': 'Email ou senha incorretos'}), 401
    # Migração transparente: se a senha estava em SHA-256, regrava em bcrypt.
    if novo_hash:
        try: sb.table('users').update({'password': novo_hash}).eq('id', user['id']).execute()
        except Exception as e: print(f"Falha ao migrar hash: {e}")
    if not user.get('verified'):
        codigo = gerar_codigo()
        exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        sb.table('users').update({'verify_code': codigo, 'verify_exp': exp, 'verify_attempts': 0}).eq('id', user['id']).execute()
        email_verificacao(email, user['name'], codigo)
        return jsonify({'error': 'Verifique seu email', 'unverified': True, 'email': email}), 403
    if not user.get('active', True):
        return jsonify({'error': 'Conta desativada'}), 403
    # Gerar novo session_id: invalida automaticamente qualquer sessão anterior
    new_session_id = secrets.token_hex(16)
    sb.table('users').update({'session_id': new_session_id}).eq('id', user['id']).execute()
    return jsonify({'ok': True, 'token': make_token(user['id'], session_id=new_session_id), 'name': user['name']})

@app.route('/api/auth/forgot', methods=['POST'])
@limiter.limit("5 per minute; 15 per hour")
def forgot():
    d     = request.get_json()
    email = d.get('email','').strip().lower()
    sb    = get_sb()
    res   = sb.table('users').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'ok': True})
    user   = res.data[0]
    codigo = gerar_codigo()
    exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    sb.table('users').update({'verify_code': codigo, 'verify_exp': exp, 'verify_attempts': 0}).eq('id', user['id']).execute()
    email_reset_senha(email, user['name'], codigo)
    return jsonify({'ok': True})

@app.route('/api/auth/reset', methods=['POST'])
@limiter.limit("8 per minute; 30 per hour")
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
    ok, erro = checar_codigo(sb, 'users', user, codigo)
    if not ok:
        return jsonify({'error': erro}), 400
    sb.table('users').update({
        'password': hash_password(new_pw),
        'verify_code': None, 'verify_exp': None, 'verify_attempts': 0
    }).eq('id', user['id']).execute()
    return jsonify({'ok': True})

# ── PERFIL ───────────────────────────────────────────────
@app.route('/api/perfil', methods=['GET'])
@require_auth
def get_perfil():
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    ps   = get_plano_status(user)
    return jsonify({
        'name': user['name'],
        'email': user.get('email'),
        'active': user.get('active', True),
        'verified': user.get('verified', False),
        'created': user.get('created_at'),
        'termos_aceite_em': user.get('termos_aceite_em'),
        'status': ps
    })

@app.route('/api/perfil/trocar-senha/solicitar', methods=['POST'])
@require_auth
def solicitar_troca_senha():
    """Envia código 2FA por email para confirmar troca de senha"""
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    if not user.get('email'): return jsonify({'error': 'Conta sem email cadastrado'}), 400
    codigo = gerar_codigo()
    exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    sb.table('users').update({'verify_code': codigo, 'verify_exp': exp}).eq('id', g.user_id).execute()
    email_troca_senha(user['email'], user['name'], codigo)
    return jsonify({'ok': True, 'email': user['email']})

@app.route('/api/perfil/trocar-senha/confirmar', methods=['POST'])
@require_auth
def confirmar_troca_senha():
    d         = request.get_json()
    codigo    = d.get('code','').strip()
    nova_pw   = d.get('password','')
    if len(nova_pw) < 6: return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    sb  = get_sb()
    res = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    now  = datetime.utcnow().isoformat()
    if user.get('verify_code') != codigo:
        return jsonify({'error': 'Código incorreto'}), 400
    if user.get('verify_exp') and now > user['verify_exp']:
        return jsonify({'error': 'Código expirado. Solicite novamente.'}), 400
    sb.table('users').update({
        'password': hash_password(nova_pw),
        'verify_code': None, 'verify_exp': None
    }).eq('id', g.user_id).execute()
    return jsonify({'ok': True})

@app.route('/api/perfil/excluir/solicitar', methods=['POST'])
@require_auth
def solicitar_exclusao():
    """Envia código 2FA por email para confirmar exclusão de conta"""
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    if not user.get('email'): return jsonify({'error': 'Conta sem email cadastrado'}), 400
    codigo = gerar_codigo()
    exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    sb.table('users').update({'verify_code': codigo, 'verify_exp': exp}).eq('id', g.user_id).execute()
    email_exclusao_conta(user['email'], user['name'], codigo)
    return jsonify({'ok': True, 'email': user['email']})

@app.route('/api/perfil/excluir/confirmar', methods=['POST'])
@require_auth
def confirmar_exclusao():
    d      = request.get_json()
    codigo = d.get('code','').strip()
    sb     = get_sb()
    res    = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    now  = datetime.utcnow().isoformat()
    if user.get('verify_code') != codigo:
        return jsonify({'error': 'Código incorreto'}), 400
    if user.get('verify_exp') and now > user['verify_exp']:
        return jsonify({'error': 'Código expirado. Solicite novamente.'}), 400
    # Apagar fotos do storage
    try:
        rows = sb.table('despesas').select('photo_path').eq('user_id', g.user_id).execute()
        paths = [r['photo_path'] for r in rows.data if r.get('photo_path')]
        if paths: sb.storage.from_('recibos').remove(paths)
    except: pass
    # Apagar todos os dados do usuário
    sb.table('despesas').delete().eq('user_id', g.user_id).execute()
    sb.table('receitas').delete().eq('user_id', g.user_id).execute()
    sb.table('categorias').delete().eq('user_id', g.user_id).execute()
    sb.table('metas').delete().eq('user_id', g.user_id).execute()
    sb.table('recorrentes').delete().eq('user_id', g.user_id).execute()
    sb.table('parcelamentos').delete().eq('user_id', g.user_id).execute()
    sb.table('pagamentos').delete().eq('user_id', g.user_id).execute()
    sb.table('users').delete().eq('id', g.user_id).execute()
    return jsonify({'ok': True})
@app.route('/api/aceitar-termos', methods=['POST'])
@require_auth
def aceitar_termos():
    sb  = get_sb()
    now = datetime.utcnow().isoformat()
    sb.table('users').update({'termos_aceite_em': now}).eq('id', g.user_id).execute()
    return jsonify({'ok': True, 'termos_aceite_em': now})

@app.route('/api/conta/status', methods=['GET'])
@require_auth
def conta_status():
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    ps   = get_plano_status(user)
    ps['termos_aceitos'] = bool(user.get('termos_aceite_em'))
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
    rows = sb.table('despesas').select('*').eq('user_id', g.user_id).is_('deleted_at', 'null').order('ts', desc=True).execute()
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
    """Soft delete: marca como excluído, mantém por 15 dias na lixeira"""
    sb  = get_sb()
    row = sb.table('despesas').select('*').eq('id', eid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    sb.table('despesas').update({'deleted_at': datetime.utcnow().isoformat()}).eq('id', eid).execute()
    return jsonify({'ok': True})

@app.route('/api/despesas/clear', methods=['POST'])
@require_auth
def clear_despesas():
    """Soft delete em massa de todas as despesas ativas"""
    sb  = get_sb()
    now = datetime.utcnow().isoformat()
    sb.table('despesas').update({'deleted_at': now}).eq('user_id', g.user_id).is_('deleted_at', 'null').execute()
    return jsonify({'ok': True})

# ── LIXEIRA ──────────────────────────────────────────────
@app.route('/api/lixeira', methods=['GET'])
@require_auth
def get_lixeira():
    sb     = get_sb()
    limite = (datetime.utcnow() - timedelta(days=15)).isoformat()
    # Purgar itens com mais de 15 dias automaticamente
    try:
        old_desp = sb.table('despesas').select('id,photo_path').eq('user_id', g.user_id).not_.is_('deleted_at','null').lt('deleted_at', limite).execute()
        for od in (old_desp.data or []):
            if od.get('photo_path'):
                try: sb.storage.from_('recibos').remove([od['photo_path']])
                except: pass
        if old_desp.data:
            ids = [od['id'] for od in old_desp.data]
            sb.table('despesas').delete().in_('id', ids).execute()
        sb.table('receitas').delete().eq('user_id', g.user_id).not_.is_('deleted_at','null').lt('deleted_at', limite).execute()
    except: pass

    despesas = sb.table('despesas').select('*').eq('user_id', g.user_id).not_.is_('deleted_at','null').order('deleted_at', desc=True).execute()
    receitas = sb.table('receitas').select('*').eq('user_id', g.user_id).not_.is_('deleted_at','null').order('deleted_at', desc=True).execute()

    result = []
    for e in (despesas.data or []):
        if e.get('photo_data'):
            e['photo_inline'] = 'data:image/jpeg;base64,' + e['photo_data']
        e.pop('photo_data', None)
        e['_tipo'] = 'despesa'
        result.append(e)
    for r in (receitas.data or []):
        r['_tipo'] = 'receita'
        result.append(r)
    result.sort(key=lambda x: x.get('deleted_at') or '', reverse=True)
    return jsonify(result)

@app.route('/api/lixeira/<tipo>/<int:item_id>/restaurar', methods=['POST'])
@require_auth
def restaurar_item(tipo, item_id):
    sb    = get_sb()
    table = 'despesas' if tipo == 'despesa' else 'receitas'
    row   = sb.table(table).select('id').eq('id', item_id).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    sb.table(table).update({'deleted_at': None}).eq('id', item_id).execute()
    return jsonify({'ok': True})

@app.route('/api/lixeira/<tipo>/<int:item_id>', methods=['DELETE'])
@require_auth
def excluir_definitivo(tipo, item_id):
    sb    = get_sb()
    table = 'despesas' if tipo == 'despesa' else 'receitas'
    row   = sb.table(table).select('*').eq('id', item_id).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    item = row.data[0]
    if tipo == 'despesa' and item.get('photo_path'):
        try: sb.storage.from_('recibos').remove([item['photo_path']])
        except: pass
    sb.table(table).delete().eq('id', item_id).execute()
    return jsonify({'ok': True})

@app.route('/api/lixeira/restaurar-tudo', methods=['POST'])
@require_auth
def restaurar_tudo():
    sb = get_sb()
    sb.table('despesas').update({'deleted_at': None}).eq('user_id', g.user_id).not_.is_('deleted_at','null').execute()
    sb.table('receitas').update({'deleted_at': None}).eq('user_id', g.user_id).not_.is_('deleted_at','null').execute()
    return jsonify({'ok': True})

@app.route('/api/lixeira/limpar-tudo', methods=['POST'])
@require_auth
def limpar_lixeira_tudo():
    sb = get_sb()
    despesas_del = sb.table('despesas').select('id,photo_path').eq('user_id', g.user_id).not_.is_('deleted_at','null').execute()
    for d in (despesas_del.data or []):
        if d.get('photo_path'):
            try: sb.storage.from_('recibos').remove([d['photo_path']])
            except: pass
    if despesas_del.data:
        ids = [d['id'] for d in despesas_del.data]
        sb.table('despesas').delete().in_('id', ids).execute()
    sb.table('receitas').delete().eq('user_id', g.user_id).not_.is_('deleted_at','null').execute()
    return jsonify({'ok': True})

# ── RECEITAS ─────────────────────────────────────────────
@app.route('/api/receitas', methods=['GET'])
@require_auth
def get_receitas():
    sb   = get_sb()
    rows = sb.table('receitas').select('*').eq('user_id', g.user_id).is_('deleted_at', 'null').order('ts', desc=True).execute()
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
    """Soft delete: marca como excluída, mantém por 15 dias na lixeira"""
    sb  = get_sb()
    row = sb.table('receitas').select('id').eq('id', rid).eq('user_id', g.user_id).execute()
    if not row.data: return jsonify({'error': 'Não encontrado'}), 404
    sb.table('receitas').update({'deleted_at': datetime.utcnow().isoformat()}).eq('id', rid).execute()
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
    d     = request.get_json()
    code  = d.get('code','').strip().upper()
    plano = d.get('plano','')
    sb    = get_sb()
    row   = sb.table('cupons').select('*').eq('code', code).eq('ativo', True).execute()
    if not row.data: return jsonify({'error': 'Cupom inválido ou expirado'}), 404
    cupom = row.data[0]
    if cupom.get('usos_max') and cupom.get('usos_atual', 0) >= cupom['usos_max']:
        return jsonify({'error': 'Cupom esgotado — todas as vagas foram utilizadas'}), 410
    # Verificar se cupom é válido para o plano
    planos_validos = cupom.get('planos') or []
    if planos_validos and plano and plano not in planos_validos:
        nomes = {'basico':'Básico','standard':'Standard','premium':'Premium'}
        nomes_validos = ', '.join([nomes.get(p,p) for p in planos_validos])
        return jsonify({'error': f'Cupom válido apenas para: {nomes_validos}'}), 400
    usos_restantes = None
    if cupom.get('usos_max'):
        usos_restantes = cupom['usos_max'] - cupom.get('usos_atual', 0)
    return jsonify({
        'ok': True,
        'desconto': cupom['desconto'],
        'tipo': cupom.get('tipo','pct'),
        'planos': planos_validos,
        'usos_restantes': usos_restantes
    })

@app.route('/api/cupom/aplicar', methods=['POST'])
@require_auth
def aplicar_cupom():
    """Registra o uso do cupom após pagamento aprovado"""
    d    = request.get_json()
    code = d.get('code','').strip().upper()
    sb   = get_sb()
    row  = sb.table('cupons').select('*').eq('code', code).execute()
    if not row.data: return jsonify({'ok': True})
    cupom = row.data[0]
    novos_usos = cupom.get('usos_atual', 0) + 1
    update = {'usos_atual': novos_usos}
    if cupom.get('usos_max') and novos_usos >= cupom['usos_max']:
        update['ativo'] = False
    sb.table('cupons').update(update).eq('code', code).execute()
    return jsonify({'ok': True})

@app.route('/api/adm/cupons', methods=['GET'])
@require_adm
def adm_get_cupons():
    sb   = get_sb()
    rows = sb.table('cupons').select('*').order('criado', desc=True).execute()
    return jsonify(rows.data or [])

@app.route('/api/adm/cupons', methods=['POST'])
@require_adm
def adm_create_cupom():
    d    = request.get_json()
    code = d.get('code','').strip().upper()
    if not code: return jsonify({'error': 'Código obrigatório'}), 400
    sb   = get_sb()
    existing = sb.table('cupons').select('id').eq('code', code).execute()
    if existing.data: return jsonify({'error': 'Código já existe'}), 409
    sb.table('cupons').insert({
        'code':       code,
        'desconto':   float(d.get('desconto', 10)),
        'tipo':       'pct',
        'planos':     d.get('planos', []),
        'usos_max':   int(d.get('usos_max')) if d.get('usos_max') else None,
        'usos_atual': 0,
        'ativo':      True
    }).execute()
    return jsonify({'ok': True})

@app.route('/api/adm/cupons/<code>', methods=['DELETE'])
@require_adm
def adm_delete_cupom(code):
    sb = get_sb()
    sb.table('cupons').delete().eq('code', code).execute()
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
def validar_assinatura_mp(req):
    """Valida o header x-signature das notificações do Mercado Pago (HMAC-SHA256).

    O MP monta o 'manifest' com o data.id (em minúsculas), o x-request-id e o
    timestamp ts extraído do próprio x-signature, e assina com a chave secreta
    do webhook. Se MP_WEBHOOK_SECRET não estiver configurada, retorna None
    (indefinido) — o chamador decide se aceita ou bloqueia.
    """
    if not MP_WEBHOOK_SECRET:
        return None
    sig = req.headers.get('x-signature', '')
    req_id = req.headers.get('x-request-id', '')
    ts = None; v1 = None
    for parte in sig.split(','):
        if '=' in parte:
            k, _, val = parte.strip().partition('=')
            if k == 'ts': ts = val
            elif k == 'v1': v1 = val
    data_id = (req.args.get('data.id') or req.args.get('id') or '')
    if not (ts and v1 and data_id):
        return False
    manifest = f"id:{data_id.lower()};request-id:{req_id};ts:{ts};"
    esperado = hmac.new(MP_WEBHOOK_SECRET.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(esperado, v1)

def preco_esperado(sb, plano, cupom_code):
    """Recalcula, no servidor, quanto o plano deveria custar considerando um
    cupom válido. Nunca confia em valor vindo do cliente."""
    base = PLANOS[plano]['preco']
    cupom_code = (cupom_code or '').strip().upper()
    if cupom_code:
        cr = sb.table('cupons').select('*').eq('code', cupom_code).eq('ativo', True).execute()
        if cr.data:
            c = cr.data[0]
            usos_ok = not c.get('usos_max') or c.get('usos_atual', 0) < c['usos_max']
            planos_ok = not c.get('planos') or not c['planos'] or plano in c['planos']
            if usos_ok and planos_ok:
                pct = float(c.get('desconto', 0))
                base = round(base * (1 - pct / 100), 2)
    return max(1.00, base)

def registrar_uso_cupom(sb, cupom_code):
    cupom_code = (cupom_code or '').strip().upper()
    if not cupom_code:
        return
    try:
        row = sb.table('cupons').select('*').eq('code', cupom_code).execute()
        if row.data:
            c = row.data[0]
            novos = c.get('usos_atual', 0) + 1
            upd = {'usos_atual': novos}
            if c.get('usos_max') and novos >= c['usos_max']:
                upd['ativo'] = False
            sb.table('cupons').update(upd).eq('code', cupom_code).execute()
    except Exception as e:
        print(f"Erro ao registrar cupom: {e}")

def liberar_plano_se_pago(payment_id):
    """ÚNICO ponto que concede plano pago. Consulta o pagamento na API do MP e
    só libera se: status == 'approved', metadata com user_id/plano válidos, e o
    valor efetivamente pago bate com o preço esperado (plano - cupom).
    Idempotente: se o pagamento já foi processado, não duplica nem reconcede.
    Retorna (ok: bool, motivo: str)."""
    try:
        pay = mp_sdk().payment().get(payment_id)['response']
    except Exception as e:
        return False, f'erro_consulta_mp: {e}'

    status = pay.get('status')
    if status != 'approved':
        return False, f'status_{status}'

    meta  = pay.get('metadata', {}) or {}
    uid   = meta.get('user_id')
    plano = meta.get('plano')
    cupom = meta.get('cupom')
    if not uid or plano not in PLANOS:
        return False, 'metadata_invalida'

    pago = float(pay.get('transaction_amount') or 0)
    sb   = get_sb()
    esperado = preco_esperado(sb, plano, cupom)
    if pago + PRECO_TOLERANCIA < esperado:
        return False, f'valor_insuficiente_pago_{pago}_esperado_{esperado}'

    # Idempotência: se este mp_id já foi marcado como aprovado, não reprocessa.
    ja = sb.table('pagamentos').select('id').eq('mp_id', str(payment_id)).eq('status', 'aprovado').execute()
    if ja.data:
        return True, 'ja_processado'

    plano_end = (datetime.utcnow() + timedelta(days=365)).isoformat()
    sb.table('users').update({'plano': plano, 'plano_end': plano_end, 'trial_end': None}).eq('id', uid).execute()
    sb.table('pagamentos').insert({'user_id': uid, 'mp_id': str(payment_id),
                                   'plano': plano, 'valor': pago, 'status': 'aprovado'}).execute()
    registrar_uso_cupom(sb, cupom)
    return True, 'aprovado'

@app.route('/api/pagamento/criar', methods=['POST'])
@require_auth
def criar_pagamento():
    d     = request.get_json()
    plano = d.get('plano')
    cupom_code = (d.get('cupom') or '').strip().upper()
    if plano not in PLANOS: return jsonify({'error': 'Plano inválido'}), 400
    sb   = get_sb()
    res  = sb.table('users').select('*').eq('id', g.user_id).execute()
    if not res.data: return jsonify({'error': 'Usuário não encontrado'}), 404
    user = res.data[0]
    sdk  = mp_sdk()
    p    = PLANOS[plano]
    preco_final = p['preco']
    desconto_info = ''

    # Aplicar cupom se informado
    if cupom_code:
        cupom_res = sb.table('cupons').select('*').eq('code', cupom_code).eq('ativo', True).execute()
        if cupom_res.data:
            cupom = cupom_res.data[0]
            usos_ok = not cupom.get('usos_max') or cupom.get('usos_atual', 0) < cupom['usos_max']
            planos_ok = not cupom.get('planos') or not cupom['planos'] or plano in cupom['planos']
            if usos_ok and planos_ok:
                pct = float(cupom.get('desconto', 0))
                preco_final = round(preco_final * (1 - pct / 100), 2)
                desconto_info = f' ({int(pct)}% OFF - Cupom {cupom_code})'

    # Garantir valor mínimo de R$ 1,00 (limite MP)
    preco_final = max(1.00, preco_final)

    title = f"Despesas Pessoais — Plano {p['nome']} (Anual){desconto_info}"
    pref_data = {
        'items': [{'title': title, 'quantity': 1, 'currency_id': 'BRL', 'unit_price': preco_final}],
        'payer': {'name': user['name']},
        'back_urls': {
            'success': f"{APP_URL}/assinar?status=sucesso&plano={plano}&cupom={cupom_code}",
            'failure': f"{APP_URL}/assinar?status=erro",
            'pending': f"{APP_URL}/assinar?status=pendente",
        },
        'auto_return': 'approved',
        'notification_url': f"{APP_URL}/api/pagamento/webhook",
        'metadata': {'user_id': str(g.user_id), 'plano': plano, 'cupom': cupom_code},
        'statement_descriptor': 'DESPESAS APP',
    }
    result = sdk.preference().create(pref_data)
    if result['status'] != 201: return jsonify({'error': 'Erro ao criar preferência'}), 500
    pref = result['response']
    sb.table('pagamentos').insert({'user_id': g.user_id, 'mp_id': pref['id'],
                                   'plano': plano, 'valor': preco_final, 'status': 'pendente'}).execute()
    return jsonify({'ok': True, 'init_point': pref['init_point'], 'preco_final': preco_final})

@app.route('/api/pagamento/webhook', methods=['POST'])
def webhook():
    # 1) Autenticidade: valida a assinatura HMAC do Mercado Pago.
    #    None = secret não configurada (registra aviso mas segue, pois a
    #    liberação ainda re-consulta o MP). False = assinatura inválida → 401.
    assinatura = validar_assinatura_mp(request)
    if assinatura is False:
        print("Webhook rejeitado: assinatura x-signature inválida")
        return '', 401
    if assinatura is None:
        print("AVISO: MP_WEBHOOK_SECRET não configurada — webhook sem validação de assinatura")

    data  = request.get_json(silent=True) or {}
    topic = data.get('type') or request.args.get('topic', '') or request.args.get('type', '')
    if topic == 'payment':
        payment_id = (data.get('data', {}) or {}).get('id') or request.args.get('data.id') or request.args.get('id')
        if payment_id:
            ok, motivo = liberar_plano_se_pago(payment_id)
            print(f"Webhook payment {payment_id}: ok={ok} motivo={motivo}")
    # Sempre 200 para o MP não reenviar em loop (erros ficam no log).
    return '', 200

@app.route('/api/pagamento/confirmar', methods=['POST'])
@require_auth
def confirmar_pagamento():
    """Endpoint de RETORNO do checkout — apenas CONSULTA o estado do pagamento
    e do plano do usuário. NÃO concede plano (isso é exclusivo do webhook, que
    valida assinatura e valor). Existe para o front dar feedback imediato ao
    usuário enquanto o webhook processa de forma assíncrona."""
    d          = request.get_json() or {}
    payment_id = d.get('payment_id')
    sb         = get_sb()

    # Se veio payment_id, tenta liberar já (mesma validação estrita do webhook),
    # cobrindo o caso em que o retorno chega antes da notificação assíncrona.
    if payment_id:
        ok, motivo = liberar_plano_se_pago(payment_id)
        print(f"Confirmar payment {payment_id}: ok={ok} motivo={motivo}")

    # Reporta o plano atual do usuário (fonte da verdade = banco).
    res  = sb.table('users').select('plano, plano_end').eq('id', g.user_id).execute()
    user = res.data[0] if res.data else {}
    plano_atual = user.get('plano')
    if plano_atual:
        return jsonify({'ok': True, 'plano': plano_atual, 'plano_end': user.get('plano_end')})
    return jsonify({'ok': False, 'pendente': True,
                    'message': 'Pagamento em processamento. Seu plano será ativado assim que confirmado.'})

# ── ADM ──────────────────────────────────────────────────
def bootstrap_admin_principal(sb):
    """Garante que o admin principal (env ADM_EMAIL) sempre existe na tabela admins."""
    existing = sb.table('admins').select('id').eq('email', ADM_EMAIL).execute()
    if not existing.data:
        sb.table('admins').insert({
            'name': 'Administrador', 'email': ADM_EMAIL,
            'password': hash_password(ADM_PASSWORD), 'is_primary': True
        }).execute()

@app.route('/api/adm/login', methods=['POST'])
@limiter.limit("10 per minute; 50 per hour")
def adm_login():
    d     = request.get_json()
    email = d.get('email','').strip().lower()
    pw    = d.get('password','')
    sb    = get_sb()
    bootstrap_admin_principal(sb)
    res = sb.table('admins').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error': 'Credenciais incorretas'}), 401
    admin = res.data[0]
    ok, novo_hash = verify_password(pw, admin['password'])
    if not ok:
        return jsonify({'error': 'Credenciais incorretas'}), 401
    if novo_hash:
        try: sb.table('admins').update({'password': novo_hash}).eq('id', admin['id']).execute()
        except Exception as e: print(f"Falha ao migrar hash adm: {e}")
    return jsonify({'ok': True, 'token': make_token(admin['id'], role='adm'), 'id': admin['id'], 'name': admin['name'], 'is_primary': admin.get('is_primary', False)})

@app.route('/api/adm/forgot', methods=['POST'])
@limiter.limit("5 per minute; 15 per hour")
def adm_forgot():
    email = request.get_json().get('email','').strip().lower()
    sb    = get_sb()
    bootstrap_admin_principal(sb)
    res = sb.table('admins').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'ok': True})  # não revela se o email existe
    admin  = res.data[0]
    codigo = gerar_codigo()
    exp    = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    sb.table('admins').update({'verify_code': codigo, 'verify_exp': exp, 'verify_attempts': 0}).eq('id', admin['id']).execute()
    email_reset_senha_adm(email, admin['name'], codigo)
    return jsonify({'ok': True})

@app.route('/api/adm/reset', methods=['POST'])
@limiter.limit("8 per minute; 30 per hour")
def adm_reset():
    d      = request.get_json()
    email  = d.get('email','').strip().lower()
    codigo = d.get('code','').strip()
    pw     = d.get('password','')
    if len(pw) < 6: return jsonify({'error': 'Senha mínimo 6 caracteres'}), 400
    sb  = get_sb()
    res = sb.table('admins').select('*').eq('email', email).execute()
    if not res.data: return jsonify({'error': 'Código incorreto'}), 400
    admin = res.data[0]
    ok, erro = checar_codigo(sb, 'admins', admin, codigo)
    if not ok:
        return jsonify({'error': erro}), 400
    sb.table('admins').update({
        'password': hash_password(pw), 'verify_code': None, 'verify_exp': None, 'verify_attempts': 0
    }).eq('id', admin['id']).execute()
    return jsonify({'ok': True})

@app.route('/api/adm/admins', methods=['GET'])
@require_adm
def adm_list_admins():
    sb  = get_sb()
    bootstrap_admin_principal(sb)
    res = sb.table('admins').select('id,name,email,is_primary,created_at').order('created_at').execute()
    return jsonify(res.data)

@app.route('/api/adm/admins', methods=['POST'])
@require_adm
def adm_create_admin():
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
    existing = sb.table('admins').select('id').eq('email', email).execute()
    if existing.data:
        return jsonify({'error': 'Já existe um admin com esse email'}), 409
    sb.table('admins').insert({
        'name': name, 'email': email,
        'password': hash_password(pw), 'is_primary': False
    }).execute()
    try: email_novo_adm(email, name, pw)
    except: pass
    return jsonify({'ok': True})

@app.route('/api/adm/admins/<aid>', methods=['DELETE'])
@require_adm
def adm_delete_admin(aid):
    sb  = get_sb()
    res = sb.table('admins').select('*').eq('id', aid).execute()
    if not res.data: return jsonify({'error': 'Admin não encontrado'}), 404
    alvo = res.data[0]
    if alvo.get('is_primary'):
        return jsonify({'error': 'O administrador principal não pode ser removido'}), 403
    if str(g.user_id) == str(aid):
        return jsonify({'error': 'Você não pode remover a si mesmo'}), 403
    sb.table('admins').delete().eq('id', aid).execute()
    return jsonify({'ok': True})

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
    try:
        rows = sb.table('despesas').select('photo_path').eq('user_id', uid).execute()
        paths = [r['photo_path'] for r in rows.data if r.get('photo_path')]
        if paths: sb.storage.from_('recibos').remove(paths)
    except Exception as e:
        print(f"Erro ao remover fotos (uid={uid}): {e}")
    try:
        sb.table('despesas').delete().eq('user_id', uid).execute()
        sb.table('receitas').delete().eq('user_id', uid).execute()
        sb.table('categorias').delete().eq('user_id', uid).execute()
        sb.table('metas').delete().eq('user_id', uid).execute()
        sb.table('recorrentes').delete().eq('user_id', uid).execute()
        sb.table('parcelamentos').delete().eq('user_id', uid).execute()
        sb.table('pagamentos').delete().eq('user_id', uid).execute()
        sb.table('users').delete().eq('id', uid).execute()
    except Exception as e:
        print(f"Erro ao excluir usuário (uid={uid}): {e}")
        return jsonify({'error': 'Falha ao excluir usuário. Verifique os logs.'}), 500
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

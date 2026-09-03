from __future__ import annotations
import datetime as dt
import hmac
import json
import os
import pathlib
import shutil
import secrets
import sqlite3
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import webview
except ImportError:
    webview = None

BASE = pathlib.Path(__file__).resolve().parent
DB = BASE / 'data' / 'estoque.db'
WWW = BASE / 'app'
ASSETS = BASE / 'assets'
STORES_JSON = BASE / 'data' / 'stores.json'
CONFIG = BASE / 'data' / 'settings.json'
BACKUPS = BASE / 'data' / 'backups'
PORT = 8876
ADMIN_EMAIL = 'teste@teste.local'
SESSIONS: dict[str, dict] = {}


def now_iso():
    return dt.datetime.now().isoformat(timespec='seconds')


def load_settings():
    defaults = {'admin_pin': '2580', 'session_ttl_minutes': 480}
    if CONFIG.exists():
        try:
            data = json.loads(CONFIG.read_text(encoding='utf-8'))
            defaults.update({k: data[k] for k in defaults if k in data})
        except Exception:
            pass
    return defaults

SETTINGS = load_settings()


def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=5000')
    return con


def q(sql, params=(), one=False):
    con = connect()
    try:
        rows = con.execute(sql, params).fetchall()
        return dict(rows[0]) if one and rows else None if one else [dict(r) for r in rows]
    finally:
        con.close()


def init_db():
    con = connect()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS categories(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        sort_order INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category_id INTEGER NOT NULL,
        model TEXT,
        details TEXT,
        notes TEXT,
        stock INTEGER NOT NULL DEFAULT 0,
        initial_stock INTEGER NOT NULL DEFAULT 0,
        min_stock INTEGER NOT NULL DEFAULT 0,
        unit TEXT NOT NULL DEFAULT 'UN',
        active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY(category_id) REFERENCES categories(id)
    );
    CREATE TABLE IF NOT EXISTS locations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE,
        name TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL DEFAULT 'LOCAL',
        active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS movements(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        item_id INTEGER NOT NULL,
        movement_type TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        origin TEXT,
        destination TEXT,
        reason TEXT NOT NULL,
        reference TEXT,
        reversed_at TEXT,
        reversed_by INTEGER,
        reversal_reason TEXT,
        updated_at TEXT,
        updated_by INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(item_id) REFERENCES items(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        user_id INTEGER,
        action TEXT NOT NULL,
        entity TEXT NOT NULL,
        entity_id INTEGER,
        details TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    cols = {r['name'] for r in con.execute('PRAGMA table_info(movements)').fetchall()}
    for col, ddl in [('reversed_at','TEXT'),('reversed_by','INTEGER'),('reversal_reason','TEXT'),('updated_at','TEXT'),('updated_by','INTEGER')]:
        if col not in cols:
            con.execute(f'ALTER TABLE movements ADD COLUMN {col} {ddl}')
    for table, col, ddl in [('categories','active','INTEGER NOT NULL DEFAULT 1'),('items','initial_stock','INTEGER NOT NULL DEFAULT 0'),('locations','code','TEXT'),('locations','active','INTEGER NOT NULL DEFAULT 1')]:
        cols2={r['name'] for r in con.execute(f'PRAGMA table_info({table})').fetchall()}
        if col not in cols2:
            con.execute(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}')
            if table=='items' and col=='initial_stock':
                con.execute('UPDATE items SET initial_stock=stock')
    con.execute('INSERT OR IGNORE INTO users(name,email,role,active) VALUES(?,?,?,1)', ('TESTE', ADMIN_EMAIL, 'Administrador'))
    con.execute('UPDATE users SET name="TESTE",role="Administrador",active=1 WHERE lower(email)=lower(?)', (ADMIN_EMAIL,))
    if STORES_JSON.exists():
        for s in json.loads(STORES_JSON.read_text(encoding='utf-8')):
            code=(s.get('code') or '').strip(); name=(s.get('name') or code).strip()
            if not code or not name: continue
            typ='Loja' if code.startswith(('TA','VN','ET','HT')) else 'Externo'
            con.execute('INSERT OR IGNORE INTO locations(code,name,type,active) VALUES(?,?,?,1)', (code,name,typ))
            con.execute('UPDATE locations SET name=?,type=?,active=1 WHERE code=?',(name,typ,code))
    con.execute('INSERT OR IGNORE INTO locations(code,name,type,active) VALUES(?,?,?,1)',('TI','Estoque TI','Central'))
    con.execute('INSERT OR IGNORE INTO locations(code,name,type,active) VALUES(?,?,?,1)',('MANUT','Manutenção','Interno'))
    con.commit(); con.close()


def get_user(user_id):
    return q('SELECT id,name,email,role,active FROM users WHERE id=? AND active=1', (int(user_id),), one=True)


def get_session(headers):
    auth=headers.get('Authorization','')
    if not auth.startswith('Bearer '): return None
    s=SESSIONS.get(auth[7:].strip())
    if not s: return None
    if time.time()-s['created'] > int(SETTINGS.get('session_ttl_minutes',480))*60:
        SESSIONS.pop(auth[7:].strip(),None); return None
    return s


def new_session(user, admin=False):
    token=secrets.token_urlsafe(32)
    SESSIONS[token]={'user':user,'created':time.time(),'admin':bool(admin)}
    return token


def require_session(handler):
    s=get_session(handler.headers)
    if not s:
        handler._send(401, {'ok':False,'error':'Sessão inválida.'}); return None
    return s


def require_admin(handler):
    s=get_session(handler.headers)
    if not s or s['user']['role'].lower()!='administrador' or not s.get('admin'):
        handler._send(403, {'ok':False,'error':'Acesso administrativo bloqueado.'}); return None
    return s


def audit(con, user_id, action, entity, entity_id, details):
    con.execute('INSERT INTO audit_log(created_at,user_id,action,entity,entity_id,details) VALUES(?,?,?,?,?,?)', (now_iso(),user_id,action,entity,entity_id,json.dumps(details,ensure_ascii=False)))


def signed_effect(t, qty):
    return qty if t=='ENTRADA' else -qty


def rebuild_stock(con):
    items=con.execute('SELECT id,initial_stock FROM items').fetchall()
    for item in items:
        total=item['initial_stock']
        rows=con.execute('SELECT movement_type,quantity FROM movements WHERE item_id=? AND reversed_at IS NULL ORDER BY id',(item['id'],)).fetchall()
        for m in rows: total += signed_effect(m['movement_type'],m['quantity'])
        con.execute('UPDATE items SET stock=? WHERE id=?',(total,item['id']))


class ApiHandler(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _send(self, code, obj):
        raw=json.dumps(obj,ensure_ascii=False).encode('utf-8')
        self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def _body(self):
        n=int(self.headers.get('Content-Length','0')); raw=self.rfile.read(n) or b'{}'; return json.loads(raw.decode('utf-8'))
    def _path(self): return urllib.parse.urlparse(self.path).path
    def _serve(self,fp):
        data=fp.read_bytes(); ctype={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.png':'image/png','.ico':'image/x-icon'}.get(fp.suffix.lower(),'application/octet-stream')
        self.send_response(200); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        p=self._path()
        try:
            if p=='/api/me':
                s=get_session(self.headers); self._send(200,{'authenticated':bool(s),'user':s['user'] if s else None,'admin':bool(s and s.get('admin'))}); return
            if p=='/api/operators':
                self._send(200,q('SELECT id,name,email,role,active FROM users WHERE active=1 ORDER BY name')); return
            if p=='/api/categories':
                self._send(200,q('''SELECT c.id,c.name,c.sort_order,c.active,COUNT(i.id) item_count,COALESCE(SUM(i.stock),0) stock FROM categories c LEFT JOIN items i ON i.category_id=c.id AND i.active=1 WHERE c.active=1 GROUP BY c.id ORDER BY c.sort_order,c.name''')); return
            if p=='/api/items':
                qs=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query); cid=qs.get('category',[''])[0]; search=qs.get('q',[''])[0].strip()
                sql='''SELECT i.id,i.category_id,i.name,i.model,i.details,i.notes,i.stock,i.initial_stock,i.min_stock,i.unit,c.name category,CASE WHEN i.stock<=i.min_stock AND i.min_stock>0 THEN 1 ELSE 0 END low FROM items i JOIN categories c ON c.id=i.category_id WHERE i.active=1'''; params=[]
                if cid: sql+=' AND i.category_id=?'; params.append(int(cid))
                if search: sql+=' AND (i.name LIKE ? OR COALESCE(i.model,\'\') LIKE ?)'; params += [f'%{search}%',f'%{search}%']
                sql+=' ORDER BY i.name'; self._send(200,q(sql,params)); return
            if p=='/api/locations':
                self._send(200,q('SELECT id,code,name,type,active FROM locations WHERE active=1 ORDER BY CASE type WHEN "Central" THEN 0 WHEN "Loja" THEN 1 ELSE 2 END,name')); return
            if p=='/api/history':
                self._send(200,q('''SELECT m.*,u.name user_name,u.email user_email,u.role user_role,i.name item_name,c.name category,ru.name reversed_by_name,uu.name updated_by_name FROM movements m JOIN users u ON u.id=m.user_id JOIN items i ON i.id=m.item_id JOIN categories c ON c.id=i.category_id LEFT JOIN users ru ON ru.id=m.reversed_by LEFT JOIN users uu ON uu.id=m.updated_by ORDER BY m.id DESC LIMIT 1000''')); return
            if p=='/api/dashboard':
                totals=q('SELECT COUNT(*) materials,COALESCE(SUM(stock),0) units,COALESCE(SUM(CASE WHEN stock<=min_stock AND min_stock>0 THEN 1 ELSE 0 END),0) critical FROM items WHERE active=1',one=True)
                recent=q('''SELECT m.id,m.created_at,m.movement_type,m.quantity,u.name user_name,i.name item_name,m.origin,m.destination,m.reason,m.reversed_at FROM movements m JOIN users u ON u.id=m.user_id JOIN items i ON i.id=m.item_id ORDER BY m.id DESC LIMIT 8''')
                cats=q('''SELECT c.id,c.name,COUNT(i.id) materials,COALESCE(SUM(i.stock),0) units FROM categories c LEFT JOIN items i ON i.category_id=c.id AND i.active=1 WHERE c.active=1 GROUP BY c.id ORDER BY c.sort_order,c.name''')
                self._send(200,{'totals':totals,'recent':recent,'categories':cats}); return
            if p=='/api/admin/snapshot':
                if not require_admin(self): return
                self._send(200,{'categories':q('SELECT * FROM categories ORDER BY sort_order,name'),'items':q('SELECT i.*,c.name category FROM items i JOIN categories c ON c.id=i.category_id ORDER BY c.name,i.name'),'locations':q('SELECT * FROM locations ORDER BY type,name'),'users':q('SELECT id,name,email,role,active FROM users ORDER BY name'),'movements':q('''SELECT m.*,u.name user_name,u.email user_email,i.name item_name,c.name category,ru.name reversed_by_name,uu.name updated_by_name FROM movements m JOIN users u ON u.id=m.user_id JOIN items i ON i.id=m.item_id JOIN categories c ON c.id=i.category_id LEFT JOIN users ru ON ru.id=m.reversed_by LEFT JOIN users uu ON uu.id=m.updated_by ORDER BY m.id DESC LIMIT 1000'''),'audit':q('''SELECT a.*,u.name user_name,u.email user_email FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500''')}); return
            if p=='/api/admin/recalculate':
                s=require_admin(self)
                if not s: return
                con=connect(); con.execute('BEGIN IMMEDIATE'); rebuild_stock(con); audit(con,s['user']['id'],'RECALCULAR_SALDO','items',None,{'scope':'all'}); con.commit(); con.close(); self._send(200,{'ok':True}); return
            if p=='/api/admin/database':
                if not require_admin(self): return
                BACKUPS.mkdir(parents=True, exist_ok=True)
                con=connect()
                try:
                    tables=[]
                    total=0
                    names=[r['name'] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()]
                    for name in names:
                        safe=name.replace('"','""')
                        count=con.execute(f'SELECT COUNT(*) c FROM "{safe}"').fetchone()['c']
                        tables.append({'name':name,'type':'tabela','rows':count}); total+=count
                finally: con.close()
                size=DB.stat().st_size if DB.exists() else 0
                if size<1024: human=f'{size} B'
                elif size<1024**2: human=f'{size/1024:.1f} KB'
                else: human=f'{size/1024**2:.1f} MB'
                self._send(200,{'ok':True,'path':str(DB),'size':size,'size_human':human,'modified_at':dt.datetime.fromtimestamp(DB.stat().st_mtime).isoformat(timespec='seconds') if DB.exists() else None,'tables':tables,'total_rows':total,'backups':sorted([x.name for x in BACKUPS.glob('estoque-*.db')],reverse=True)[:10]}); return
            if p=='/api/admin/users':
                if not require_admin(self): return
                self._send(200,q('SELECT id,name,email,role,active FROM users ORDER BY name')); return
            if p=='/api/admin/database/download':
                if not require_admin(self): return
                if not DB.exists(): raise ValueError('Banco de dados não encontrado.')
                raw=DB.read_bytes(); self.send_response(200); self.send_header('Content-Type','application/octet-stream'); self.send_header('Content-Disposition','attachment; filename="estoque.db"'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return
            if p.startswith('/assets/'):
                rel=p[len('/assets/'):].lstrip('/'); fp=(ASSETS/rel).resolve()
                if ASSETS.resolve() in fp.parents and fp.exists() and fp.is_file(): self._serve(fp); return
                self.send_error(404); return
            rel=p.lstrip('/') or 'index.html'; fp=(WWW/rel).resolve()
            if WWW.resolve() in fp.parents and fp.exists() and fp.is_file(): self._serve(fp); return
            self.send_error(404)
        except Exception as exc:
            self._send(500,{'ok':False,'error':str(exc)})
    def do_POST(self):
        p=self._path()
        try:
            body=self._body()
            if p=='/api/operator/select':
                user=get_user(body.get('user_id'))
                if not user: raise ValueError('Operador inválido.')
                is_admin=user['role'].lower()=='administrador'
                if is_admin:
                    pin=str(body.get('pin','')).strip()
                    expected=str(SETTINGS.get('admin_pin','')).strip()
                    if not expected or not hmac.compare_digest(pin,expected):
                        self._send(401,{'ok':False,'error':'PIN administrativo inválido.'}); return
                token=new_session(user,is_admin); self._send(200,{'ok':True,'token':token,'user':user,'admin':is_admin}); return
            session=require_session(self)
            if not session: return
            if p=='/api/admin/database/backup':
                session=require_admin(self)
                if not session: return
                BACKUPS.mkdir(parents=True, exist_ok=True)
                stamp=dt.datetime.now().strftime('%Y%m%d_%H%M%S')
                target=BACKUPS/f'estoque-{stamp}.db'
                con=connect(); con.execute('PRAGMA wal_checkpoint(FULL)'); con.close()
                shutil.copy2(DB,target)
                con=connect(); audit(con,session['user']['id'],'BACKUP','database',None,{'filename':target.name}); con.commit(); con.close()
                self._send(200,{'ok':True,'filename':target.name,'path':str(target)}); return
            if p=='/api/movements':
                item_id=int(body['item_id']); typ=str(body['movement_type']).upper(); qty=int(body['quantity']); reason=str(body.get('reason','')).strip(); origin=str(body.get('origin','')).strip(); destination=str(body.get('destination','')).strip(); ref=str(body.get('reference','')).strip()
                if typ not in {'ENTRADA','SAIDA','TRANSFERENCIA'}: raise ValueError('Operação inválida.')
                if qty<=0: raise ValueError('A quantidade deve ser maior que zero.')
                if not reason: raise ValueError('O motivo é obrigatório.')
                if typ in {'SAIDA','TRANSFERENCIA'} and not destination: raise ValueError('Selecione o destino.')
                con=connect(); con.execute('BEGIN IMMEDIATE'); item=con.execute('SELECT id,stock FROM items WHERE id=? AND active=1',(item_id,)).fetchone()
                if not item: raise ValueError('Material não encontrado.')
                if typ in {'SAIDA','TRANSFERENCIA'} and qty>item['stock']: raise ValueError(f'Saldo insuficiente. Disponível: {item["stock"]}.')
                cur=con.execute('''INSERT INTO movements(created_at,user_id,item_id,movement_type,quantity,origin,destination,reason,reference) VALUES(?,?,?,?,?,?,?,?,?)''',(now_iso(),session['user']['id'],item_id,typ,qty,origin,destination,reason,ref))
                con.execute('UPDATE items SET stock=stock+? WHERE id=?',(signed_effect(typ,qty),item_id)); new=con.execute('SELECT stock FROM items WHERE id=?',(item_id,)).fetchone()['stock']
                audit(con,session['user']['id'],'CRIAR','movement',cur.lastrowid,{'type':typ,'item_id':item_id,'quantity':qty,'origin':origin,'destination':destination,'reason':reason,'reference':ref}); con.commit(); con.close(); self._send(200,{'ok':True,'movement_id':cur.lastrowid,'stock':new}); return
            if p=='/api/movements/reverse':
                movement_id=int(body['id']); reason=str(body.get('reason','')).strip()
                if not reason: raise ValueError('Informe o motivo do estorno.')
                con=connect(); con.execute('BEGIN IMMEDIATE'); m=con.execute('SELECT * FROM movements WHERE id=?',(movement_id,)).fetchone()
                if not m: raise ValueError('Movimentação não encontrada.')
                if m['reversed_at']: raise ValueError('Esta movimentação já foi estornada.')
                delta=-signed_effect(m['movement_type'],m['quantity']); con.execute('UPDATE items SET stock=stock+? WHERE id=?',(delta,m['item_id']))
                con.execute('UPDATE movements SET reversed_at=?,reversed_by=?,reversal_reason=? WHERE id=?',(now_iso(),session['user']['id'],reason,movement_id)); audit(con,session['user']['id'],'ESTORNAR','movement',movement_id,{'reason':reason}); con.commit(); con.close(); self._send(200,{'ok':True}); return
            if p=='/api/admin/movement':
                session=require_admin(self)
                if not session: return
                movement_id=int(body['id']); reason=str(body.get('reason','')).strip(); destination=str(body.get('destination','')).strip(); origin=str(body.get('origin','')).strip(); reference=str(body.get('reference','')).strip()
                if not reason: raise ValueError('Motivo obrigatório.')
                con=connect(); con.execute('BEGIN IMMEDIATE'); m=con.execute('SELECT * FROM movements WHERE id=?',(movement_id,)).fetchone()
                if not m: raise ValueError('Movimentação não encontrada.')
                if m['reversed_at']: raise ValueError('Movimentação estornada não pode ser editada.')
                con.execute('UPDATE movements SET origin=?,destination=?,reason=?,reference=?,updated_at=?,updated_by=? WHERE id=? AND reversed_at IS NULL',(origin,destination,reason,reference,now_iso(),session['user']['id'],movement_id)); audit(con,session['user']['id'],'EDITAR','movement',movement_id,{'origin':origin,'destination':destination,'reason':reason,'reference':reference}); con.commit(); con.close(); self._send(200,{'ok':True}); return
            if p=='/api/admin/user':
                session=require_admin(self)
                if not session: return
                uid=body.get('id')
                name=str(body.get('name','')).strip(); email=str(body.get('email','')).strip().lower(); role=str(body.get('role','Operador')).strip() or 'Operador'
                if not name or not email: raise ValueError('Nome e e-mail são obrigatórios.')
                if '@' not in email: raise ValueError('Informe um e-mail válido.')
                if role not in {'Administrador','Supervisor','Operador'}: raise ValueError('Perfil inválido.')
                con=connect(); con.execute('BEGIN IMMEDIATE')
                try:
                    if uid:
                        uid=int(uid)
                        current=con.execute('SELECT id,email FROM users WHERE id=?',(uid,)).fetchone()
                        if not current: raise ValueError('Usuário não encontrado.')
                        if current['email'].lower()==ADMIN_EMAIL.lower() and email!=ADMIN_EMAIL.lower(): raise ValueError('O administrador principal não pode ter o e-mail alterado.')
                        con.execute('UPDATE users SET name=?,email=?,role=? WHERE id=?',(name,email,role,uid)); action='ATUALIZAR'
                    else:
                        cur=con.execute('INSERT INTO users(name,email,role,active) VALUES(?,?,?,1)',(name,email,role)); uid=cur.lastrowid; action='CRIAR'
                    audit(con,session['user']['id'],action,'user',uid,{'name':name,'email':email,'role':role}); con.commit()
                except Exception:
                    con.rollback(); raise
                finally: con.close()
                self._send(200,{'ok':True,'id':uid}); return
            if p=='/api/admin/user/toggle':
                session=require_admin(self)
                if not session: return
                uid=int(body['id']); active=1 if body.get('active') else 0
                con=connect(); con.execute('BEGIN IMMEDIATE'); u=con.execute('SELECT id,email FROM users WHERE id=?',(uid,)).fetchone()
                if not u: con.rollback(); con.close(); raise ValueError('Usuário não encontrado.')
                if u['email'].lower()==ADMIN_EMAIL.lower() and not active: con.rollback(); con.close(); raise ValueError('O administrador principal não pode ser desativado.')
                con.execute('UPDATE users SET active=? WHERE id=?',(active,uid)); audit(con,session['user']['id'],'ATIVAR' if active else 'DESATIVAR','user',uid,{'active':bool(active)}); con.commit(); con.close(); self._send(200,{'ok':True}); return
            if p=='/api/admin/item':
                session=require_admin(self)
                if not session: return
                ident=body.get('id'); name=str(body.get('name','')).strip(); cid=int(body['category_id']); stock=int(body.get('stock',0)); min_stock=int(body.get('min_stock',0)); unit=str(body.get('unit','UN')).strip() or 'UN'; model=str(body.get('model','')).strip(); notes=str(body.get('notes','')).strip(); details=str(body.get('details','')).strip()
                if not name or stock<0 or min_stock<0: raise ValueError('Dados do material inválidos.')
                con=connect(); con.execute('BEGIN IMMEDIATE')
                if ident:
                    old=con.execute('SELECT * FROM items WHERE id=?',(int(ident),)).fetchone()
                    if not old: raise ValueError('Material não encontrado.')
                    con.execute('UPDATE items SET name=?,category_id=?,model=?,details=?,notes=?,stock=?,initial_stock=initial_stock,min_stock=?,unit=? WHERE id=?',(name,cid,model,details,notes,stock,min_stock,unit,int(ident))); action='EDITAR'
                else:
                    cur=con.execute('INSERT INTO items(name,category_id,model,details,notes,stock,initial_stock,min_stock,unit,active) VALUES(?,?,?,?,?,?,?,?,?,1)',(name,cid,model,details,notes,stock,stock,min_stock,unit)); ident=cur.lastrowid; action='CRIAR'
                audit(con,session['user']['id'],action,'item',ident,{'name':name}); con.commit(); con.close(); self._send(200,{'ok':True,'id':ident}); return
            if p=='/api/admin/item/toggle':
                session=require_admin(self)
                if not session: return
                ident=int(body['id']); active=1 if body.get('active',True) else 0; con=connect(); con.execute('UPDATE items SET active=? WHERE id=?',(active,ident)); audit(con,session['user']['id'],'ATIVAR' if active else 'DESATIVAR','item',ident,{'active':active}); con.commit(); con.close(); self._send(200,{'ok':True}); return
            if p=='/api/admin/category':
                session=require_admin(self)
                if not session: return
                name=str(body.get('name','')).strip(); ident=body.get('id'); order=int(body.get('sort_order',0))
                if not name: raise ValueError('Nome obrigatório.')
                con=connect(); con.execute('BEGIN IMMEDIATE')
                if ident: con.execute('UPDATE categories SET name=?,sort_order=? WHERE id=?',(name,order,int(ident))); ident=int(ident); action='EDITAR'
                else: cur=con.execute('INSERT INTO categories(name,sort_order) VALUES(?,?)',(name,order)); ident=cur.lastrowid; action='CRIAR'
                audit(con,session['user']['id'],action,'category',ident,{'name':name,'sort_order':order}); con.commit(); con.close(); self._send(200,{'ok':True,'id':ident}); return
            if p=='/api/admin/location':
                session=require_admin(self)
                if not session: return
                name=str(body.get('name','')).strip(); code=str(body.get('code','')).strip() or None; typ=str(body.get('type','Loja')).strip(); ident=body.get('id')
                if not name: raise ValueError('Nome obrigatório.')
                con=connect(); con.execute('BEGIN IMMEDIATE')
                if ident: con.execute('UPDATE locations SET code=?,name=?,type=? WHERE id=?',(code,name,typ,int(ident))); ident=int(ident); action='EDITAR'
                else: cur=con.execute('INSERT INTO locations(code,name,type,active) VALUES(?,?,?,1)',(code,name,typ)); ident=cur.lastrowid; action='CRIAR'
                audit(con,session['user']['id'],action,'location',ident,{'code':code,'name':name,'type':typ}); con.commit(); con.close(); self._send(200,{'ok':True,'id':ident}); return
            if p=='/api/admin/location/toggle':
                session=require_admin(self)
                if not session: return
                ident=int(body['id']); active=1 if body.get('active',True) else 0; con=connect(); con.execute('UPDATE locations SET active=? WHERE id=?',(active,ident)); audit(con,session['user']['id'],'ATIVAR' if active else 'DESATIVAR','location',ident,{'active':active}); con.commit(); con.close(); self._send(200,{'ok':True}); return
            if p=='/api/admin/category/toggle':
                session=require_admin(self)
                if not session: return
                ident=int(body['id']); active=1 if body.get('active',True) else 0; con=connect(); con.execute('UPDATE categories SET active=? WHERE id=?',(active,ident)); audit(con,session['user']['id'],'ATIVAR' if active else 'DESATIVAR','category',ident,{'active':active}); con.commit(); con.close(); self._send(200,{'ok':True}); return
            self.send_error(404)
        except sqlite3.IntegrityError as exc:
            try: con.rollback(); con.close()
            except Exception: pass
            self._send(400,{'ok':False,'error':'Não foi possível gravar: registro duplicado ou relacionado.'})
        except Exception as exc:
            try: con.rollback(); con.close()
            except Exception: pass
            self._send(400,{'ok':False,'error':str(exc)})


def start_server():
    init_db(); srv=ThreadingHTTPServer(('127.0.0.1',PORT),ApiHandler); threading.Thread(target=srv.serve_forever,daemon=True).start(); return srv

if __name__=='__main__':
    srv=start_server(); url=f'http://127.0.0.1:{PORT}/index.html'
    if webview:
        webview.create_window('Estoque TI',url,width=1680,height=1040,min_size=(1220,760),text_select=True,resizable=True)
        webview.start(gui='edgechromium',debug=False)
    else:
        webbrowser.open(url)
        try: threading.Event().wait()
        except KeyboardInterrupt: srv.shutdown()

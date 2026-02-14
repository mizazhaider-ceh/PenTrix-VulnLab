"""
app.py — Main Flask application for The PenTrix Web App Pentesting Lab
═══════════════════════════════════════════════════════════════════════
A realistic corporate intranet portal that is INTENTIONALLY VULNERABLE.
Every vulnerability is labeled with: # [VULN: CH##-C##]
═══════════════════════════════════════════════════════════════════════
"""
import os
import base64
from flask import Flask, request, session, redirect, render_template, jsonify, g, send_file, make_response
from flask_cors import CORS
from db import get_db, close_db, init_db
from flags import get_flag, FLAGS, FLAG_VALUES, HINTS

def create_app():
    app = Flask(__name__)
    
    # [VULN: CH04-C02] Hardcoded weak secret key — exposed via /debug endpoint
    app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_12345')
    
    # [VULN: CH02-C01/C02] Debug mode always on — verbose errors
    app.config['DEBUG'] = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
    app.config['UPLOAD_FOLDER'] = '/app/static/uploads'
    app.config['API_KEY'] = 'sk-pentrix-internal-key-9876'  # [VULN: CH04-C03]
    app.config['INTERNAL_SERVICE_URL'] = os.environ.get('INTERNAL_SERVICE_URL', 'http://internal:8080')
    
    # NO CSRF protection — intentional for CH10
    # NO flask-wtf installed — intentional
    
    CORS(app)  # [VULN: CH15] Wide-open CORS
    
    # Register teardown
    app.teardown_appcontext(close_db)
    
    # ═══════════════════════════════════════
    # CONTEXT PROCESSOR — Global template variables
    # ═══════════════════════════════════════
    @app.context_processor
    def inject_globals():
        """Inject CTF progress into all templates for sidebar progress bar"""
        ctx = {'ctf_progress': 0, 'ctf_captured': 0, 'ctf_total': len(FLAGS)}
        if session.get('user_id'):
            try:
                db = get_db()
                captured = db.execute(
                    'SELECT COUNT(DISTINCT flag_id) as cnt FROM submissions WHERE user_id=? AND correct=1',
                    [session['user_id']]
                ).fetchone()
                cnt = captured['cnt'] if captured else 0
                ctx['ctf_captured'] = cnt
                ctx['ctf_progress'] = int(cnt / len(FLAGS) * 100) if len(FLAGS) > 0 else 0
            except Exception:
                pass
        return ctx
    
    # ═══════════════════════════════════════
    # AFTER-REQUEST HOOKS — Intentional misconfigurations
    # ═══════════════════════════════════════
    @app.after_request
    def add_headers(response):
        # [VULN: CH02-C01] Server version disclosure
        response.headers['Server'] = 'Werkzeug/2.3.7 Python/3.11.2'
        # [VULN: CH02-C04] X-Powered-By disclosure
        response.headers['X-Powered-By'] = 'Flask/2.3.3'
        # [VULN: CH02-C06] Internal IP disclosure
        response.headers['X-Internal-IP'] = '10.0.1.42'
        # [VULN: CH04-C07] Custom headers leaking secrets
        response.headers['X-Debug-Mode'] = 'enabled'
        response.headers['X-Backend-Server'] = 'pentrix-web-01.internal'
        response.headers['X-Request-ID'] = 'req-' + str(hash(str(request.path)))[-8:]
        response.headers['X-API-Version'] = 'v2.3.3-internal'
        response.headers['X-Build-Commit'] = 'a1b2c3d4e5f6'
        
        # [VULN: CH12] NO X-Frame-Options — enables clickjacking
        # [VULN: CH12] NO Content-Security-Policy — enables XSS / clickjacking
        # [VULN: CH12] NO X-Content-Type-Options — MIME sniffing
        
        # [VULN: CH15-C01/C02] CORS origin reflection — any origin trusted
        origin = request.headers.get('Origin')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key, X-Forwarded-For'
        
        return response
    
    # ═══════════════════════════════════════
    # REQUEST LOGGING — [VULN: CH11-C07] Logs User-Agent unsafely
    # ═══════════════════════════════════════
    @app.before_request
    def log_request():
        try:
            db = get_db()
            user_id = session.get('user_id')
            # [VULN: CH11-C07] User-Agent stored without sanitization
            db.execute(
                'INSERT INTO access_logs (user_id, path, method, ip, user_agent) VALUES (?, ?, ?, ?, ?)',
                [user_id, request.path, request.method, request.remote_addr, request.headers.get('User-Agent', '')]
            )
            db.commit()
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # Register all route blueprints
    # ═══════════════════════════════════════
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.profile import profile_bp
    from routes.posts import posts_bp
    from routes.messages import messages_bp
    from routes.files import files_bp
    from routes.admin import admin_bp
    from routes.tools import tools_bp
    from routes.tickets import tickets_bp
    from routes.api import api_bp
    from routes.scoreboard import scoreboard_bp
    from routes.challenges import challenges_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(posts_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(scoreboard_bp)
    app.register_blueprint(challenges_bp)
    
    # ═══════════════════════════════════════
    # GLOBAL ROUTES — Discovery & Fingerprinting targets
    # ═══════════════════════════════════════
    
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect('/dashboard')
        return render_template('index.html')
    
    # [VULN: CH01-C02] robots.txt with hidden paths
    @app.route('/robots.txt')
    def robots():
        flag = get_flag('CH01-C02')
        content = f"""User-agent: *
Disallow: /admin/
Disallow: /debug/
Disallow: /backup/
Disallow: /internal/
Disallow: /internal/archive/
Disallow: /internal/comms/
Disallow: /internal/emails/
Disallow: /secret/
Disallow: /api/v2/
Disallow: /api/v3/
Disallow: /go/internal
# {flag}
"""
        return content, 200, {'Content-Type': 'text/plain'}
    
    # [VULN: CH01-C06] sitemap.xml
    @app.route('/sitemap.xml')
    def sitemap():
        flag = get_flag('CH01-C06')
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>http://localhost:5000/</loc></url>
    <url><loc>http://localhost:5000/login</loc></url>
    <url><loc>http://localhost:5000/dashboard</loc></url>
    <url><loc>http://localhost:5000/admin</loc></url>
    <url><loc>http://localhost:5000/secret</loc></url>
    <!-- {flag} -->
</urlset>"""
        return content, 200, {'Content-Type': 'application/xml'}
    
    # [VULN: CH01-C09] Changelog endpoint
    @app.route('/changelog')
    def changelog():
        flag = get_flag('CH01-C09')
        return f"""PenTrix Corp Internal Portal - Changelog
=========================================

v2.3.3 (2024-03-15) - Current [PRODUCTION]
  - Added network diagnostics tool (/tools/ping) — shells to os.popen()
  - Increased file upload limit to 50MB, all MIME types accepted
  - Added GraphQL endpoint with introspection enabled
  - XML import tool deployed (DTD/entity processing NOT disabled)
  - YAML restore uses yaml.load() without SafeLoader
  - Deployed internal service on port 8080 (no auth)
  - {flag}
  
v2.3.2 (2024-03-01) - Security "Fixes"
  - CORS: now reflecting Origin header (is this secure?)
  - X-Frame-Options: added to TODO list (not implemented)
  - Password storage: still plaintext, migration to bcrypt "planned"
  - See /internal/audit-checklist for status

v2.3.1 (2024-02-01) - API Update
  - Added API v2 endpoints (/api/v2/)
  - Exposed /actuator health endpoints
  - JWT tokens use shared SECRET_KEY: super_secret_key_12345
  - Admin API key: sk-pentrix-admin-key-1234

v2.3.0 (2024-01-15) - Migration from PHP
  - Migrated to Flask/Python with SQLite
  - Backup stored at /backup/ during migration
  - Debug at /debug, admin backup at /admin2
  - .env, .git/HEAD, config.json accessible from web root
  - Test accounts: admin:admin, alice:password123, bob:letmein
  - Credentials in plaintext: dev_user:dev_secret, charlie:qwerty

v2.2.0 (2023-12-01) - Messaging & Tickets
  - Added message system (no access control between users)
  - Added support tickets (XSS in body not sanitized)
  - File upload: all MIME types accepted, no path validation
  - Transfer: accepts negative amounts, coupon: race condition

HTML version: /changelog.html
""", 200, {'Content-Type': 'text/plain'}
    
    # [VULN: CH01-C10 / CH04-C02] Debug endpoint — dumps config
    @app.route('/debug')
    def debug_endpoint():
        flag = get_flag('CH01-C10')
        flag2 = get_flag('CH04-C02')
        config_data = {
            'debug': True,
            'secret_key': app.secret_key,
            'database_url': 'sqlite:////app/data/pentrix.db',
            'internal_service': app.config['INTERNAL_SERVICE_URL'],
            'api_key': app.config['API_KEY'],
            'admin_credentials': {'username': 'admin', 'password': 'admin'},
            'flag_ch01_c10': flag,
            'flag_ch04_c02': flag2,
            'flask_version': '2.3.3',
            'python_version': '3.11.2',
            'environment': 'development',
        }
        return jsonify(config_data)
    
    # [VULN: CH07-C01] Hidden /secret endpoint
    @app.route('/secret')
    def secret_page():
        flag = get_flag('CH07-C01')
        return f"""<html><head><title>Secret Terminal</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#0a0e17; color:#10b981; font-family:'Cascadia Code','Fira Code','Consolas',monospace; padding:0; overflow:hidden; }}
.term {{ position:relative; min-height:100vh; padding:40px; }}
.scanline {{ position:fixed; top:0; left:0; right:0; bottom:0; pointer-events:none; background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px); z-index:10; }}
.crt {{ position:fixed; top:0; left:0; right:0; bottom:0; pointer-events:none; box-shadow:inset 0 0 120px rgba(0,0,0,0.7); z-index:11; }}
.prompt {{ color:#38bdf8; }}
.flag {{ color:#f59e0b; font-size:1.1rem; padding:8px 16px; background:rgba(245,158,11,0.08); border:1px dashed rgba(245,158,11,0.3); border-radius:4px; display:inline-block; margin:8px 0; }}
pre {{ line-height:1.7; font-size:0.9rem; }}
.blink {{ animation: blink 1s step-end infinite; }}
@keyframes blink {{ 50% {{ opacity:0; }} }}
h1 {{ color:#10b981; font-size:1.5rem; margin-bottom:16px; text-shadow:0 0 20px rgba(16,185,129,0.4); }}
a {{ color:#38bdf8; }}
</style></head><body>
<div class="scanline"></div>
<div class="crt"></div>
<div class="term">
<pre>
<span class="prompt">root@pentrix-web-01:~#</span> cat /etc/secret.conf

   ____            _____     _
  |  _ \\ ___  _ _|_   _| __(_)_  __
  | |_) / _ \\| '_ \\| || '__| \\ \\/ /
  |  __/  __/| | | | || |  | |>  <
  |_|   \\___||_| |_|_||_|  |_/_/\\_\\

  <span style="color:#ef4444">[ SECRET TERMINAL - AUTHORIZED ACCESS ONLY ]</span>

</pre>
<h1>🔐 You found the secret endpoint!</h1>
<pre>
<span class="prompt">root@pentrix-web-01:~#</span> echo $FLAG
<span class="flag">{flag}</span>

<span class="prompt">root@pentrix-web-01:~#</span> cat /etc/shadow
root:$6$rounds=656000$salt$hash:19000:0:99999:7:::
admin:$6$admin$weakpasswordhash:19000:0:99999:7:::

<span class="prompt">root@pentrix-web-01:~#</span> env | grep -i secret
SECRET_KEY=super_secret_key_12345
API_KEY=sk-pentrix-internal-key-9876
JWT_SECRET=super_secret_key_12345
REDIS_URL=redis://pentrix_redis:6379

<span class="prompt">root@pentrix-web-01:~#</span> <span class="blink">_</span>
</pre>
<p style="margin-top:24px;color:#64748b;font-size:0.8rem;">
    [ <a href="/debug">Debug Panel</a> | <a href="/admin2">Admin Backup</a> | <a href="/dashboard">Dashboard</a> ]
</p>
</div>
</body></html>"""
    
    # [VULN: CH07-C04] Hidden admin route
    @app.route('/admin2')
    def admin2():
        flag = get_flag('CH07-C04')
        return f"""<html><head><title>Admin Backup</title>
<style>
body {{ background:#0a0e17; color:#c9d1d9; font-family:'Cascadia Code',monospace; padding:40px; }}
.hdr {{ color:#ef4444; border-bottom:1px solid rgba(239,68,68,0.2); padding-bottom:12px; margin-bottom:20px; }}
.flag {{ color:#f59e0b; background:rgba(245,158,11,0.08); padding:6px 14px; border:1px dashed rgba(245,158,11,0.3); border-radius:4px; font-size:1rem; display:inline-block; }}
pre {{ color:#94a3b8; line-height:1.7; }}
a {{ color:#38bdf8; }}
</style></head><body>
<h1 class="hdr">⚙️ Admin Backup Panel</h1>
<pre>
Status: <span style="color:#10b981;">● Active</span>
Access: <span style="color:#ef4444;">No authentication required</span>

Database backup: /backup/db.sqlite
Config backup:   /config.json
Environment:     /.env
Git info:        /.git/HEAD

Flag: <span class="flag">{flag}</span>

Quick Links:
  <a href="/debug">Debug Panel</a> | <a href="/admin">Main Admin</a> | <a href="/logs">Access Logs</a>
</pre>
</body></html>"""
    
    # [VULN: CH07-C07] Internal status endpoint
    @app.route('/internal/status')
    def internal_status():
        flag = get_flag('CH07-C07')
        return jsonify({
            'status': 'operational',
            'services': {
                'web': 'running',
                'redis': 'running',
                'internal': 'running'
            },
            'flag': flag,
            'uptime': '72h 15m',
            'version': '1.3.2'
        })
    
    # [VULN: CH07-C08] Exposed .git directory
    @app.route('/.git/HEAD')
    def git_head():
        flag = get_flag('CH07-C08')
        return f"ref: refs/heads/main\n# {flag}\n", 200, {'Content-Type': 'text/plain'}
    
    @app.route('/.git/config')
    def git_config():
        return """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://github.com/pentrix-corp/internal-portal.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    name = admin
    email = admin@pentrix.corp
""", 200, {'Content-Type': 'text/plain'}
    
    # [VULN: CH07-C09] Test and dev endpoints
    @app.route('/test')
    def test_endpoint():
        flag = get_flag('CH07-C09')
        return jsonify({'environment': 'test', 'flag': flag, 'debug': True})
    
    @app.route('/dev')
    def dev_endpoint():
        return jsonify({'environment': 'development', 'features': ['graphql', 'websocket', 'api_v3'], 'debug': True})
    
    # [VULN: CH01-C04] Backup file
    @app.route('/backup/db.sqlite')
    @app.route('/backup/')
    def backup_db():
        flag = get_flag('CH04-C06')
        return f"SQLite format 3\x00\n-- PenTrix Backup Database\n-- {flag}\n-- Contains: users, sessions, posts, messages, files, tickets\n", 200, {'Content-Type': 'application/octet-stream'}
    
    # [VULN: CH04-C08] Config JSON
    @app.route('/config.json')
    def config_json():
        flag = get_flag('CH04-C08')
        return jsonify({
            'secret_key': app.secret_key,
            'api_key': app.config['API_KEY'],
            'flag': flag,
            'database': 'sqlite:////app/data/pentrix.db',
            'internal_service': 'http://internal:8080'
        })
    
    # [VULN: CH04-C10] Logs endpoint
    @app.route('/logs')
    def logs_endpoint():
        flag = get_flag('CH04-C10')
        db = get_db()
        logs = db.execute('SELECT * FROM access_logs ORDER BY id DESC LIMIT 100').fetchall()
        log_lines = [f"[{l['created_at']}] {l['method']} {l['path']} - IP: {l['ip']} - UA: {l['user_agent']} - User: {l['user_id']}" for l in logs]
        return f"PenTrix Access Logs\n{'='*50}\n{flag}\n{'='*50}\n" + '\n'.join(log_lines), 200, {'Content-Type': 'text/plain'}
    
    # [VULN: CH01-C04] app.py.bak backup file
    @app.route('/app.py.bak')
    def app_backup():
        flag = get_flag('CH01-C04')
        return f"""# PenTrix Corp Internal Portal - Backup
# Created: 2024-01-15
# {flag}
SECRET_KEY = 'super_secret_key_12345'
DATABASE_URL = 'sqlite:////app/data/pentrix.db'
ADMIN_PASSWORD = 'admin'
API_KEY = 'sk-pentrix-internal-key-9876'
""", 200, {'Content-Type': 'text/plain'}
    
    # [VULN: CH02-C07] 500 error with stack trace
    @app.route('/500-test')
    def error_test():
        # Intentionally raise an error to show verbose traceback
        raise Exception("Intentional error for fingerprinting — OS: Linux, Framework: Flask/2.3.3, Python: 3.11.2")
    
    # [VULN: CH04-C04] Exposed .env file
    @app.route('/.env')
    def env_file():
        flag = get_flag('CH04-C04')
        return f"""# PenTrix Configuration
PORT=5000
FLAG_SECRET=pentrix_lab_secret_2024
SECRET_KEY=super_secret_key_12345
API_KEY=sk-pentrix-internal-key-9876
DATABASE_URL=sqlite:////app/data/pentrix.db
INTERNAL_SERVICE_URL=http://internal:8080
REDIS_URL=redis://redis:6379/0
ADMIN_PASSWORD=admin
# {flag}
""", 200, {'Content-Type': 'text/plain'}
    
    # [VULN: CH07-C02] Debug parameter
    @app.route('/dashboard/settings')
    def dashboard_settings():
        debug = request.args.get('debug')
        flag = None
        if debug == 'true':
            flag = get_flag('CH07-C02')
        return render_template('dashboard/settings.html', debug_flag=flag, debug_mode=debug)
    
    # [VULN: CH02-C03] Error page with OS info
    @app.errorhandler(404)
    def not_found_error(error):
        # Pick a random narrative hint for the 404 page
        import random
        narrative_hints = [
            "Tip: developers often leave hidden endpoints accessible. Have you checked robots.txt?",
            "Not all paths are visible. Some are hidden in plain sight — in source code, headers, and cookies.",
            "A good pentester doesn't just guess paths. They read what the application reveals about itself.",
            "The internal team left notes at /internal/notes. Maybe they mentioned something useful.",
            "Try checking the developer chat logs. Sometimes the team discusses endpoints they forgot to remove.",
            "Have you inspected the HTTP response headers? They can be surprisingly talkative.",
            "Every 404 is intel. You now know this path doesn't exist — that narrows your search.",
        ]
        hint = random.choice(narrative_hints)
        return f"""<html>
<head><title>404 — Page Not Found | PenTrix Corp</title>
<link rel="stylesheet" href="/static/css/style.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body style="display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
<div style="text-align:center;max-width:520px;padding:40px;">
    <div style="font-size:5rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--info));-webkit-background-clip:text;-webkit-text-fill-color:transparent;line-height:1;">404</div>
    <h2 style="margin:16px 0 8px;">Dead End</h2>
    <p style="color:var(--text-muted);margin-bottom:16px;">The path <code style="background:var(--surface);padding:2px 8px;border-radius:4px;">{request.path}</code> leads nowhere.</p>
    <p style="color:var(--text-secondary);font-size:0.85rem;line-height:1.6;background:rgba(255,255,255,0.03);padding:14px 18px;border-radius:8px;border-left:3px solid var(--accent);text-align:left;margin-bottom:20px;">{hint}</p>
    <div style="display:flex;gap:10px;justify-content:center;">
        <a href="/dashboard" class="btn btn-primary">Dashboard</a>
        <a href="/challenges" class="btn btn-sm">Challenges</a>
        <a href="/" class="btn btn-sm">Home</a>
    </div>
    <!-- Server: Werkzeug/2.3.7 Python/3.11.2 Framework: Flask/2.3.3 -->
    <!-- pentrix-web-01.internal | Build: a1b2c3d4e5f6 -->
</div>
</body></html>""", 404

    @app.errorhandler(500)
    def internal_error(error):
        flag = get_flag('CH02-C03')
        return f"""<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h1>Internal Server Error</h1>
<pre>
Traceback (most recent call last):
  File "/app/app.py", line 42, in dispatch_request
    rv = self.ensure_sync(rule.endpoint)(**req.view_args)
  File "/app/routes/dashboard.py", line 15, in index
    raise RuntimeError("Internal application error")
RuntimeError: {str(error)}

Server: Werkzeug/2.3.7 on Python 3.11.2
OS: Linux 5.15.0-91-generic #101-Ubuntu SMP x86_64
Framework: Flask 2.3.3
Database: SQLite 3.39.0
{flag}
</pre>
</body></html>""", 500
    
    # [VULN: CH02-C05] Database error with SQLite info
    @app.route('/db-error-test')
    def db_error_test():
        flag = get_flag('CH02-C05')
        return f"""<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h1>Database Error</h1>
<pre>
sqlite3.OperationalError: no such table: nonexistent_table
Database: SQLite version 3.39.0
Path: /app/data/pentrix.db
{flag}
</pre>
</body></html>""", 500
    
    # [VULN: CH09-C03] Open redirect
    @app.route('/redirect')
    def open_redirect():
        url = request.args.get('url', request.args.get('redirect', '/dashboard'))
        # [VULN: CH09-C03] No validation on redirect target
        return redirect(url)
    
    # [VULN: CH01-C01] Secret page linked in footer
    @app.route('/secret-page')
    def secret_linked_page():
        flag = get_flag('CH01-C01')
        return f"""<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h1>🔐 Secret Documentation</h1>
<p>This page is linked from the footer — only those who look carefully will find it.</p>
<pre>{flag}</pre>
</body></html>"""
    
    # [VULN: CH13-C02] Negative transfer
    @app.route('/account/transfer', methods=['GET', 'POST'])
    def account_transfer():
        if 'user_id' not in session:
            return redirect('/login')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id=?', [session['user_id']]).fetchone()
        message = None
        flag = None
        
        if request.method == 'POST':
            to_user = request.form.get('to_user', '')
            amount = float(request.form.get('amount', 0))
            
            # [VULN: CH13-C02] No validation on negative amounts
            recipient = db.execute('SELECT * FROM users WHERE username=?', [to_user]).fetchone()
            if recipient:
                db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, session['user_id']])
                db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, recipient['id']])
                db.commit()
                
                if amount < 0:
                    flag = get_flag('CH13-C02')
                    message = f'Transfer complete! {flag}'
                else:
                    message = f'Transferred ${amount:.2f} to {to_user}'
            else:
                message = 'Recipient not found'
        
        return render_template('dashboard/transfer.html', user=user, message=message, flag=flag)
    
    # [VULN: CH13-C01] Coupon application (unlimited use)
    @app.route('/coupons/apply', methods=['POST'])
    def apply_coupon():
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        code = request.form.get('code', request.json.get('code', '') if request.is_json else '')
        db = get_db()
        
        # [VULN: CH13-C01] Race condition — uses_left checked but not atomically decremented
        coupon = db.execute('SELECT * FROM coupons WHERE code = ?', [code]).fetchone()
        if coupon and coupon['uses_left'] > 0:
            # Simulate processing delay (makes race condition exploitable)
            import time
            time.sleep(0.1)
            
            db.execute('UPDATE coupons SET uses_left = uses_left - 1 WHERE code = ?', [code])
            db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [coupon['discount'], session['user_id']])
            db.commit()
            
            flag = get_flag('CH13-C01')
            return jsonify({'success': True, 'discount': coupon['discount'], 'flag': flag})
        
        return jsonify({'error': 'Invalid or expired coupon'}), 400
    
    # [VULN: CH13-C07] Client-side age verification
    @app.route('/age-verify')
    def age_verify():
        return render_template('dashboard/age_verify.html')
    
    @app.route('/age-verify/confirmed', methods=['POST'])
    def age_verified():
        # [VULN: CH13-C07] Only checks client-sent value, no server verification
        verified = request.form.get('age_verified', 'false')
        if verified == 'true':
            flag = get_flag('CH13-C07')
            return jsonify({'access': 'granted', 'flag': flag})
        return jsonify({'access': 'denied'}), 403
    
    # [VULN: CH13-C08] Self-approval
    @app.route('/approvals/<int:request_id>/approve', methods=['POST'])
    def approve_request(request_id):
        if 'user_id' not in session:
            return redirect('/login')
        
        db = get_db()
        req = db.execute('SELECT * FROM approval_requests WHERE id = ?', [request_id]).fetchone()
        
        if req:
            # [VULN: CH13-C08] No check if approver == requester
            db.execute('UPDATE approval_requests SET status = ?, approved_by = ? WHERE id = ?',
                      ['approved', session['user_id'], request_id])
            db.commit()
            
            if req['user_id'] == session['user_id']:
                flag = get_flag('CH13-C08')
                return jsonify({'status': 'approved', 'flag': flag, 'message': 'Self-approval detected!'})
            return jsonify({'status': 'approved'})
        
        return jsonify({'error': 'Request not found'}), 404
    
    # DOM Lab page
    @app.route('/dom-lab')
    def dom_lab():
        return render_template('dom/playground.html')
    
    # [VULN: CH07-C03] Common web paths — recon targets
    @app.route('/phpinfo')
    def phpinfo():
        return """<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h1>Not PHP... but you found something!</h1>
<p>This server runs Flask/Python, not PHP. But nice try with directory busting!</p>
<p>Hint: Try /debug, /secret, /admin2, /backup/, /.env, /.git/HEAD</p>
</body></html>"""
    
    @app.route('/wp-admin')
    @app.route('/wp-login.php')
    def wp_admin():
        return """<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h1>No WordPress here!</h1>
<p>This portal runs on Flask. Good reconnaissance though!</p>
<p>Try: /api/docs, /graphql, /internal/status</p>
</body></html>"""
    
    @app.route('/actuator')
    @app.route('/actuator/health')
    @app.route('/actuator/env')
    def actuator():
        flag = get_flag('CH07-C05')
        return jsonify({
            'status': 'UP',
            'app': 'pentrix-portal',
            'environment': 'development',
            'profiles': ['dev', 'debug'],
            'flag': flag,
            'config': {
                'server.address': '0.0.0.0',
                'server.port': 5000,
                'spring.datasource.url': 'sqlite:////app/data/pentrix.db'
            }
        })
    
    @app.route('/server-status')
    @app.route('/server-info')
    def server_status():
        flag = get_flag('CH02-C09')
        return f"""<html><head><title>Server Status</title></head>
<body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h1>Server Status for pentrix-web-01</h1>
<pre>
Server Version: Werkzeug/2.3.7 (Python/3.11.2)
Server Built:   Jan 15 2024 09:30:42
Current Time:   Running
Restart Time:   Container start
Server uptime:  72 hours 15 minutes
Total accesses: 15234
CPU Usage:      u12.5 s3.2
{flag}

Active Connections:
  10.0.1.42:5000 → Redis (6379)
  10.0.1.42:5000 → Internal (8080)
  
Loaded Modules: flask, jinja2, sqlite3, pyjwt, yaml, pickle
</pre>
</body></html>""", 200
    
    @app.route('/.htaccess')
    def htaccess():
        return """# PenTrix Configuration
RewriteEngine On
RewriteRule ^admin$ /admin [L]
# Secret paths:
# /api/v2/internal
# /backup/
# /reports/export
SetEnv DB_PASSWORD admin
SetEnv REDIS_URL redis://pentrix_redis:6379
""", 200, {'Content-Type': 'text/plain'}
    
    @app.route('/crossdomain.xml')
    def crossdomain():
        flag = get_flag('CH15-C05')
        return f"""<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <allow-access-from domain="*"/>
  <allow-http-request-headers-from domain="*" headers="*"/>
  <!-- {flag} -->
</cross-domain-policy>""", 200, {'Content-Type': 'application/xml'}
    
    @app.route('/security.txt')
    @app.route('/.well-known/security.txt')
    def security_txt():
        flag = get_flag('CH01-C07')
        return f"""Contact: admin@pentrix-corp.internal
Encryption: none
Acknowledgements: /hall-of-fame
Preferred-Languages: en
Canonical: http://localhost:5000/.well-known/security.txt
# {flag}
# Internal: pentrix-web-01.internal
# VPN: vpn.pentrix-corp.internal
""", 200, {'Content-Type': 'text/plain'}
    
    @app.route('/humans.txt')
    def humans_txt():
        flag = get_flag('CH01-C08')
        return f"""/* TEAM */
Developer: dev_user
Contact: dev_team@pentrix-corp.internal
From: Internal
Password: dev_secret
# {flag}

/* THANKS */
Flask framework: https://flask.palletsprojects.com
Internal service team: internal-ops@pentrix-corp.internal
""", 200, {'Content-Type': 'text/plain'}
    
    # [VULN: CH10-C01] CSRF — change email (no CSRF token)
    @app.route('/account/email', methods=['POST'])
    def change_email():
        if 'user_id' not in session:
            return redirect('/login')
        
        new_email = request.form.get('email', '')
        db = get_db()
        db.execute('UPDATE users SET email = ? WHERE id = ?', [new_email, session['user_id']])
        db.commit()
        
        flag = get_flag('CH10-C01')
        return jsonify({'success': True, 'flag': flag, 'message': f'Email changed to {new_email}'})
    
    # [VULN: CH10-C02] CSRF — change password (no old password required)
    @app.route('/account/password', methods=['POST'])
    def change_password():
        if 'user_id' not in session:
            return redirect('/login')
        
        new_password = request.form.get('new_password', '')
        # [VULN: CH10-C02] No old password verification!
        db = get_db()
        db.execute('UPDATE users SET password = ? WHERE id = ?', [new_password, session['user_id']])
        db.commit()
        
        flag = get_flag('CH10-C02')
        return jsonify({'success': True, 'flag': flag})
    
    # [VULN: CH10-C03] CSRF via GET to delete account
    @app.route('/account/delete')
    def delete_account():
        if 'user_id' not in session:
            return redirect('/login')
        
        flag = get_flag('CH10-C03')
        db = get_db()
        db.execute('UPDATE users SET is_active = 0 WHERE id = ?', [session['user_id']])
        db.commit()
        
        return jsonify({'deleted': True, 'flag': flag})
    
    # [VULN: CH10-C05] CSRF — promote to admin
    @app.route('/account/promote', methods=['POST'])
    def promote_to_admin():
        user_id = request.form.get('user_id', session.get('user_id'))
        db = get_db()
        db.execute("UPDATE users SET role = 'admin' WHERE id = ?", [user_id])
        db.commit()
        
        flag = get_flag('CH10-C05')
        return jsonify({'promoted': True, 'flag': flag})
    
    # [VULN: CH04-C05] Verbose error with credit card
    @app.route('/payment/process', methods=['POST'])
    def process_payment():
        flag = get_flag('CH04-C05')
        return f"""<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h1>Payment Processing Error</h1>
<pre>
Error: Payment gateway timeout
Transaction Details:
  Card: 4111-1111-1111-1111
  Amount: $500.00
  User: admin@pentrix.corp
  {flag}

Please contact support.
</pre>
</body></html>""", 500
    
    # [VULN: CH13-C04] Skip email verification
    @app.route('/verify-email/skip')
    def skip_verification():
        if 'user_id' not in session:
            return redirect('/login')
        
        db = get_db()
        db.execute('UPDATE users SET email_verified = 1 WHERE id = ?', [session['user_id']])
        db.commit()
        
        flag = get_flag('CH13-C04')
        return jsonify({'verified': True, 'flag': flag, 'message': 'Email verification skipped!'})
    
    # [VULN: CH13-C05] Export unauthorized data
    @app.route('/reports/export')
    def export_report():
        if 'user_id' not in session:
            return redirect('/login')
        
        # [VULN: CH13-C05] No authorization check — any user can export
        db = get_db()
        users = db.execute('SELECT username, email, salary, ssn FROM users').fetchall()
        flag = get_flag('CH13-C05')
        
        data = [{'username': u['username'], 'email': u['email'], 'salary': u['salary'], 'ssn': u['ssn']} for u in users]
        return jsonify({'flag': flag, 'report': data})
    
    # [VULN: CH13-C06] Predictable sequential user ID
    @app.route('/next-user-id')
    def next_user_id():
        db = get_db()
        last = db.execute('SELECT MAX(id) as max_id FROM users').fetchone()
        next_id = (last['max_id'] or 0) + 1
        flag = get_flag('CH13-C06')
        return jsonify({'next_id': next_id, 'flag': flag})
    
    # [VULN: CH13-C09] Email enumeration (no rate limit)
    @app.route('/check-email')
    def check_email():
        email = request.args.get('email', '')
        db = get_db()
        user = db.execute('SELECT id FROM users WHERE email = ?', [email]).fetchone()
        if user:
            return jsonify({'exists': True, 'message': 'Email is registered'})
        return jsonify({'exists': False, 'message': 'Email not found'})
    
    # ═══════════════════════════════════════════════════════════
    # CORPORATE ENVIRONMENT SIMULATION — Narrative Intelligence
    # Internal communications, file artifacts, access logs,
    # and corporate memos that serve as organic recon clues.
    # ═══════════════════════════════════════════════════════════

    @app.route('/internal/comms')
    @app.route('/internal/messages')
    def internal_comms():
        """Corporate internal messaging system — organic hints embedded in office chatter."""
        return render_template('narrative/comms.html')

    @app.route('/internal/chat')
    def internal_chat():
        """Developer Slack-style chat logs — leaked conversations with organic clues."""
        return render_template('narrative/chat.html')

    @app.route('/internal/notes')
    def internal_notes():
        """Internal sticky notes / memos left around the system."""
        return f"""<html><head><title>PenTrix Corp — Internal Notes</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:'Inter','Segoe UI',sans-serif; padding:40px; max-width:900px; margin:0 auto; }}
h1 {{ color:#f0f6fc; font-size:1.5rem; border-bottom:1px solid rgba(255,255,255,0.06); padding-bottom:12px; }}
.note {{ background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:16px 20px; margin:12px 0; position:relative; }}
.note::before {{ content:'📌'; position:absolute; top:-8px; left:12px; font-size:1.1rem; }}
.author {{ font-size:0.78rem; color:#8b949e; margin-top:8px; }}
.urgent {{ border-left:3px solid #f85149; }}
.resolved {{ border-left:3px solid #3fb950; opacity:0.7; }}
.info {{ border-left:3px solid #58a6ff; }}
a {{ color:#58a6ff; }}
</style></head><body>
<h1>📋 Internal Notes Board</h1>
<p style="color:#8b949e;font-size:0.88rem;">PenTrix Corp &mdash; For internal use only. Do not distribute externally.</p>

<div class="note urgent">
    <strong>URGENT: Migration Cleanup</strong><br>
    We migrated from the old portal last week. The backup was stored at <code>/backup/</code> during the transition.
    Someone please verify it's been removed. The old staging endpoint might still be accessible too.<br>
    <span class="author">&mdash; admin, 3 days ago</span>
</div>

<div class="note info">
    <strong>RE: Test Accounts</strong><br>
    Dev reminder: the test accounts (alice:password123, bob:letmein) were supposed to be temporary.
    We still haven't rotated those credentials. Also, dev_user's API key is still <code>sk-pentrix-dev-key-5678</code> — needs rotation.<br>
    <span class="author">&mdash; dev_user, 1 week ago</span>
</div>

<div class="note">
    <strong>Debug Mode Still Active</strong><br>
    Noticed <code>/debug</code> is still responding in production. Also, someone mentioned they saw
    our <code>.env</code> file was accessible from the browser? Can someone check?<br>
    <span class="author">&mdash; charlie, 5 days ago</span>
</div>

<div class="note resolved">
    <strong>RESOLVED: CORS Configuration</strong><br>
    Fixed the CORS headers... I think. We're reflecting the Origin header now which should work.
    Security team, please review when you get a chance. Currently allowing credentials with wildcard fallback.<br>
    <span class="author">&mdash; dev_user, 2 weeks ago</span>
</div>

<div class="note info">
    <strong>Scheduled: Security Audit Q4</strong><br>
    The security audit is coming up. Please make sure we've cleaned up:
    - Old admin panel at <code>/admin2</code> (is this still reachable?)
    - The XML import tool (do we validate DTDs?)
    - YAML restore endpoint (I heard pickle was involved?)
    Check <a href="/internal/audit-checklist">/internal/audit-checklist</a> for the full list.<br>
    <span class="author">&mdash; hr_manager, 1 week ago</span>
</div>

<div class="note">
    <strong>GraphQL Endpoint</strong><br>
    Introspection is still enabled on <code>/graphql</code>. I asked about disabling it but the frontend team
    says they need it for development. Can we at least restrict the queries?<br>
    <span class="author">&mdash; alice, 4 days ago</span>
</div>

<!-- Internal: pentrix-web-01 / redis:6379 / internal:8080 -->
<!-- TODO: rotate SECRET_KEY before audit (currently: super_secret_key_12345) -->
</body></html>""", 200, {'Content-Type': 'text/html'}

    @app.route('/internal/audit-checklist')
    def audit_checklist():
        """Pre-audit checklist — reveals what the devs know is broken."""
        return f"""<html><head><title>Audit Checklist</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; padding:40px; max-width:800px; margin:0 auto; }}
h1 {{ color:#f0f6fc; }} .done {{ color:#3fb950; }} .pending {{ color:#f85149; }} .partial {{ color:#d29922; }}
li {{ margin:8px 0; line-height:1.6; }}
</style></head><body>
<h1>🔒 Pre-Audit Security Checklist</h1>
<p style="color:#8b949e;">Last updated: 2024-03-10 by dev_user</p>
<ul>
<li class="done">✅ HTTPS enabled (via reverse proxy)</li>
<li class="pending">❌ Remove /debug endpoint from production</li>
<li class="pending">❌ Remove /admin2 backup admin panel</li>
<li class="pending">❌ Disable GraphQL introspection</li>
<li class="partial">⚠️ CORS — "fixed" (reflecting origin header)</li>
<li class="pending">❌ Rotate hardcoded SECRET_KEY</li>
<li class="pending">❌ Remove .env, .git/HEAD, config.json from web root</li>
<li class="partial">⚠️ CSRF tokens — "planned for next sprint"</li>
<li class="done">✅ Rate limiting — (not actually implemented)</li>
<li class="pending">❌ Validate XML/YAML imports (DTD/entity injection?)</li>
<li class="pending">❌ Sanitize file upload types (SVG, HTML allowed)</li>
<li class="partial">⚠️ Password storage — still plaintext (migration planned)</li>
<li class="pending">❌ Remove test accounts before go-live</li>
<li class="pending">❌ Fix IDOR on /profile, /messages, /files endpoints</li>
<li class="partial">⚠️ Input sanitization — "mostly done" (SQL queries use string formatting)</li>
</ul>
<p style="color:#484f58;font-size:0.8rem;margin-top:30px;"><!-- Note: this checklist is itself a security vulnerability --></p>
</body></html>""", 200, {'Content-Type': 'text/html'}

    @app.route('/internal/wiki')
    @app.route('/internal/docs')
    def internal_wiki():
        """Internal wiki with developer documentation — clues embedded naturally."""
        return f"""<html><head><title>PenTrix Corp Wiki</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:'Inter',sans-serif; padding:40px; max-width:900px; margin:0 auto; line-height:1.7; }}
h1 {{ color:#f0f6fc; }} h2 {{ color:#58a6ff; margin-top:30px; font-size:1.1rem; }} code {{ background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:4px; font-size:0.88rem; }}
hr {{ border-color:rgba(255,255,255,0.06); margin:20px 0; }}
a {{ color:#58a6ff; }}
</style></head><body>
<h1>📖 PenTrix Corp — Internal Developer Wiki</h1>
<p style="color:#8b949e;font-size:0.85rem;">Restricted access. Do not share with external parties.</p>
<hr>
<h2>Architecture Overview</h2>
<p>The portal consists of three services orchestrated via Docker Compose:</p>
<ul>
<li><strong>pentrix_web</strong> (port 5000) — Main Flask application with SQLite backend</li>
<li><strong>pentrix_internal</strong> (port 8080) — Internal microservice for SSRF demo targets</li>
<li><strong>pentrix_redis</strong> (port 6379) — Redis cache, no authentication required</li>
</ul>

<h2>Authentication</h2>
<p>Session-based auth using Flask's built-in sessions. <code>SECRET_KEY</code> is set in app config.
Passwords are stored in <strong>plaintext</strong> (intentional — this is a vuln lab).
JWT tokens use the same secret key. Default admin creds: <code>admin:admin</code></p>

<h2>API Endpoints</h2>
<p>REST API at <code>/api/v1/</code> and <code>/api/v2/</code>. GraphQL at <code>/graphql</code> (introspection enabled).
API keys stored in <code>api_keys</code> table. Admin key: <code>sk-pentrix-admin-key-1234</code></p>

<h2>Known Issues</h2>
<ul>
<li>The <code>/tools/ping</code> endpoint shells out to <code>os.popen()</code> — needs sanitization</li>
<li>File upload accepts any MIME type including <code>.html</code>, <code>.svg</code>, <code>.php</code></li>
<li>The YAML restore at <code>/tools/restore</code> uses <code>yaml.load()</code> — unsafe deserializer</li>
<li>XML import at <code>/tools/xml-import</code> doesn't disable external entities</li>
<li>The <code>/redirect</code> endpoint has no URL validation (open redirect)</li>
</ul>

<h2>Accessing Internal Service</h2>
<p>The internal service runs on <code>http://internal:8080</code> and is not exposed externally.
However, the <code>/tools/fetch</code> endpoint can be used to reach it (SSRF). The internal service
includes endpoints like <code>/admin</code>, <code>/flag</code>, <code>/users</code>.</p>

<!-- TODO: remove this wiki before production deployment -->
<!-- DB path: /app/data/pentrix.db -->
<!-- Flag secret: pentrix_lab_secret_2024 -->
</body></html>""", 200, {'Content-Type': 'text/html'}

    @app.route('/internal/emails')
    def internal_emails():
        """Cached internal email thread — corporate drama with embedded clues."""
        return f"""<html><head><title>Corporate Email Cache</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:'Inter',sans-serif; padding:40px; max-width:900px; margin:0 auto; }}
h1 {{ color:#f0f6fc; font-size:1.4rem; }} 
.email {{ background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:16px 20px; margin:16px 0; }}
.email-header {{ display:flex; justify-content:space-between; font-size:0.82rem; color:#8b949e; margin-bottom:8px; border-bottom:1px solid rgba(255,255,255,0.04); padding-bottom:8px; }}
.subject {{ color:#58a6ff; font-weight:600; }}
.from {{ color:#e6edf3; }}
</style></head><body>
<h1>📧 Email Gateway Cache — pentrix-smtp</h1>
<p style="color:#8b949e;font-size:0.82rem;">Cached emails from internal SMTP relay. This cache should not be publicly accessible.</p>

<div class="email">
    <div class="email-header">
        <span><span class="from">From: admin@pentrix.corp</span> → hr@pentrix.corp</span>
        <span>2024-03-12 09:15</span>
    </div>
    <div class="subject">RE: Password Policy Update</div>
    <p>We'll implement bcrypt in the next release. For now, all passwords remain in plaintext in the users table.
    Please don't share this — it includes salary and SSN fields too. The export endpoint at <code>/reports/export</code>
    pulls everything without authorization checks.</p>
</div>

<div class="email">
    <div class="email-header">
        <span><span class="from">From: dev_user@pentrix.corp</span> → admin@pentrix.corp</span>
        <span>2024-03-11 16:42</span>
    </div>
    <div class="subject">Staging Routes Left Behind</div>
    <p>Hey admin, I pushed the production build but I think I left a few staging routes active:
    <code>/test</code>, <code>/dev</code>, <code>/debug</code>, <code>/500-test</code>.
    Also the <code>/actuator</code> endpoints are responding — thought we disabled those.
    Can you check? My API key <code>sk-pentrix-dev-key-5678</code> should still work if you need to test.</p>
</div>

<div class="email">
    <div class="email-header">
        <span><span class="from">From: charlie@pentrix.corp</span> → dev_user@pentrix.corp</span>
        <span>2024-03-10 11:20</span>
    </div>
    <div class="subject">RE: SSRF Concern</div>
    <p>I tested the fetch tool at <code>/tools/fetch</code> and was able to reach <code>http://internal:8080/admin</code>
    from the browser. The internal service doesn't require auth either. Shouldn't we whitelist URLs?
    Also, the ping tool at <code>/tools/ping</code> seems to accept semicolons in the input...</p>
</div>

<div class="email">
    <div class="email-header">
        <span><span class="from">From: alice@pentrix.corp</span> → all-staff@pentrix.corp</span>
        <span>2024-03-08 14:55</span>
    </div>
    <div class="subject">Profile Privacy Concern</div>
    <p>Hi team, I noticed I can view other people's profiles by changing the ID in the URL
    (<code>/profile/1</code>, <code>/profile/2</code>, etc.). Same thing with messages — I can read
    inbox items that aren't mine. Is this intentional?</p>
</div>

<div class="email">
    <div class="email-header">
        <span><span class="from">From: hr_manager@pentrix.corp</span> → admin@pentrix.corp</span>
        <span>2024-03-06 08:30</span>
    </div>
    <div class="subject">File Upload Issue</div>
    <p>Someone uploaded an SVG file as their profile picture and it executed JavaScript when I viewed it.
    The file manager at <code>/files/</code> also serves HTML files directly. We need content-type validation ASAP.
    Also, I noticed you can use <code>../</code> in the filename to upload outside the uploads directory.</p>
</div>

<!-- smtp-cache-node: pentrix-smtp-01.internal -->
<!-- relay-config: /etc/postfix/main.cf -->
</body></html>""", 200, {'Content-Type': 'text/html'}

    # ═══════════════════════════════════════════════════════════
    # RED HERRINGS — Misleading endpoints with lesson messages
    # "A lesson from Izaz and The PenTrix"
    # ═══════════════════════════════════════════════════════════

    @app.route('/backup_old.zip')
    @app.route('/database_dump.sql')
    @app.route('/admin_export.csv')
    def red_herring_files():
        """Red herring — looks promising but teaches a lesson."""
        return f"""<html><head><title>Nice Try!</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:'Inter',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
.container {{ text-align:center; max-width:560px; padding:40px; }}
.icon {{ font-size:4rem; margin-bottom:16px; }}
h1 {{ color:#f0f6fc; font-size:1.5rem; }}
.lesson {{ background:linear-gradient(135deg, rgba(16,185,129,0.06), rgba(56,189,248,0.04)); border:1px solid rgba(16,185,129,0.15); border-radius:12px; padding:24px; margin:24px 0; text-align:left; line-height:1.7; }}
.lesson-header {{ color:#10b981; font-weight:700; font-size:0.85rem; letter-spacing:1px; text-transform:uppercase; margin-bottom:8px; }}
.cta {{ margin-top:20px; }} .cta a {{ color:#58a6ff; text-decoration:none; }} .cta a:hover {{ text-decoration:underline; }}
</style></head><body>
<div class="container">
    <div class="icon">🎭</div>
    <h1>This was a decoy.</h1>
    <p style="color:#8b949e;">The file <code>{request.path}</code> doesn't contain anything useful.</p>
    <div class="lesson">
        <div class="lesson-header">💡 A Lesson from Izaz and The PenTrix</div>
        Not every path leads somewhere. In real penetration testing, you'll encounter countless
        rabbit holes. The skill isn't just finding things — it's knowing which findings matter.
        Prioritize your targets. Check response codes, content types, and file sizes before
        diving deep. A good pentester wastes no time on empty leads.<br><br>
        <strong>Keep trying. You're learning.</strong> 🔥
    </div>
    <div class="cta">
        <a href="/challenges">← Back to Challenges</a> &nbsp;|&nbsp;
        <a href="/internal/notes">Try the notes board</a>
    </div>
</div>
</body></html>""", 200, {'Content-Type': 'text/html'}

    @app.route('/super_secret_admin')
    @app.route('/master_key')
    @app.route('/vault')
    def red_herring_endpoints():
        """Red herring — suspiciously named endpoints that teach patience."""
        return f"""<html><head><title>Dead End</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:'Inter',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
.container {{ text-align:center; max-width:560px; padding:40px; }}
.glitch {{ font-size:3rem; color:#f85149; font-weight:800; animation:glitch 0.3s infinite; }}
@keyframes glitch {{ 0%,100% {{ transform:translate(0); }} 25% {{ transform:translate(-2px,1px); }} 75% {{ transform:translate(2px,-1px); }} }}
.lesson {{ background:linear-gradient(135deg, rgba(248,81,73,0.06), rgba(210,153,34,0.04)); border:1px solid rgba(248,81,73,0.15); border-radius:12px; padding:24px; margin:24px 0; text-align:left; line-height:1.7; }}
.lesson-header {{ color:#f85149; font-weight:700; font-size:0.85rem; letter-spacing:1px; text-transform:uppercase; margin-bottom:8px; }}
a {{ color:#58a6ff; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
</style></head><body>
<div class="container">
    <div class="glitch">ACCESS DENIED</div>
    <p style="color:#8b949e;margin:16px 0;">You requested <code>{request.path}</code> — but there's nothing here.</p>
    <div class="lesson">
        <div class="lesson-header">💡 A Lesson from Izaz and The PenTrix</div>
        Obvious names are often traps. Real secrets aren't behind <code>/vault</code> or <code>/master_key</code>.
        They're hidden in mundane places — error messages, HTTP headers, backup files with boring names,
        developer comments buried in source code. Think like a lazy developer, not a movie hacker.<br><br>
        <strong>The best finds are the ones nobody thought to hide.</strong>
    </div>
    <p style="margin-top:20px;"><a href="/challenges">← Challenges</a> | <a href="/robots.txt">robots.txt</a> | <a href="/.well-known/security.txt">security.txt</a></p>
</div>
</body></html>""", 200, {'Content-Type': 'text/html'}

    @app.route('/flag.txt')
    @app.route('/flags.txt')
    @app.route('/flag')
    def red_herring_flag():
        """Red herring — searching for flag files directly."""
        return f"""<html><head><title>Not That Easy</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:'Inter',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
.container {{ text-align:center; max-width:560px; padding:40px; }}
.lesson {{ background:linear-gradient(135deg, rgba(210,153,34,0.06), rgba(16,185,129,0.04)); border:1px solid rgba(210,153,34,0.15); border-radius:12px; padding:24px; margin:24px 0; text-align:left; line-height:1.7; }}
.lesson-header {{ color:#d29922; font-weight:700; font-size:0.85rem; letter-spacing:1px; text-transform:uppercase; margin-bottom:8px; }}
a {{ color:#58a6ff; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
</style></head><body>
<div class="container">
    <div style="font-size:4rem;">🏴</div>
    <h1 style="color:#f0f6fc;">Flags aren't served on a platter.</h1>
    <p style="color:#8b949e;">You tried <code>{request.path}</code> — that's too direct.</p>
    <div class="lesson">
        <div class="lesson-header">💡 A Lesson from Izaz and The PenTrix</div>
        In real engagements, sensitive data isn't stored in <code>flag.txt</code>. You need to understand
        the application first — map the attack surface, study the endpoints, analyze the responses.
        Each flag in The PenTrix represents a real vulnerability. Find them by <em>exploiting</em> the app,
        not by guessing filenames.<br><br>
        <strong>Start with reconnaissance. The answers will follow.</strong><br>
        <span style="font-size:0.85rem;color:#8b949e;">When you finish, share your achievement on LinkedIn! 🏆</span>
    </div>
    <p style="margin-top:20px;"><a href="/challenges">← Start with the challenges</a></p>
</div>
</body></html>""", 200, {'Content-Type': 'text/html'}

    @app.route('/.secret')
    @app.route('/hidden')
    @app.route('/private')
    def red_herring_hidden():
        """Red herring — common directory guessing names."""
        return f"""<html><head><title>Looking in the Wrong Place</title>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; padding:40px; max-width:600px; margin:40px auto; }}
.lesson {{ background:rgba(16,185,129,0.04); border:1px solid rgba(16,185,129,0.12); border-radius:8px; padding:20px; margin:20px 0; line-height:1.7; }}
.lesson-header {{ color:#10b981; font-weight:700; font-size:0.8rem; letter-spacing:1px; }}
a {{ color:#58a6ff; }}
</style></head><body>
<pre style="color:#8b949e;">
$ curl http://target{request.path}
HTTP/1.1 200 OK
Content-Type: text/html

</pre>
<h2 style="color:#f0f6fc;">Nothing secret about this path.</h2>
<div class="lesson">
    <div class="lesson-header">💡 A Lesson from Izaz and The PenTrix</div>
    Directory brute-forcing is a valid technique, but smart recon starts with what the application
    <em>tells</em> you. Check <code>robots.txt</code>, <code>sitemap.xml</code>, <code>security.txt</code>,
    HTML source comments, JavaScript files, and HTTP response headers. The breadcrumbs are already there.
</div>
<p><a href="/robots.txt">Start here →</a></p>
</body></html>""", 200, {'Content-Type': 'text/html'}

    # ═══════════════════════════════════════════════════════════
    # CTF SECRETS SECTION — 10 hidden secrets across 6 categories
    # Harder to find than regular flags. Require deep exploration.
    # ═══════════════════════════════════════════════════════════

    @app.route('/ctf/secrets')
    def ctf_secrets():
        """CTF Secrets section — 10 elite secrets across 6 categories."""
        if 'user_id' not in session:
            return redirect('/login')
        return render_template('challenges/secrets.html')

    # SECRET 1: Hidden in HTTP response header (Category: Headers)
    @app.after_request
    def add_secret_headers(response):
        # Only on specific routes to make it challenging
        if request.path == '/dashboard':
            response.headers['X-CTF-Secret-1'] = 'SECRET{header_whisperer_found_me}'
        if request.path == '/api/docs':
            response.headers['X-Hidden-Token'] = 'SECRET{api_docs_header_leak}'
        return response

    # SECRET 2: Hidden in cookie (Category: Cookies)
    @app.after_request
    def add_secret_cookies(response):
        if request.path == '/dashboard' and 'user_id' in session:
            import base64
            secret_data = base64.b64encode(b'SECRET{cookie_monster_decoded_this}').decode()
            response.set_cookie('_pentrix_session_debug', secret_data, httponly=False, samesite='None', secure=False)
        return response

    # SECRET 3: Hidden in source code comment (Category: Source Code)
    # (embedded in base.html template)

    # SECRET 4: Hidden endpoint requiring specific header (Category: Headers)
    @app.route('/api/v3/internal')
    def api_v3_internal():
        auth = request.headers.get('X-Internal-Auth')
        if auth == 'pentrix-internal-token':
            return jsonify({
                'status': 'authenticated',
                'secret': 'SECRET{internal_api_requires_custom_header}',
                'message': 'You found the v3 internal API. This requires the X-Internal-Auth header.'
            })
        return jsonify({'error': 'Unauthorized', 'hint': 'This endpoint requires internal authentication headers'}), 401

    # SECRET 5: Hidden in robots.txt disallowed path (Category: Recon)
    @app.route('/internal/archive')
    def internal_archive():
        return f"""<html><head><title>Archive</title>
<style>body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; padding:40px; }}</style></head><body>
<h1>📦 Internal Archive</h1>
<pre>
Archive Index — PenTrix Corp
============================
File: employee_records_2023.bak  [DELETED]
File: server_migration_notes.md  [DELETED]
File: secret_config_backup.txt   [AVAILABLE]

Contents of secret_config_backup.txt:
-------------------------------------
# Old configuration — do not use in production
SECRET{{archived_secrets_never_truly_deleted}}
DB_BACKUP_KEY=pentrix_backup_2024
LEGACY_API=http://internal:8080/legacy
</pre>
</body></html>""", 200, {'Content-Type': 'text/html'}

    # SECRET 6: Hidden in JavaScript console (Category: Client-Side)
    # (embedded in dashboard.js / base.html <script>)

    # SECRET 7: Hidden via timing — only available at specific "time" (Category: Logic)
    @app.route('/api/v2/health')
    def api_v2_health():
        from datetime import datetime
        # Secret appears when minute is even (or with debug param)
        show_secret = datetime.now().minute % 2 == 0 or request.args.get('debug') == 'true'
        result = {
            'status': 'healthy',
            'uptime': '72h 14m',
            'version': '2.3.3',
            'services': {'web': 'up', 'redis': 'up', 'internal': 'up'}
        }
        if show_secret:
            result['_debug_token'] = 'SECRET{timing_is_everything_in_recon}'
        return jsonify(result)

    # SECRET 8: Hidden in error response body (Category: Error Analysis)
    @app.route('/api/v2/admin')
    def api_v2_admin():
        """Returns a 403 with a secret in the error details."""
        return jsonify({
            'error': 'Forbidden',
            'code': 403,
            'details': 'Access restricted to admin role. Contact admin@pentrix.corp for access.',
            'trace_id': 'SECRET{forbidden_errors_leak_secrets}',
            'server': 'pentrix-web-01'
        }), 403

    # SECRET 9: Hidden in redirect chain (Category: Network)
    @app.route('/go/internal')
    def go_internal():
        return redirect('/go/step2')

    @app.route('/go/step2')
    def go_step2():
        return redirect('/go/final')

    @app.route('/go/final')
    def go_final():
        return f"""<html><head><title>End of Chain</title>
<style>body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; padding:40px; }}</style></head><body>
<h1>You followed the redirect chain!</h1>
<p>Most scanners don't follow redirect chains manually. You did.</p>
<pre>SECRET{{redirect_chain_persistence}}</pre>
</body></html>""", 200, {'Content-Type': 'text/html'}

    # SECRET 10: Hidden in a deeply nested JSON response (Category: API)
    @app.route('/api/v2/config')
    def api_v2_config():
        return jsonify({
            'app': {
                'name': 'PenTrix Corp Portal',
                'version': '2.3.3',
                'environment': {
                    'type': 'production',
                    'debug': False,
                    'features': {
                        'graphql': True,
                        'websocket': False,
                        'api_v3': True,
                        'internal': {
                            'enabled': True,
                            'services': ['web', 'redis', 'internal'],
                            'metadata': {
                                'last_deploy': '2024-03-15',
                                'deploy_key': 'SECRET{nested_json_treasure_hunter}',
                                'region': 'us-east-1'
                            }
                        }
                    }
                }
            }
        })

    # ═══════════════════════════════════════════════════════════
    # ENHANCED CHANGELOG — Immersive narrative with embedded clues
    # ═══════════════════════════════════════════════════════════

    # Override the existing changelog with a richer version
    @app.route('/changelog.html')
    def changelog_html():
        flag = get_flag('CH01-C09')
        return render_template('narrative/changelog.html', flag=flag)

    return app

# Create and run app
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

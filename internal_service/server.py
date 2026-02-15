"""
internal_service/server.py — SSRF Target Internal Service for The PenTrix
============================================================================
This is a deliberately insecure internal service running on port 8080.
It is NOT exposed to the host — only reachable from the Docker network.
Students discover it via SSRF vulnerabilities in the main web app.

INTENTIONALLY VULNERABLE — DO NOT DEPLOY IN PRODUCTION
"""
from flask import Flask, request, jsonify, Response
import os
import hmac
import hashlib
import json
import time
import subprocess
import socket

app = Flask(__name__)

INTERNAL_SECRET = os.environ.get('INTERNAL_SECRET', 'internal_flag_secret_2024')
FLAG_SECRET = os.environ.get('FLAG_SECRET', 'pentrix_lab_secret_2024')

# ── Meaningful flag names (must match the main app's flags.py) ──
MEANINGFUL_FLAGS = {
    'BONUS-SSRF-C01': 'flag{ssrf_localhost_internal}',
    'BONUS-SSRF-C02': 'flag{ssrf_metadata_service}',
    'BONUS-SSRF-C03': 'flag{ssrf_url_import_feature}',
    'BONUS-SSRF-C04': 'flag{blind_ssrf_webhook}',
    'BONUS-SSRF-C05': 'flag{ssrf_ip_encoding_bypass}',
    'BONUS-SSRF-C06': 'flag{ssrf_file_protocol_read}',
    'BONUS-SSRF-C07': 'flag{ssrf_redis_exploitation}',
    'BONUS-SSRF-C08': 'flag{ssrf_dns_rebinding}',
    'BONUS-SSRF-C09': 'flag{ssrf_admin_internal_port}',
    'BONUS-SSRF-C10': 'flag{ssrf_rce_chain_complete}',
}


def generate_flag(flag_id):
    """Generate a flag matching the main app's database values."""
    # Use the meaningful name if known (matches what's in the scoreboard DB)
    if flag_id in MEANINGFUL_FLAGS:
        return MEANINGFUL_FLAGS[flag_id]
    # Fallback for any unknown flag IDs
    digest = hmac.new(
        FLAG_SECRET.encode(),
        flag_id.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    parts = flag_id.replace('-', '_').split('_')
    return f"FLAG{{{parts[0]}_{parts[1]}_{digest}}}"


# ═══════════════════════════════════════
# ROOT — Service Status
# ═══════════════════════════════════════
@app.route('/')
def index():
    """
    Landing page for the internal service.
    Reaching this via SSRF yields BONUS-SSRF-C01.
    """
    flag = generate_flag('BONUS-SSRF-C01')
    return jsonify({
        'service': 'PenTrix Internal Service',
        'version': '1.0.0-internal',
        'status': 'running',
        'hostname': socket.gethostname(),
        'endpoints': [
            '/', '/admin', '/flag', '/metadata',
            '/redis-info', '/health', '/debug',
            '/internal/config', '/exec'
        ],
        'flag': flag,
        'message': 'Congratulations! You accessed the internal service via SSRF.'
    })


# ═══════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════
@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'uptime': time.time()})


# ═══════════════════════════════════════
# METADATA — Cloud Metadata Mock (BONUS-SSRF-C02)
# ═══════════════════════════════════════
@app.route('/metadata')
@app.route('/latest/meta-data/')
@app.route('/computeMetadata/v1/')
def metadata():
    """
    Mimics a cloud metadata endpoint (AWS/GCP style).
    SSRF to this endpoint yields BONUS-SSRF-C02.
    """
    flag = generate_flag('BONUS-SSRF-C02')
    return jsonify({
        'instance-id': 'i-0abc123def456789',
        'instance-type': 't2.micro',
        'ami-id': 'ami-pentrix-internal',
        'hostname': 'ip-172-16-0-5.internal',
        'local-ipv4': '172.16.0.5',
        'public-ipv4': '203.0.113.42',
        'iam': {
            'security-credentials': {
                'role-name': 'PenTrixInternalRole',
                'access-key-id': 'AKIAPENTRIXFAKEKEY123',
                'secret-access-key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYPENTRIXFAKE',
                'token': 'FwoGZXIvYXdzEBYaDFake...',
                'expiration': '2025-12-31T23:59:59Z'
            }
        },
        'flag': flag,
        'message': 'Cloud metadata accessed via SSRF!'
    })


@app.route('/latest/meta-data/iam/security-credentials/')
def metadata_iam():
    """Sub-path of the metadata service for realistic cloud simulation."""
    return Response('PenTrixInternalRole\n', mimetype='text/plain')


@app.route('/latest/meta-data/iam/security-credentials/PenTrixInternalRole')
def metadata_iam_role():
    """Returns fake IAM credentials — realistic SSRF target."""
    flag = generate_flag('BONUS-SSRF-C02')
    return jsonify({
        'Code': 'Success',
        'LastUpdated': '2024-01-15T00:00:00Z',
        'Type': 'AWS-HMAC',
        'AccessKeyId': 'AKIAPENTRIXFAKEKEY123',
        'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYPENTRIXFAKE',
        'Token': 'FwoGZXIvYXdzEBYaDFakeTokenHere...',
        'Expiration': '2025-12-31T23:59:59Z',
        'flag': flag
    })


# ═══════════════════════════════════════
# FLAG ENDPOINT
# ═══════════════════════════════════════
@app.route('/flag')
def flag_endpoint():
    """Direct flag endpoint — reachable from SSRF."""
    return jsonify({
        'flag': generate_flag('BONUS-SSRF-C01'),
        'message': 'You found the internal flag endpoint!'
    })


# ═══════════════════════════════════════
# REDIS INFO (BONUS-SSRF-C07)
# ═══════════════════════════════════════
@app.route('/redis-info')
def redis_info():
    """
    Exposes Redis connection details.
    Student can use SSRF to discover this, then chain with Redis exploitation.
    """
    flag = generate_flag('BONUS-SSRF-C07')
    
    # Try to actually get Redis info
    redis_data = {
        'host': 'redis',
        'port': 6379,
        'url': 'redis://redis:6379/0',
        'password': None,
        'info': 'Redis is running without authentication on the internal network'
    }
    
    try:
        import redis
        r = redis.Redis(host='redis', port=6379, decode_responses=True)
        r.set('pentrix_internal_flag', flag)
        redis_data['connected'] = True
        redis_data['keys'] = r.keys('*')
    except Exception as e:
        redis_data['connected'] = False
        redis_data['error'] = str(e)
    
    return jsonify({
        'redis': redis_data,
        'flag': flag,
        'hint': 'Try connecting to redis://redis:6379 from the main app via SSRF'
    })


# ═══════════════════════════════════════
# ADMIN PANEL (BONUS-SSRF-C09)
# ═══════════════════════════════════════
@app.route('/admin')
def admin_panel():
    """
    Internal admin panel — only accessible from inside the network.
    SSRF to reach this yields BONUS-SSRF-C09.
    """
    flag = generate_flag('BONUS-SSRF-C09')
    
    # Check if "authenticated" via internal header
    auth = request.headers.get('X-Internal-Auth', '')
    
    return f"""
    <html>
    <head><title>PenTrix Internal Admin</title></head>
    <body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
        <h1 style="color:#238636;">🔒 Internal Admin Panel</h1>
        <p>This panel is only accessible from the internal network.</p>
        <hr style="border-color:#30363d;">
        
        <h2>System Information</h2>
        <pre>
Hostname: {socket.gethostname()}
Internal IP: {socket.gethostbyname(socket.gethostname())}
Service Port: 8080
Redis Host: redis:6379
Web App Host: web:5000
        </pre>
        
        <h2>Internal Users Database</h2>
        <table border="1" cellpadding="8" style="border-collapse:collapse;border-color:#30363d;">
            <tr style="background:#161b22;">
                <th>Username</th><th>Role</th><th>Secret</th>
            </tr>
            <tr><td>admin</td><td>superadmin</td><td>admin_secret_key_2024</td></tr>
            <tr><td>system</td><td>service</td><td>svc_internal_token_xyz</td></tr>
            <tr><td>backup</td><td>automation</td><td>backup_cron_secret</td></tr>
        </table>
        
        <h2>Internal API Keys</h2>
        <pre>
INTERNAL_SECRET: {INTERNAL_SECRET}
API_KEY: sk-pentrix-internal-key-9876
JWT_SECRET: super_secret_key_12345
REDIS_URL: redis://redis:6379/0
        </pre>
        
        <h2>🏁 Flag</h2>
        <pre style="color:#238636;font-size:18px;">{flag}</pre>
        <p>You accessed the internal admin panel via SSRF!</p>
    </body>
    </html>
    """


# ═══════════════════════════════════════
# DEBUG ENDPOINT
# ═══════════════════════════════════════
@app.route('/debug')
def debug():
    """Exposes environment variables and system info."""
    return jsonify({
        'env': {k: v for k, v in os.environ.items()},
        'hostname': socket.gethostname(),
        'cwd': os.getcwd(),
        'user': os.popen('whoami').read().strip(),
        'ip': socket.gethostbyname(socket.gethostname())
    })


# ═══════════════════════════════════════
# INTERNAL CONFIG (bonus discovery)
# ═══════════════════════════════════════
@app.route('/internal/config')
def internal_config():
    """Exposes internal configuration — reachable via SSRF."""
    return jsonify({
        'database': {
            'path': '/app/data/pentrix.db',
            'type': 'sqlite'
        },
        'redis': {
            'host': 'redis',
            'port': 6379,
            'password': None
        },
        'secrets': {
            'jwt_secret': 'super_secret_key_12345',
            'api_key': 'sk-pentrix-internal-key-9876',
            'internal_secret': INTERNAL_SECRET,
            'flag_secret': FLAG_SECRET
        },
        'services': {
            'web': 'http://web:5000',
            'internal': 'http://internal:8080',
            'redis': 'redis://redis:6379/0'
        }
    })


# ═══════════════════════════════════════
# EXEC ENDPOINT — RCE via SSRF chain (BONUS-SSRF-C10)
# ═══════════════════════════════════════
@app.route('/exec', methods=['GET', 'POST'])
def exec_endpoint():
    """
    Command execution endpoint on the internal service.
    Student chains SSRF + this endpoint for BONUS-SSRF-C10.
    """
    cmd = request.args.get('cmd', request.form.get('cmd', ''))
    
    if not cmd:
        flag = generate_flag('BONUS-SSRF-C10')
        return jsonify({
            'service': 'Internal Command Executor',
            'usage': 'GET /exec?cmd=<command> or POST with cmd parameter',
            'warning': 'This endpoint accepts arbitrary commands!',
            'flag': flag,
            'hint': 'Chain SSRF to reach this endpoint and execute commands'
        })
    
    # INTENTIONALLY VULNERABLE: executes arbitrary commands
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        flag = generate_flag('BONUS-SSRF-C10')
        return jsonify({
            'command': cmd,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'flag': flag
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ═══════════════════════════════════════
# SECRET FILES — Discoverable via SSRF
# ═══════════════════════════════════════
@app.route('/secret')
@app.route('/secret.txt')
def secret_file():
    """Hidden secret file on internal service."""
    return Response(
        f"INTERNAL SECRET DOCUMENT\n"
        f"========================\n"
        f"Database credentials: admin/admin\n"
        f"API Key: sk-pentrix-internal-key-9876\n"
        f"Internal Token: {INTERNAL_SECRET}\n"
        f"Redis: redis://redis:6379/0 (no auth)\n"
        f"\nFlag: {generate_flag('BONUS-SSRF-C01')}\n",
        mimetype='text/plain'
    )


# ═══════════════════════════════════════
# SALARY REPORT — Scenario B Target
# ═══════════════════════════════════════
@app.route('/reports/salary')
def salary_report():
    """
    Internal salary report — target of Scenario B (Data Heist).
    Student chains API IDOR + SSRF to access this.
    """
    return jsonify({
        'report': 'Internal Salary Report Q4 2024',
        'classification': 'CONFIDENTIAL',
        'employees': [
            {'name': 'Alice Johnson', 'role': 'Senior Developer', 'salary': 145000},
            {'name': 'Bob Smith', 'role': 'QA Engineer', 'salary': 98000},
            {'name': 'Charlie Brown', 'role': 'DevOps Lead', 'salary': 135000},
            {'name': 'Diana Prince', 'role': 'CTO', 'salary': 210000},
            {'name': 'Eve Adams', 'role': 'Security Analyst', 'salary': 125000},
        ],
        'total_payroll': 713000,
        'flag': generate_flag('BONUS-SSRF-C09'),
        'note': 'This report should only be accessible from the internal network.'
    })


# ═══════════════════════════════════════
# GOPHER/RAW TCP SIMULATION
# ═══════════════════════════════════════
@app.route('/redis-cmd')
def redis_cmd():
    """
    Shows how to interact with Redis via SSRF.
    Provides gopher:// payload hints for BONUS-SSRF-C07.
    """
    flag = generate_flag('BONUS-SSRF-C07')
    return jsonify({
        'redis_host': 'redis',
        'redis_port': 6379,
        'example_gopher_payloads': [
            'gopher://redis:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a',
            'gopher://redis:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0aflag%0d%0a$4%0d%0atest%0d%0a',
            'gopher://redis:6379/_*1%0d%0a$4%0d%0aKEYS%0d%0a*%0d%0a',
        ],
        'flag': flag,
        'hint': 'Use SSRF with gopher:// protocol to send raw commands to Redis'
    })


# ═══════════════════════════════════════
# DNS REBINDING INFO (BONUS-SSRF-C08)
# ═══════════════════════════════════════
@app.route('/dns-info')
def dns_info():
    """Provides info useful for DNS rebinding attack."""
    flag = generate_flag('BONUS-SSRF-C08')
    return jsonify({
        'internal_ip': socket.gethostbyname(socket.gethostname()),
        'service_port': 8080,
        'hint': 'Use a DNS rebinding service to resolve to the internal IP',
        'tools': [
            'rbndr.us - DNS rebinding tool',
            'rebind.network - Automated DNS rebinding',
            'Use your-ip.internal-ip.rbndr.us format'
        ],
        'flag': flag
    })


# ═══════════════════════════════════════
# CATCH-ALL — Log SSRF attempts
# ═══════════════════════════════════════
@app.route('/<path:path>')
def catch_all(path):
    """Log and respond to any SSRF probing."""
    return jsonify({
        'path': f'/{path}',
        'method': request.method,
        'message': f'Internal service received request to /{path}',
        'known_endpoints': [
            '/', '/admin', '/flag', '/metadata', '/redis-info',
            '/health', '/debug', '/internal/config', '/exec',
            '/secret', '/reports/salary', '/redis-cmd', '/dns-info'
        ]
    }), 404


# ═══════════════════════════════════════
if __name__ == '__main__':
    print("=" * 60)
    print("  PenTrix Internal Service v1.0")
    print("  Running on port 8080 (internal only)")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8080, debug=False)

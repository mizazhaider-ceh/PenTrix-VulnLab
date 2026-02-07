"""
routes/api.py — API Vulnerabilities (CH14, CH15, CH07)
═══════════════════════════════════════════════════════
REST API, GraphQL mock, CORS demos, rate limit bypass.
"""
import json
import time
from flask import Blueprint, request, jsonify, session, g
from db import get_db
from flags import get_flag

api_bp = Blueprint('api', __name__)

# ═══════════════════════════════════════
# Simple rate-limit state (in-memory, per-IP)
# ═══════════════════════════════════════
_rate_limit_store = {}  # ip -> [timestamps]

def check_rate_limit(ip, limit=10, window=60):
    """
    [VULN: CH14-C09] Rate limit based on IP only — bypassable via X-Forwarded-For header
    """
    now = time.time()
    key = request.headers.get('X-Forwarded-For', ip)  # [VULN] trusts proxy header
    
    if key not in _rate_limit_store:
        _rate_limit_store[key] = []
    
    # Clean old entries
    _rate_limit_store[key] = [t for t in _rate_limit_store[key] if now - t < window]
    
    if len(_rate_limit_store[key]) >= limit:
        return False
    
    _rate_limit_store[key].append(now)
    return True


# ═══════════════════════════════════════
# /api/users — List all users (UNAUTHENTICATED)
# ═══════════════════════════════════════
@api_bp.route('/api/users')
def api_list_users():
    """
    [VULN: CH14-C01] No authentication required to list users
    [VULN: CH14-C04] Returns ALL fields including sensitive data
    """
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
    
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    
    # [VULN: CH14-C04] Excessive data exposure — returns passwords, SSN, salary
    user_list = []
    for u in users:
        user_list.append({
            'id': u['id'],
            'username': u['username'],
            'email': u['email'],
            'password': u['password'],  # [VULN] plaintext password exposed
            'role': u['role'],
            'salary': u['salary'],      # [VULN] sensitive data
            'ssn': u['ssn'],            # [VULN] sensitive data
            'is_active': u['is_active'],
            'created_at': u['created_at'],
            'reset_token': u['reset_token'],  # [VULN] token exposed
            'flag': get_flag('CH14-C01')
        })
    
    return jsonify({
        'users': user_list,
        'total': len(user_list),
        'flag_unauthenticated': get_flag('CH14-C01'),
        'flag_excessive_data': get_flag('CH14-C04')
    })


# ═══════════════════════════════════════
# /api/users/<id> — Get single user by ID (IDOR)
# ═══════════════════════════════════════
@api_bp.route('/api/users/<int:user_id>')
def api_get_user(user_id):
    """
    [VULN: CH14-C05] API IDOR — any user can access any other user's data
    """
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # [VULN: CH14-C05] No authorization check — any user's data returned
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'password': user['password'],
        'role': user['role'],
        'salary': user['salary'],
        'ssn': user['ssn'],
        'is_active': user['is_active'],
        'created_at': user['created_at'],
        'api_flag': get_flag('CH14-C05')
    })


# ═══════════════════════════════════════
# PATCH /api/users/<id> — Update user (Mass Assignment + BOLA)
# ═══════════════════════════════════════
@api_bp.route('/api/users/<int:user_id>', methods=['PATCH'])
def api_update_user(user_id):
    """
    [VULN: CH14-C03] Mass assignment — accepts any field including role
    [VULN: CH14-C06] Broken object-level authorization — no owner check
    [VULN: CH14-C10] JSON body injection to escalate privileges
    """
    # [VULN: CH14-C06] No check if logged-in user owns this profile
    data = request.get_json(force=True, silent=True) or {}
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # [VULN: CH14-C03] Mass assignment — blindly updates ANY field from JSON body
    allowed_update_fields = ['username', 'email', 'password', 'role', 'salary', 'ssn', 'is_active']
    updates = []
    values = []
    flags_earned = []
    
    for field in allowed_update_fields:
        if field in data:
            updates.append(f"{field} = ?")
            values.append(data[field])
            
            # Track what was mass-assigned
            if field == 'role':
                flags_earned.append({'flag_id': 'CH14-C03', 'flag': get_flag('CH14-C03'), 'reason': 'Mass assignment on role field'})
                flags_earned.append({'flag_id': 'CH14-C10', 'flag': get_flag('CH14-C10'), 'reason': 'JSON injection to escalate privileges'})
            if field == 'salary':
                flags_earned.append({'flag_id': 'CH14-C06', 'flag': get_flag('CH14-C06'), 'reason': 'Modified another user salary (BOLA)'})
    
    if updates:
        values.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        db.execute(query, values)
        db.commit()
    
    # Fetch updated user
    updated = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    
    return jsonify({
        'message': 'User updated successfully',
        'user': {
            'id': updated['id'],
            'username': updated['username'],
            'email': updated['email'],
            'role': updated['role'],
            'salary': updated['salary'],
        },
        'flags_earned': flags_earned if flags_earned else 'No privilege changes detected'
    })


# ═══════════════════════════════════════
# /api/v1/config — Deprecated API endpoint
# ═══════════════════════════════════════
@api_bp.route('/api/v1/config')
def api_v1_config():
    """
    [VULN: CH14-C07] Deprecated API still accessible — exposes internal config
    """
    return jsonify({
        'api_version': '1.0.0-DEPRECATED',
        'warning': 'This API version is deprecated. Use /api/v2/ instead.',
        'config': {
            'database': 'sqlite:////app/data/pentrix.db',
            'secret_key': 'super_secret_key_12345',   # [VULN] secret exposed
            'api_key': 'sk-pentrix-internal-key-9876', # [VULN] key exposed
            'internal_service': 'http://internal:8080',
            'redis_url': 'redis://pentrix_redis:6379',
            'debug': True,
            'flag_secret': 'pentrix_lab_secret_2024'   # [VULN] master secret
        },
        'flag': get_flag('CH14-C07')
    })


# ═══════════════════════════════════════
# /api/v2/internal — Hidden internal API
# ═══════════════════════════════════════
@api_bp.route('/api/v2/internal')
def api_v2_internal():
    """
    [VULN: CH07-C05] Hidden endpoint discoverable via version fuzzing
    Returns internal data including salary reports
    """
    db = get_db()
    users = db.execute('SELECT username, salary, ssn, role FROM users').fetchall()
    
    salary_report = []
    for u in users:
        salary_report.append({
            'username': u['username'],
            'salary': u['salary'],
            'ssn': u['ssn'],
            'role': u['role']
        })
    
    return jsonify({
        'endpoint': '/api/v2/internal',
        'classification': 'CONFIDENTIAL',
        'salary_report': salary_report,
        'flag': get_flag('CH07-C05'),
        'note': 'This endpoint was supposed to be internal-only.'
    })


# ═══════════════════════════════════════
# /api/graphql — GraphQL mock with introspection
# ═══════════════════════════════════════
@api_bp.route('/api/graphql', methods=['GET', 'POST'])
def api_graphql():
    """
    [VULN: CH14-C08] GraphQL introspection enabled — reveals hidden queries/mutations
    """
    if request.method == 'GET':
        return jsonify({
            'message': 'PenTrix GraphQL Endpoint',
            'usage': 'POST a JSON body with "query" field',
            'hint': 'Try introspection: {"query": "{ __schema { types { name fields { name } } } }"}',
        })
    
    data = request.get_json(force=True, silent=True) or {}
    query = data.get('query', '')
    
    # Minimal GraphQL-like mock
    if '__schema' in query or '__type' in query:
        # [VULN: CH14-C08] Introspection reveals hidden schema
        return jsonify({
            'data': {
                '__schema': {
                    'types': [
                        {
                            'name': 'Query',
                            'fields': [
                                {'name': 'users', 'description': 'List all users (no auth needed)'},
                                {'name': 'user', 'args': [{'name': 'id'}], 'description': 'Get user by ID'},
                                {'name': 'secretFlags', 'description': 'HIDDEN: Returns all challenge flags'},
                                {'name': 'internalConfig', 'description': 'HIDDEN: Returns app configuration'},
                                {'name': 'salaryReport', 'description': 'HIDDEN: All employee salaries'},
                                {'name': 'adminActions', 'description': 'HIDDEN: Administrative operations'}
                            ]
                        },
                        {
                            'name': 'Mutation',
                            'fields': [
                                {'name': 'updateUser', 'args': [{'name': 'id'}, {'name': 'role'}]},
                                {'name': 'deleteUser', 'args': [{'name': 'id'}]},
                                {'name': 'promoteToAdmin', 'args': [{'name': 'username'}]},
                                {'name': 'resetAllPasswords', 'description': 'HIDDEN: Mass password reset'}
                            ]
                        },
                        {
                            'name': 'User',
                            'fields': [
                                {'name': 'id'}, {'name': 'username'}, {'name': 'email'},
                                {'name': 'password'}, {'name': 'role'}, {'name': 'salary'},
                                {'name': 'ssn'}, {'name': 'apiKey'}, {'name': 'resetToken'}
                            ]
                        }
                    ]
                }
            },
            'flag': get_flag('CH14-C08')
        })
    
    elif 'secretFlags' in query:
        db = get_db()
        flags = db.execute('SELECT flag_id, flag_value, description FROM flags').fetchall()
        return jsonify({
            'data': {
                'secretFlags': [{'id': f['flag_id'], 'value': f['flag_value'], 'desc': f['description']} for f in flags]
            }
        })
    
    elif 'internalConfig' in query:
        return jsonify({
            'data': {
                'internalConfig': {
                    'secretKey': 'super_secret_key_12345',
                    'flagSecret': 'pentrix_lab_secret_2024',
                    'dbPath': '/app/data/pentrix.db',
                    'internalUrl': 'http://internal:8080',
                    'redisUrl': 'redis://pentrix_redis:6379'
                }
            }
        })
    
    elif 'salaryReport' in query:
        db = get_db()
        users = db.execute('SELECT username, salary, ssn FROM users').fetchall()
        return jsonify({
            'data': {
                'salaryReport': [{'username': u['username'], 'salary': u['salary'], 'ssn': u['ssn']} for u in users]
            }
        })
    
    elif 'users' in query:
        db = get_db()
        users = db.execute('SELECT id, username, email, role FROM users').fetchall()
        return jsonify({
            'data': {
                'users': [dict(u) for u in users]
            }
        })
    
    else:
        return jsonify({
            'errors': [{'message': f'Unrecognized query: {query}'}],
            'hint': 'Try introspection first to discover available queries'
        }), 400


# ═══════════════════════════════════════
# /api/rate-test — Rate limit bypass demo
# ═══════════════════════════════════════
@api_bp.route('/api/rate-test')
def api_rate_test():
    """
    [VULN: CH14-C09] Rate limit bypass via X-Forwarded-For header manipulation
    """
    ip = request.remote_addr
    xff = request.headers.get('X-Forwarded-For', '')
    effective_ip = xff if xff else ip
    
    if not check_rate_limit(ip):
        return jsonify({
            'error': 'Rate limit exceeded (10 requests per 60 seconds)',
            'your_ip': ip,
            'hint': 'The rate limiter trusts the X-Forwarded-For header...',
            'bypass_hint': 'Try adding X-Forwarded-For: <random-ip> header'
        }), 429
    
    return jsonify({
        'message': 'Request successful',
        'effective_ip': effective_ip,
        'requests_info': f'Rate limiting based on IP: {effective_ip}',
        'flag': get_flag('CH14-C09')
    })


# ═══════════════════════════════════════
# /api/key/verify — API key verification
# ═══════════════════════════════════════
@api_bp.route('/api/key/verify')
def api_key_verify():
    """
    [VULN: CH14-C02] API key discoverable in JS source (see /static/js/app.js)
    """
    api_key = request.headers.get('X-API-Key', '')
    
    if api_key == 'sk-pentrix-internal-key-9876':
        return jsonify({
            'message': 'API key valid',
            'access': 'full',
            'flag': get_flag('CH14-C02')
        })
    
    return jsonify({
        'error': 'Invalid or missing API key',
        'hint': 'Find the API key in the application JavaScript source'
    }), 401


# ═══════════════════════════════════════
# /api/private/export — CORS misconfigured private endpoint
# ═══════════════════════════════════════
@api_bp.route('/api/private/export')
def api_private_export():
    """
    [VULN: CH15-C10] Sensitive export endpoint with CORS misconfiguration
    [VULN: CH15-C01] Wildcard CORS allows reading from any origin
    [VULN: CH15-C02] Origin reflection trusts any origin
    [VULN: CH15-C04] Credentials sent with CORS
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    db = get_db()
    user_id = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    
    # Sensitive data export
    return jsonify({
        'export_type': 'private_user_data',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'salary': user['salary'],
            'ssn': user['ssn'],
            'password': user['password'],  # [VULN] password in export
        },
        'api_keys': [{'note': 'Exported via CORS-vulnerable endpoint'}],
        'cors_flags': {
            'CH15-C01': get_flag('CH15-C01'),
            'CH15-C02': get_flag('CH15-C02'),
            'CH15-C04': get_flag('CH15-C04'),
            'CH15-C10': get_flag('CH15-C10')
        }
    })


# ═══════════════════════════════════════
# /api/cors/test — CORS testing endpoint
# ═══════════════════════════════════════
@api_bp.route('/api/cors/test')
def api_cors_test():
    """
    [VULN: CH15-C03] null origin allowed
    [VULN: CH15-C05] Subdomain prefixed origin trusted
    [VULN: CH15-C07] Simple GET request bypasses pre-flight
    [VULN: CH15-C08] Internal API exploitable via CORS
    [VULN: CH15-C09] Weak origin whitelist validation
    """
    origin = request.headers.get('Origin', 'none')
    
    # [VULN: CH15-C03] null origin accepted
    # [VULN: CH15-C05] Any origin containing 'pentrix' is trusted
    # [VULN: CH15-C09] Regex bypass — evil.pentrix.com would match
    trusted = False
    if origin == 'null':
        trusted = True  # [VULN: CH15-C03] sandboxed iframe exploitation
    elif 'pentrix' in origin.lower():
        trusted = True  # [VULN: CH15-C05/C09] weak domain validation
    elif origin != 'none':
        trusted = True  # [VULN: CH15-C02] reflects everything anyway
    
    flags = {}
    if origin == 'null':
        flags['CH15-C03'] = get_flag('CH15-C03')
    if 'pentrix' in origin.lower() and origin != f"http://localhost:5000":
        flags['CH15-C05'] = get_flag('CH15-C05')
    if origin != 'none':
        flags['CH15-C02'] = get_flag('CH15-C02')
        flags['CH15-C07'] = get_flag('CH15-C07')
        flags['CH15-C08'] = get_flag('CH15-C08')
        flags['CH15-C09'] = get_flag('CH15-C09')
    
    return jsonify({
        'endpoint': '/api/cors/test',
        'your_origin': origin,
        'trusted': trusted,
        'cors_headers_reflected': True,
        'sensitive_data': {
            'internal_api_url': 'http://internal:8080',
            'redis_url': 'redis://pentrix_redis:6379',
            'db_path': '/app/data/pentrix.db'
        },
        'flags': flags if flags else 'Send a request with an Origin header to test CORS'
    })


# ═══════════════════════════════════════
# /api/cors/steal — CORS + CSRF chain demo
# ═══════════════════════════════════════
@api_bp.route('/api/cors/steal')
def api_cors_steal():
    """
    [VULN: CH15-C06] CORS + CSRF chain — read user data cross-origin with credentials
    """
    if 'user_id' not in session:
        return jsonify({
            'error': 'Must be logged in',
            'hint': 'This endpoint demonstrates CORS+CSRF chain — login first, then access from a different origin with credentials'
        }), 401
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', [session['user_id']]).fetchone()
    
    return jsonify({
        'stolen_data': {
            'username': user['username'],
            'email': user['email'],
            'password': user['password'],
            'role': user['role'],
            'ssn': user['ssn'],
            'salary': user['salary']
        },
        'flag': get_flag('CH15-C06')
    })


# ═══════════════════════════════════════
# /api/reports/<id> — Report access via IDOR (Scenario B)
# ═══════════════════════════════════════
@api_bp.route('/api/reports/<int:report_id>')
def api_get_report(report_id):
    """
    Used in Scenario B — "Data Heist"
    [VULN: CH03-C01] IDOR on report ID
    """
    # Simulated reports
    reports = {
        1: {'title': 'Q1 Financial Summary', 'data': 'Revenue: $2.3M, Expenses: $1.8M', 'classification': 'public'},
        2: {'title': 'Employee Salary Report', 'data': 'See /api/v2/internal for full data', 'classification': 'confidential'},
        3: {'title': 'Security Audit Results', 'data': 'Multiple critical vulnerabilities found. See internal ticket #42.', 'classification': 'top-secret'},
        4: {'title': 'Credentials Backup', 'data': 'admin:admin, hr_manager:hr2024, See /api/users for full list', 'classification': 'top-secret', 'flag': get_flag('SCENARIO-B')},
    }
    
    report = reports.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found', 'hint': 'Try report IDs 1-4'}), 404
    
    return jsonify(report)


# ═══════════════════════════════════════
# /api/docs — OpenAPI / Swagger documentation
# ═══════════════════════════════════════
@api_bp.route('/api/docs')
def api_docs():
    """Exposes API documentation — helps with discovery"""
    return jsonify({
        'openapi': '3.0.0',
        'info': {
            'title': 'PenTrix Internal API',
            'version': '2.0.0',
            'description': 'Internal API for PenTrix Corp portal'
        },
        'paths': {
            '/api/users': {'get': {'summary': 'List all users (NO AUTH REQUIRED)', 'tags': ['Users']}},
            '/api/users/{id}': {
                'get': {'summary': 'Get user by ID', 'tags': ['Users']},
                'patch': {'summary': 'Update user fields (mass assignment vulnerable)', 'tags': ['Users']}
            },
            '/api/v1/config': {'get': {'summary': 'Deprecated config endpoint', 'tags': ['Config']}},
            '/api/v2/internal': {'get': {'summary': 'Internal salary data', 'tags': ['Internal']}},
            '/api/graphql': {'post': {'summary': 'GraphQL endpoint with introspection', 'tags': ['GraphQL']}},
            '/api/rate-test': {'get': {'summary': 'Rate limit test', 'tags': ['Testing']}},
            '/api/key/verify': {'get': {'summary': 'Verify API key', 'tags': ['Auth']}},
            '/api/private/export': {'get': {'summary': 'Export private user data', 'tags': ['Export']}},
            '/api/cors/test': {'get': {'summary': 'CORS configuration test', 'tags': ['CORS']}},
            '/api/cors/steal': {'get': {'summary': 'CORS+CSRF chain demo', 'tags': ['CORS']}},
            '/api/reports/{id}': {'get': {'summary': 'Access reports by ID', 'tags': ['Reports']}},
        }
    })

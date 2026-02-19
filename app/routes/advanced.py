"""
routes/advanced.py — Advanced Exploitation Challenges
═══════════════════════════════════════════════════════
Professional-grade vulnerabilities that mirror real-world
findings from bug bounties and red team engagements.

Categories:
  • Race Conditions (TOCTOU)
  • JWT Key Confusion
  • Prototype Pollution (simulated)
  • Business Logic Chains
  • Type Juggling
  • Mass Assignment Escalation
  • HTTP Request Smuggling Hints
  • GraphQL Depth/Batch Attacks
"""
import json
import time
import hashlib
import threading
from functools import wraps
from flask import Blueprint, request, jsonify, session
from db import get_db
from flags import get_flag

advanced_bp = Blueprint('advanced', __name__)


# ═══════════════════════════════════════
# RACE CONDITION — Double-Spend on Transfer
# ═══════════════════════════════════════

# Shared lock that is intentionally NOT used properly
_transfer_lock = threading.Lock()

@advanced_bp.route('/api/transfer', methods=['POST'])
def race_transfer():
    """
    [VULN: CH17-C01] TOCTOU Race Condition — Transfer Money
    
    The balance check and balance update are NOT atomic.
    Send two concurrent POST requests with the same amount
    to drain more money than the account holds.
    
    Exploit:
      for i in $(seq 1 10); do
        curl -X POST /api/transfer -d 'to=bob&amount=900' -b 'session=...' &
      done
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    to_user = request.form.get('to', request.json.get('to', '') if request.is_json else '')
    try:
        amount = float(request.form.get('amount', request.json.get('amount', 0) if request.is_json else 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400
    
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    
    db = get_db()
    
    # [VULN] Check balance (TOCTOU — balance can change between check and update)
    sender = db.execute('SELECT * FROM users WHERE id = ?', [session['user_id']]).fetchone()
    if not sender:
        return jsonify({'error': 'User not found'}), 404
    
    if sender['balance'] < amount:
        return jsonify({'error': 'Insufficient funds', 'balance': sender['balance']}), 400
    
    recipient = db.execute('SELECT * FROM users WHERE username = ?', [to_user]).fetchone()
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # [VULN] Artificial delay between check and update — widens the race window
    time.sleep(0.15)
    
    # Debit sender, credit recipient (not atomic — race condition!)
    db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, session['user_id']])
    db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, recipient['id']])
    db.commit()
    
    # Check if balance went negative (means race was exploited)
    updated = db.execute('SELECT balance FROM users WHERE id = ?', [session['user_id']]).fetchone()
    flag = None
    if updated['balance'] < 0:
        flag = get_flag('CH17-C01')
    
    return jsonify({
        'success': True,
        'transferred': amount,
        'new_balance': updated['balance'],
        'flag': flag
    })


# ═══════════════════════════════════════
# RACE CONDITION — Coupon Double-Use
# ═══════════════════════════════════════

@advanced_bp.route('/api/coupon/race', methods=['POST'])
def race_coupon():
    """
    [VULN: CH17-C02] Race Condition on Single-Use Coupon
    
    A single-use coupon can be redeemed multiple times
    by sending parallel requests before the first one commits.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    code = request.form.get('code', request.json.get('code', '') if request.is_json else '')
    db = get_db()
    
    coupon = db.execute('SELECT * FROM coupons WHERE code = ?', [code]).fetchone()
    if not coupon or coupon['uses_left'] <= 0:
        return jsonify({'error': 'Invalid or expired coupon'}), 400
    
    # [VULN] Window of opportunity — read-then-write without lock
    time.sleep(0.2)
    
    db.execute('UPDATE coupons SET uses_left = uses_left - 1 WHERE code = ?', [code])
    db.execute('UPDATE users SET balance = balance + ? WHERE id = ?',
               [coupon['discount'], session['user_id']])
    db.commit()
    
    user = db.execute('SELECT balance FROM users WHERE id = ?', [session['user_id']]).fetchone()
    flag = get_flag('CH17-C02')
    
    return jsonify({
        'redeemed': True,
        'discount': coupon['discount'],
        'balance': user['balance'],
        'flag': flag
    })


# ═══════════════════════════════════════
# JWT KEY CONFUSION — Algorithm Switching
# ═══════════════════════════════════════

@advanced_bp.route('/api/jwt/public-key')
def jwt_public_key():
    """
    [VULN: CH17-C03] JWT Key Confusion — Public Key Endpoint
    
    The /api/token/verify endpoint accepts HS256 tokens.
    If you use THIS public key as the HS256 secret, you can
    forge tokens — classic RS256 → HS256 key confusion attack.
    """
    # Fake RSA public key (in a real scenario this would be the actual pub key)
    public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8MFXJ3JRVDM35BK0AE
k3xRkLPcWJnz7FPHEV3GpG0xXFN0XLJsgjXR5MEPyRy7MBFtHLoBzKFN8CnP6ld
h5X8sigdARJhGFywz7ELTM7y3X9KFQNpqQgPhU8CFdEAZxJt0Ccm4s2BkYyGAFVM
iY9kJhDJiH2a3eT0LnnNy5PcA6WHBHKWX8fMJkjcVaHG3OfDAPR8MWsr5JG5RA9
VXxJiX89Dh06sdJKGFhE1IrfMKNjGxAT0YNHP9d4X8iRBv5zzN3CT25Y7xHk1q9E
NjRrVlq+3iRMGM/pDjKS7TewMrR+jQ+R66JClJ2Z6m7hs2Dd7oTqJBSxFIDJVXVi
+wIDAQAB
-----END PUBLIC KEY-----"""
    
    flag = get_flag('CH17-C03')
    return jsonify({
        'algorithm': 'RS256',
        'public_key': public_key,
        'note': 'Use this to verify our JWT tokens',
        'flag': flag
    })


@advanced_bp.route('/api/jwt/verify-advanced', methods=['POST'])
def jwt_verify_advanced():
    """
    [VULN: CH17-C03] JWT Algorithm Confusion Verification
    
    Accepts both RS256 and HS256. If HS256 is used with
    the public key as secret, the signature will validate — 
    this is the key confusion attack.
    """
    token = request.form.get('token', request.json.get('token', '') if request.is_json else '')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    try:
        import jwt as pyjwt
        # [VULN] Accepts multiple algorithms — allows HS256 with public key
        public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8MFXJ3JRVDM35BK0AE
k3xRkLPcWJnz7FPHEV3GpG0xXFN0XLJsgjXR5MEPyRy7MBFtHLoBzKFN8CnP6ld
h5X8sigdARJhGFywz7ELTM7y3X9KFQNpqQgPhU8CFdEAZxJt0Ccm4s2BkYyGAFVM
iY9kJhDJiH2a3eT0LnnNy5PcA6WHBHKWX8fMJkjcVaHG3OfDAPR8MWsr5JG5RA9
VXxJiX89Dh06sdJKGFhE1IrfMKNjGxAT0YNHP9d4X8iRBv5zzN3CT25Y7xHk1q9E
NjRrVlq+3iRMGM/pDjKS7TewMrR+jQ+R66JClJ2Z6m7hs2Dd7oTqJBSxFIDJVXVi
+wIDAQAB
-----END PUBLIC KEY-----"""
        
        # Try HS256 first (vulnerable!), then RS256
        try:
            decoded = pyjwt.decode(token, public_key, algorithms=['HS256', 'RS256'])
            flag = get_flag('CH17-C03')
            return jsonify({
                'valid': True,
                'decoded': decoded,
                'algorithm_used': 'accepted',
                'flag': flag,
                'message': 'Key confusion attack successful! HS256 accepted with public key.'
            })
        except pyjwt.InvalidSignatureError:
            return jsonify({'valid': False, 'error': 'Invalid signature'}), 401
        except pyjwt.DecodeError as e:
            return jsonify({'valid': False, 'error': str(e)}), 400
    except ImportError:
        return jsonify({'error': 'JWT library not available'}), 500


# ═══════════════════════════════════════
# BUSINESS LOGIC — Price Manipulation
# ═══════════════════════════════════════

STORE_ITEMS = {
    1: {'name': 'Basic Plan', 'price': 9.99},
    2: {'name': 'Pro Plan', 'price': 49.99},
    3: {'name': 'Enterprise Plan', 'price': 199.99},
    4: {'name': 'Secret Admin Tool', 'price': 999.99},
}

@advanced_bp.route('/api/store/items')
def store_items():
    """Product catalog for the business logic challenges."""
    return jsonify({'items': [
        {'id': k, 'name': v['name'], 'price': v['price']}
        for k, v in STORE_ITEMS.items()
    ]})


@advanced_bp.route('/api/store/purchase', methods=['POST'])
def store_purchase():
    """
    [VULN: CH17-C04] Business Logic — Client-Side Price Trust
    
    The server trusts the price sent by the client instead of
    looking it up from the catalog. Send price=0.01 to buy
    anything for almost nothing.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    item_id = request.form.get('item_id', request.json.get('item_id', 0) if request.is_json else 0)
    # [VULN] Server trusts client-supplied price
    price = request.form.get('price', request.json.get('price', None) if request.is_json else None)
    quantity = request.form.get('quantity', request.json.get('quantity', 1) if request.is_json else 1)
    
    try:
        item_id = int(item_id)
        quantity = int(quantity)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid parameters'}), 400
    
    item = STORE_ITEMS.get(item_id)
    if not item:
        return jsonify({'error': 'Item not found'}), 404
    
    # [VULN: CH17-C04] Use client price if provided, otherwise server price
    if price is not None:
        try:
            actual_price = float(price)
        except (ValueError, TypeError):
            actual_price = item['price']
    else:
        actual_price = item['price']
    
    # [VULN: CH17-C05] Negative quantity — results in credit instead of debit
    total = actual_price * quantity
    
    db = get_db()
    user = db.execute('SELECT balance FROM users WHERE id = ?', [session['user_id']]).fetchone()
    
    if user['balance'] < total:
        return jsonify({'error': 'Insufficient funds', 'balance': user['balance']}), 400
    
    db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [total, session['user_id']])
    db.commit()
    
    updated = db.execute('SELECT balance FROM users WHERE id = ?', [session['user_id']]).fetchone()
    
    flags = []
    if price is not None and float(price) < item['price']:
        flags.append(get_flag('CH17-C04'))
    if quantity < 0:
        flags.append(get_flag('CH17-C05'))
    
    return jsonify({
        'purchased': item['name'],
        'quantity': quantity,
        'unit_price': actual_price,
        'total_charged': total,
        'new_balance': updated['balance'],
        'flags': flags if flags else None
    })


# ═══════════════════════════════════════
# TYPE JUGGLING — Authentication Bypass
# ═══════════════════════════════════════

@advanced_bp.route('/api/auth/verify-pin', methods=['POST'])
def verify_pin():
    """
    [VULN: CH17-C06] Type Juggling — PIN Verification Bypass
    
    The comparison uses == with type coercion in Python-like logic.
    Sending pin as integer 0 or boolean false or array might bypass.
    The real vuln: passing pin as JSON integer vs string comparison.
    """
    data = request.get_json(silent=True) or {}
    pin = data.get('pin')
    
    # The "correct" PIN
    correct_pin = '0847'
    
    # [VULN] Loose comparison — if pin is integer 847, '0847' != 847 but...
    # In Python, str(0) == '0' != '0847', but the real trick is:
    # sending {"pin": true} where bool comparison with non-empty string is truthy
    flag = None
    
    if pin is True:
        # [VULN] bool True bypasses truthiness check
        flag = get_flag('CH17-C06')
        return jsonify({'access': 'granted', 'flag': flag, 'message': 'Type juggling bypass!'})
    
    if isinstance(pin, str) and pin == correct_pin:
        return jsonify({'access': 'granted', 'message': 'Correct PIN'})
    
    if isinstance(pin, int) and str(pin) == correct_pin:
        return jsonify({'access': 'granted', 'message': 'Correct PIN (integer)'})
    
    return jsonify({'access': 'denied', 'message': 'Incorrect PIN'}), 403


# ═══════════════════════════════════════
# PARAMETER POLLUTION — Hidden Admin Param
# ═══════════════════════════════════════

@advanced_bp.route('/api/user/update', methods=['POST'])
def update_user_advanced():
    """
    [VULN: CH17-C07] HTTP Parameter Pollution + Mass Assignment
    
    The endpoint merges form data and JSON body. If both are sent,
    JSON takes priority — allowing an attacker to sneak in 'role=admin'
    via JSON body while the form only shows harmless fields.
    
    Also: duplicate parameter names in form data — last value wins.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Merge form data and JSON (JSON takes priority)
    data = {}
    if request.form:
        data.update(request.form.to_dict())
    if request.is_json:
        data.update(request.get_json(silent=True) or {})
    
    # Allow-list of "safe" fields (but the merge above already polluted data)
    safe_fields = ['display_name', 'email']
    
    db = get_db()
    
    # [VULN] Actually applies ALL fields from merged data, not just safe ones
    for key, value in data.items():
        if key in ('display_name', 'email', 'role', 'is_active', 'salary', 'balance'):
            db.execute(f'UPDATE users SET {key} = ? WHERE id = ?', [value, session['user_id']])
    
    db.commit()
    
    user = db.execute('SELECT * FROM users WHERE id = ?', [session['user_id']]).fetchone()
    
    flag = None
    if user['role'] in ('admin', 'superadmin'):
        flag = get_flag('CH17-C07')
    
    return jsonify({
        'updated': True,
        'user': {
            'display_name': user['display_name'],
            'email': user['email'],
            'role': user['role'],
        },
        'flag': flag
    })


# ═══════════════════════════════════════
# IDOR CHAIN — View → Edit → Delete Reports
# ═══════════════════════════════════════

# In-memory report store (simulates a separate service)
REPORTS = {
    1: {'title': 'Q1 Revenue Report', 'author_id': 1, 'content': 'Revenue: $2.3M', 'confidential': True},
    2: {'title': 'Employee Satisfaction Survey', 'author_id': 5, 'content': 'Morale: Low', 'confidential': True},
    3: {'title': 'Infrastructure Audit', 'author_id': 6, 'content': 'Multiple misconfigurations found', 'confidential': True},
    4: {'title': 'Salary Benchmarking Data', 'author_id': 1, 'content': 'CEO: $450K, CTO: $320K, DevOps: $85K', 'confidential': True},
    5: {'title': 'Incident Response Log', 'author_id': 1, 'content': 'Breach detected 2024-02-15, data exfiltrated', 'confidential': True},
}


@advanced_bp.route('/api/reports')
def list_reports():
    """List reports — only shows your own (but IDOR on individual fetch)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    user_reports = [
        {'id': k, 'title': v['title']}
        for k, v in REPORTS.items()
        if v['author_id'] == session['user_id']
    ]
    return jsonify({'reports': user_reports, 'total_in_system': len(REPORTS)})


@advanced_bp.route('/api/reports/<int:report_id>')
def get_report(report_id):
    """
    [VULN: CH17-C08] IDOR — Access Any Report by ID
    
    No authorization check — any authenticated user can view any report.
    Chain: enumerate IDs → read confidential reports → use data for further attacks.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    report = REPORTS.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # [VULN] No check: report['author_id'] == session['user_id']
    flag = None
    if report['author_id'] != session['user_id']:
        flag = get_flag('CH17-C08')
    
    return jsonify({
        'id': report_id,
        'title': report['title'],
        'content': report['content'],
        'confidential': report['confidential'],
        'author_id': report['author_id'],
        'flag': flag
    })


@advanced_bp.route('/api/reports/<int:report_id>', methods=['PUT'])
def edit_report(report_id):
    """
    [VULN: CH17-C09] IDOR — Edit Any Report
    
    Escalation from read IDOR to write IDOR.
    Modify another user's confidential report.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    report = REPORTS.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    data = request.get_json(silent=True) or {}
    
    # [VULN] No authorization check on edit
    if 'title' in data:
        report['title'] = data['title']
    if 'content' in data:
        report['content'] = data['content']
    
    flag = None
    if report['author_id'] != session['user_id']:
        flag = get_flag('CH17-C09')
    
    return jsonify({
        'updated': True,
        'report': {'id': report_id, 'title': report['title']},
        'flag': flag
    })


@advanced_bp.route('/api/reports/<int:report_id>', methods=['DELETE'])
def delete_report(report_id):
    """
    [VULN: CH17-C10] IDOR Chain — Delete Any Report
    
    Full IDOR chain: View (C08) → Edit (C09) → Delete (C10).
    This mirrors real authorization bypass findings.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    report = REPORTS.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # [VULN] No authorization check on delete
    flag = None
    if report['author_id'] != session['user_id']:
        flag = get_flag('CH17-C10')
    
    del REPORTS[report_id]
    
    return jsonify({
        'deleted': True,
        'report_id': report_id,
        'flag': flag
    })


# ═══════════════════════════════════════
# HTTP VERB TAMPERING
# ═══════════════════════════════════════

@advanced_bp.route('/api/admin/users', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def admin_users_verb_tamper():
    """
    [VULN: CH17-C11] HTTP Verb Tampering — Admin Endpoint
    
    GET is "protected" (returns 403), but other HTTP methods bypass
    the access control check. Try PUT, DELETE, or PATCH.
    """
    if request.method == 'GET':
        # "Protected" — always returns 403
        return jsonify({'error': 'Admin access required', 'hint': 'Have you tried other HTTP methods?'}), 403
    
    if request.method == 'OPTIONS':
        return '', 200, {
            'Allow': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
            'X-Hint': 'Not all methods enforce the same access controls...'
        }
    
    # [VULN] All other methods bypass the "protection"
    db = get_db()
    users = db.execute('SELECT id, username, email, role, balance, salary FROM users').fetchall()
    flag = get_flag('CH17-C11')
    
    return jsonify({
        'method_used': request.method,
        'message': 'Access control only checked GET requests!',
        'flag': flag,
        'users': [dict(u) for u in users]
    })


# ═══════════════════════════════════════
# INSECURE RANDOMNESS — Predictable Token
# ═══════════════════════════════════════

_token_counter = [1000]

@advanced_bp.route('/api/auth/request-token')
def request_predictable_token():
    """
    [VULN: CH17-C12] Insecure Randomness — Sequential Token Generation
    
    Tokens are generated sequentially. Predict the next token
    and use it to authenticate.
    """
    _token_counter[0] += 1
    token = hashlib.md5(str(_token_counter[0]).encode()).hexdigest()
    
    return jsonify({
        'token': token,
        'expires_in': 300,
        'hint': 'Notice a pattern in the tokens?'
    })


@advanced_bp.route('/api/auth/validate-token', methods=['POST'])
def validate_predictable_token():
    """Validate a predicted token."""
    token = request.form.get('token', request.json.get('token', '') if request.is_json else '')
    
    # The "next" token
    next_counter = _token_counter[0] + 1
    expected_token = hashlib.md5(str(next_counter).encode()).hexdigest()
    
    if token == expected_token:
        _token_counter[0] = next_counter  # Advance counter
        flag = get_flag('CH17-C12')
        return jsonify({'valid': True, 'flag': flag, 'message': 'You predicted the next token!'})
    
    return jsonify({'valid': False, 'error': 'Token mismatch'}), 401


# ═══════════════════════════════════════
# SSRF → REDIS → RCE CHAIN (Guided)
# ═══════════════════════════════════════

@advanced_bp.route('/api/webhook/test', methods=['POST'])
def webhook_ssrf_redis():
    """
    [VULN: CH17-C13] SSRF → Redis Command Injection
    
    This webhook endpoint makes a request to a user-supplied URL.
    Use it to send Gopher-protocol payloads to Redis (10.10.2.30:6379)
    to execute arbitrary Redis commands.
    
    Payload: gopher://10.10.2.30:6379/_SET%20pwned%20true%0D%0A
    """
    url = request.form.get('url', request.json.get('url', '') if request.is_json else '')
    
    if not url:
        return jsonify({'error': 'URL required', 'hint': 'Try targeting internal services like Redis'}), 400
    
    import requests as req
    try:
        resp = req.get(url, timeout=5, allow_redirects=False)
        
        flag = None
        if 'redis' in url.lower() or '6379' in url or '10.10.2.30' in url:
            flag = get_flag('CH17-C13')
        elif 'gopher' in url.lower():
            flag = get_flag('CH17-C13')
        
        return jsonify({
            'status': resp.status_code,
            'body': resp.text[:3000],
            'flag': flag
        })
    except Exception as e:
        flag = None
        if 'gopher' in url.lower() or 'redis' in url.lower():
            flag = get_flag('CH17-C13')
        return jsonify({
            'error': str(e),
            'flag': flag,
            'hint': 'Connection errors can still confirm service existence (SSRF blind probe)'
        })


# ═══════════════════════════════════════
# ACCOUNT TAKEOVER CHAIN
# ═══════════════════════════════════════

@advanced_bp.route('/api/user/security-question', methods=['GET', 'POST'])
def security_question():
    """
    [VULN: CH17-C14] Account Takeover — Weak Security Questions
    
    GET: Returns the security question for any username (user enumeration).
    POST: If the answer matches, resets the password (no email verification).
    
    Admin's pet name is 'fluffy' — it's in their profile bio.
    """
    if request.method == 'GET':
        username = request.args.get('username', '')
        # [VULN] Returns question for ANY user — user enumeration
        questions = {
            'admin': {'question': "What is your pet's name?", 'hint': 'Check the admin profile bio'},
            'alice': {'question': 'What city were you born in?', 'hint': 'She mentions it in her posts'},
            'dev_user': {'question': 'What is your favorite framework?', 'hint': 'Obviously Flask'},
        }
        if username in questions:
            return jsonify(questions[username])
        return jsonify({'error': 'User not found', 'hint': 'Try: admin, alice, dev_user'}), 404
    
    # POST — verify answer and reset password
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    answer = data.get('answer', '').lower()
    new_password = data.get('new_password', 'hacked123')
    
    answers = {
        'admin': 'fluffy',
        'alice': 'seattle',
        'dev_user': 'flask',
    }
    
    if username in answers and answer == answers[username]:
        db = get_db()
        db.execute('UPDATE users SET password = ? WHERE username = ?', [new_password, username])
        db.commit()
        flag = get_flag('CH17-C14')
        return jsonify({
            'success': True,
            'message': f'Password for {username} has been reset!',
            'flag': flag
        })
    
    return jsonify({'error': 'Incorrect answer'}), 403


# ═══════════════════════════════════════
# INFORMATION PAGE — Advanced Challenge Index
# ═══════════════════════════════════════

@advanced_bp.route('/challenges/advanced')
def advanced_challenges_page():
    """Landing page for Chapter 17 — Advanced Exploitation."""
    if 'user_id' not in session:
        return jsonify({'error': 'Login required'}), 401
    
    challenges = [
        {'id': 'CH17-C01', 'name': 'Race Condition: Double-Spend Transfer', 'endpoint': '/api/transfer', 'difficulty': 'Hard'},
        {'id': 'CH17-C02', 'name': 'Race Condition: Coupon Double-Use', 'endpoint': '/api/coupon/race', 'difficulty': 'Hard'},
        {'id': 'CH17-C03', 'name': 'JWT Key Confusion Attack', 'endpoint': '/api/jwt/public-key', 'difficulty': 'Expert'},
        {'id': 'CH17-C04', 'name': 'Business Logic: Price Manipulation', 'endpoint': '/api/store/purchase', 'difficulty': 'Medium'},
        {'id': 'CH17-C05', 'name': 'Business Logic: Negative Quantity', 'endpoint': '/api/store/purchase', 'difficulty': 'Medium'},
        {'id': 'CH17-C06', 'name': 'Type Juggling Auth Bypass', 'endpoint': '/api/auth/verify-pin', 'difficulty': 'Hard'},
        {'id': 'CH17-C07', 'name': 'Parameter Pollution + Mass Assignment', 'endpoint': '/api/user/update', 'difficulty': 'Hard'},
        {'id': 'CH17-C08', 'name': 'IDOR Chain: View Reports', 'endpoint': '/api/reports/<id>', 'difficulty': 'Medium'},
        {'id': 'CH17-C09', 'name': 'IDOR Chain: Edit Reports', 'endpoint': '/api/reports/<id>', 'difficulty': 'Medium'},
        {'id': 'CH17-C10', 'name': 'IDOR Chain: Delete Reports', 'endpoint': '/api/reports/<id>', 'difficulty': 'Medium'},
        {'id': 'CH17-C11', 'name': 'HTTP Verb Tampering', 'endpoint': '/api/admin/users', 'difficulty': 'Easy'},
        {'id': 'CH17-C12', 'name': 'Insecure Randomness: Predictable Token', 'endpoint': '/api/auth/request-token', 'difficulty': 'Hard'},
        {'id': 'CH17-C13', 'name': 'SSRF → Redis Command Injection', 'endpoint': '/api/webhook/test', 'difficulty': 'Expert'},
        {'id': 'CH17-C14', 'name': 'Account Takeover via Security Questions', 'endpoint': '/api/user/security-question', 'difficulty': 'Medium'},
    ]
    
    return jsonify({
        'chapter': 'CH17 — Advanced Exploitation Techniques',
        'description': 'Professional-grade vulnerabilities mirroring real-world bug bounty findings.',
        'total_flags': len(challenges),
        'challenges': challenges
    })

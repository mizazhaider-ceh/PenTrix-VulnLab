"""
routes/tools.py — Network tools and utilities for The PenTrix
Contains INTENTIONAL vulnerabilities: RCE, SSTI, SSRF, XXE, Pickle, YAML
"""
import os
import subprocess
import base64
import pickle
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag

tools_bp = Blueprint('tools', __name__)

@tools_bp.route('/tools')
def tools_index():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('tools/index.html')


# [VULN: CH11-C01] OS Command Injection in ping
@tools_bp.route('/tools/ping', methods=['GET', 'POST'])
def ping():
    if 'user_id' not in session:
        return redirect('/login')
    
    result = None
    flag = None
    host = ''
    
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # INTENTIONALLY VULNERABLE: shell=True with user input
        try:
            result = subprocess.check_output(
                f"ping -c 2 {host}",
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=10
            ).decode()
        except subprocess.TimeoutExpired:
            result = "Command timed out"
        except Exception as e:
            result = str(e)
        
        # Detect command injection
        if any(c in host for c in [';', '|', '&&', '`', '$(']):
            flag = get_flag('CH11-C01')
    
    return render_template('tools/ping.html', result=result, host=host, flag=flag)


# [VULN: CH11-C03] Server-Side Template Injection (Jinja2)
@tools_bp.route('/tools/render', methods=['GET'])
def render_template_vuln():
    template_str = request.args.get('template', 'Hello World')
    
    # INTENTIONALLY VULNERABLE: renders user input as Jinja2 template
    from jinja2 import Template
    try:
        rendered = Template(template_str).render()
        
        flag = None
        if '{{' in template_str and ('config' in template_str or '7*7' in template_str or '__' in template_str):
            flag = get_flag('CH11-C03')
        
        return f"""<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h2>Template Renderer</h2>
<form method="GET" action="/tools/render">
    <input name="template" value="{template_str}" style="width:400px;padding:8px;background:#161b22;color:#c9d1d9;border:1px solid #30363d;">
    <button type="submit" style="padding:8px 16px;background:#238636;color:white;border:none;cursor:pointer;">Render</button>
</form>
<pre style="background:#161b22;padding:16px;margin-top:16px;border-radius:6px;">{rendered}</pre>
{"<pre style='color:#238636;'>"+flag+"</pre>" if flag else ""}
</body></html>"""
    except Exception as e:
        return str(e), 500


# [VULN: CH11-C04] SSTI in email template
@tools_bp.route('/tools/email-preview', methods=['POST'])
def email_preview():
    template = request.form.get('template', '')
    name = request.form.get('name', 'User')
    
    # INTENTIONALLY VULNERABLE: renders user input
    from jinja2 import Template
    try:
        rendered = Template(template).render(name=name)
        flag = None
        if '{{' in template and ('config' in template or '__' in template):
            flag = get_flag('CH11-C04')
        return jsonify({'preview': rendered, 'flag': flag})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# [VULN: CH11-C05] Unsafe eval() on user input
@tools_bp.route('/tools/calc', methods=['GET', 'POST'])
def calculator():
    result = None
    flag = None
    expr = ''
    
    if request.method == 'POST' or request.args.get('expr'):
        expr = request.form.get('expr', request.args.get('expr', ''))
        
        # INTENTIONALLY VULNERABLE: eval() on user input
        try:
            result = str(eval(expr))
            flag = get_flag('CH11-C05')
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return render_template('tools/calc.html', result=result, expr=expr, flag=flag)


# [VULN: CH11-C06] Unsafe pickle deserialization
@tools_bp.route('/api/restore', methods=['POST'])
@tools_bp.route('/tools/restore', methods=['GET', 'POST'])
def restore_session():
    if request.method == 'GET':
        return render_template('tools/restore.html')
    data = request.data or request.form.get('data', '').encode()
    
    # INTENTIONALLY VULNERABLE: deserializing untrusted data
    try:
        obj = pickle.loads(base64.b64decode(data))
        flag = get_flag('CH11-C06')
        return jsonify({'status': 'restored', 'data': str(obj), 'flag': flag})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# [VULN: CH11-C07] Command injection via User-Agent header log processing
@tools_bp.route('/tools/logs/analyze')
def analyze_logs():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    # Get last User-Agent from logs
    last_ua = db.execute('SELECT user_agent FROM access_logs ORDER BY id DESC LIMIT 1').fetchone()
    
    if last_ua:
        ua = last_ua['user_agent']
        # INTENTIONALLY VULNERABLE: User-Agent passed to shell command
        try:
            result = subprocess.check_output(
                f"echo 'User-Agent: {ua}' | head -c 500",
                shell=True,
                stderr=subprocess.STDOUT
            ).decode()
            flag = get_flag('CH11-C07')
            return jsonify({'log_analysis': result, 'flag': flag})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'message': 'No logs found'})


# [VULN: CH11-C08] Command injection in image resize parameter
@tools_bp.route('/tools/resize', methods=['POST'])
def resize_image():
    filename = request.form.get('filename', '')
    width = request.form.get('width', '100')
    height = request.form.get('height', '100')
    
    # INTENTIONALLY VULNERABLE: dimensions passed to shell
    try:
        result = subprocess.check_output(
            f"echo 'Resizing {filename} to {width}x{height}'",
            shell=True,
            stderr=subprocess.STDOUT
        ).decode()
        flag = get_flag('CH11-C08')
        return jsonify({'result': result, 'flag': flag})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# [VULN: CH11-C09] YAML deserialization RCE
@tools_bp.route('/tools/yaml-import', methods=['GET', 'POST'])
def yaml_import():
    if request.method == 'GET':
        return render_template('tools/yaml_import_form.html')
    yaml_data = request.data.decode() or request.form.get('yaml', '')
    
    # INTENTIONALLY VULNERABLE: yaml.load without safe_load
    import yaml
    try:
        obj = yaml.load(yaml_data, Loader=yaml.FullLoader)
        flag = get_flag('CH11-C09')
        return jsonify({'parsed': str(obj), 'flag': flag})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ═══════════════════════════════════════
# SSRF VULNERABILITIES
# ═══════════════════════════════════════

# [VULN: BONUS-SSRF-C01/C03] SSRF in URL fetch
@tools_bp.route('/tools/fetch', methods=['GET', 'POST'])
def fetch_url():
    if request.method == 'GET':
        return render_template('tools/fetch.html')
    
    url = request.form.get('url', request.json.get('url', '') if request.is_json else '')
    
    # INTENTIONALLY VULNERABLE: fetches arbitrary URLs including internal
    import requests as req
    try:
        response = req.get(url, timeout=5)
        
        flag = None
        if 'localhost' in url or '127.0.0.1' in url or 'internal' in url:
            flag = get_flag('BONUS-SSRF-C01')
        elif url.startswith('file://'):
            flag = get_flag('BONUS-SSRF-C06')
        
        return jsonify({
            'status': response.status_code,
            'body': response.text[:5000],
            'headers': dict(response.headers),
            'flag': flag
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# [VULN: BONUS-SSRF-C04] Blind SSRF via webhook
@tools_bp.route('/tools/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        return render_template('tools/webhook.html')
    callback_url = request.form.get('url', request.json.get('url', '') if request.is_json else '')
    
    import requests as req
    try:
        # INTENTIONALLY VULNERABLE: blind SSRF
        req.post(callback_url, json={'status': 'ok'}, timeout=3)
        flag = get_flag('BONUS-SSRF-C04')
        return jsonify({'status': 'webhook sent', 'flag': flag})
    except Exception as e:
        return jsonify({'status': 'webhook attempted', 'flag': get_flag('BONUS-SSRF-C04')})


# [VULN: BONUS-SSRF-C05] SSRF filter bypass
@tools_bp.route('/tools/safe-fetch', methods=['POST'])
def safe_fetch():
    url = request.form.get('url', request.json.get('url', '') if request.is_json else '')
    
    # "Security filter" — easy to bypass
    blocked = ['127.0.0.1', 'localhost', '0.0.0.0']
    for b in blocked:
        if b in url:
            return jsonify({'error': 'Blocked: internal addresses not allowed'}), 403
    
    # [VULN: BONUS-SSRF-C05] Filter can be bypassed with IP encoding
    # 0x7f000001, 2130706433, 017700000001, [::1], etc.
    import requests as req
    try:
        response = req.get(url, timeout=5)
        flag = get_flag('BONUS-SSRF-C05')
        return jsonify({'body': response.text[:5000], 'flag': flag})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ═══════════════════════════════════════
# XXE VULNERABILITIES
# ═══════════════════════════════════════

# [VULN: BONUS-XXE-C01] XXE in XML import
@tools_bp.route('/import/xml', methods=['GET', 'POST'])
def import_xml():
    if request.method == 'GET':
        return render_template('tools/xml_import.html')
    
    xml_data = request.data
    
    # INTENTIONALLY VULNERABLE: external entities enabled
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    
    try:
        tree = etree.fromstring(xml_data, parser)
        result = etree.tostring(tree, pretty_print=True).decode()
        
        flag = get_flag('BONUS-XXE-C01')
        return jsonify({'parsed': result, 'flag': flag})
    except Exception as e:
        # [VULN: BONUS-XXE-C07] Error-based exfiltration
        flag = get_flag('BONUS-XXE-C07')
        return jsonify({'error': str(e), 'flag': flag}), 400


# [VULN: BONUS-XXE-C08] SOAP endpoint
@tools_bp.route('/api/soap', methods=['POST'])
def soap_endpoint():
    xml_data = request.data
    
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    
    try:
        tree = etree.fromstring(xml_data, parser)
        result = etree.tostring(tree, pretty_print=True).decode()
        flag = get_flag('BONUS-XXE-C08')
        return result, 200, {'Content-Type': 'application/xml'}
    except Exception as e:
        return str(e), 400


# [VULN: BONUS-XXE-C09] XInclude injection
@tools_bp.route('/import/xinclude', methods=['POST'])
def xinclude_import():
    xml_data = request.data
    
    from lxml import etree
    try:
        tree = etree.fromstring(xml_data)
        tree.getroottree().xinclude()
        result = etree.tostring(tree, pretty_print=True).decode()
        flag = get_flag('BONUS-XXE-C09')
        return jsonify({'parsed': result, 'flag': flag})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# [VULN: CH08-C09] XSS in HTTP header reflection
@tools_bp.route('/tools/headers')
def reflect_headers():
    # INTENTIONALLY VULNERABLE: reflects headers into response without sanitization
    headers_list = []
    for key, value in request.headers:
        headers_list.append(f"<li><strong>{key}:</strong> {value}</li>")
    
    flag = None
    referer = request.headers.get('Referer', '')
    ua = request.headers.get('User-Agent', '')
    if '<script>' in referer.lower() or '<script>' in ua.lower() or 'onerror' in referer.lower():
        flag = get_flag('CH08-C09')
    
    return f"""<html><body style="background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px;">
<h2>Request Headers</h2>
<ul>{''.join(headers_list)}</ul>
{"<pre style='color:#238636;'>"+flag+"</pre>" if flag else ""}
</body></html>"""

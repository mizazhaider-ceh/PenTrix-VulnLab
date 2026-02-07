"""
routes/files.py — File upload and download for The PenTrix
Contains INTENTIONAL vulnerabilities: Directory traversal, XSS via SVG, IDOR
"""
import os
import zipfile
import io
from flask import Blueprint, request, session, redirect, render_template, jsonify, send_file
from db import get_db
from flags import get_flag

files_bp = Blueprint('files', __name__)

UPLOAD_DIR = '/app/static/uploads'

@files_bp.route('/files')
def list_files():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    # Show all public files + user's own private files
    files = db.execute('''
        SELECT f.*, u.username FROM files f JOIN users u ON f.user_id=u.id
        WHERE f.is_private=0 OR f.user_id=?
        ORDER BY f.created_at DESC
    ''', [session['user_id']]).fetchall()
    
    return render_template('files/list.html', files=files)


# [VULN: CH05-C01] Directory traversal in file download
@files_bp.route('/files/download')
def download_file():
    filename = request.args.get('file', '')
    
    if not filename:
        return "No file specified", 400
    
    # [VULN: CH05-C01] INTENTIONALLY VULNERABLE: no path normalization
    filepath = os.path.join('/app/static/uploads/', filename)
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        flag = None
        # Detect traversal usage
        if '..' in filename:
            if '/etc/passwd' in filepath or 'passwd' in content:
                flag = get_flag('CH05-C01')
            elif '/etc/hosts' in filepath:
                flag = get_flag('CH05-C03')
            elif '/proc/version' in filepath:
                flag = get_flag('CH05-C04')
            elif 'app.py' in filepath or 'flags.py' in filepath:
                flag = get_flag('CH05-C07')
            else:
                flag = get_flag('CH05-C02')
        
        response_text = content
        if flag:
            response_text += f"\n\n{flag}"
        
        return response_text, 200, {'Content-Type': 'text/plain'}
    except Exception as e:
        # [VULN: CH02-C07] Verbose error response
        return str(e), 500


# [VULN: CH05-C05] Double-encoded traversal
@files_bp.route('/files/fetch')
def fetch_file():
    filename = request.args.get('file', '')
    
    # "Filter" that only blocks single-encoded ../
    if '../' in filename:
        return "Path traversal detected!", 403
    
    # [VULN: CH05-C05] Double-encoded ../ bypasses the check
    # %252e%252e%252f -> %2e%2e%2f -> ../
    from urllib.parse import unquote
    decoded = unquote(filename)
    filepath = os.path.join('/app/static/uploads/', decoded)
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        flag = get_flag('CH05-C05')
        return content + f"\n\n{flag}", 200, {'Content-Type': 'text/plain'}
    except Exception as e:
        return str(e), 500


# [VULN: CH08-C08 / BONUS-XXE-C02] File upload — SVG allowed
@files_bp.route('/files/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    
    # [VULN: CH13-C10] Client-side file type validation only — no server validation
    # [VULN: CH08-C08] SVG files allowed — can contain JavaScript
    filename = file.filename
    
    # [VULN: CH11-C02] Command injection in filename
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file.save(filepath)
    
    db = get_db()
    is_private = 1 if request.form.get('private') else 0
    db.execute('INSERT INTO files (user_id, filename, filepath, is_private) VALUES (?, ?, ?, ?)',
               [session['user_id'], filename, filepath, is_private])
    db.commit()
    
    flag = None
    if filename.lower().endswith('.svg'):
        flag = get_flag('CH08-C08')
    
    return jsonify({'success': True, 'filename': filename, 'flag': flag})


# [VULN: CH03-C07] IDOR — download another user's file
@files_bp.route('/files/<int:file_id>/download')
def download_by_id(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    # INTENTIONALLY VULNERABLE: no ownership check
    file_record = db.execute('SELECT * FROM files WHERE id=?', [file_id]).fetchone()
    
    if not file_record:
        return "File not found", 404
    
    flag = None
    if file_record['user_id'] != session['user_id'] and file_record['is_private']:
        flag = get_flag('CH03-C07')
    
    try:
        filepath = file_record['filepath']
        with open(filepath, 'r') as f:
            content = f.read()
        
        response_text = content
        if flag:
            response_text += f"\n\n{flag}"
        
        return response_text, 200, {'Content-Type': 'application/octet-stream',
                                     'Content-Disposition': f'attachment; filename="{file_record["filename"]}"'}
    except Exception:
        return f"File content: [sample data for {file_record['filename']}]\n{flag or ''}", 200


# [VULN: CH05-C10] ZIP traversal
@files_bp.route('/files/upload-zip', methods=['POST'])
def upload_zip():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # [VULN: CH05-C10] No validation of paths inside ZIP
        z = zipfile.ZipFile(io.BytesIO(file.read()))
        z.extractall(UPLOAD_DIR)
        
        flag = None
        for name in z.namelist():
            if '..' in name:
                flag = get_flag('CH05-C10')
                break
        
        return jsonify({'success': True, 'extracted': z.namelist(), 'flag': flag})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

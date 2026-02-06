"""
routes/posts.py — Blog/announcement posts for The PenTrix
Contains INTENTIONAL vulnerabilities: Stored XSS, IDOR, SQLi, CSRF
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag

posts_bp = Blueprint('posts', __name__)

@posts_bp.route('/posts')
def list_posts():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    posts = db.execute('''
        SELECT p.*, u.username, u.display_name,
        (SELECT COUNT(*) FROM comments WHERE post_id=p.id) as comment_count
        FROM posts p JOIN users u ON p.user_id=u.id
        WHERE p.is_public=1
        ORDER BY p.created_at DESC
    ''').fetchall()
    
    return render_template('posts/list.html', posts=posts)


@posts_bp.route('/posts/<int:post_id>')
def view_post(post_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    post = db.execute('SELECT p.*, u.username, u.display_name FROM posts p JOIN users u ON p.user_id=u.id WHERE p.id=?', [post_id]).fetchone()
    
    if not post:
        return "Post not found", 404
    
    # [VULN: CH08-C02] Comments rendered with | safe (stored XSS)
    comments = db.execute('''
        SELECT c.*, u.username, u.display_name
        FROM comments c JOIN users u ON c.user_id=u.id
        WHERE c.post_id=?
        ORDER BY c.created_at ASC
    ''', [post_id]).fetchall()
    
    return render_template('posts/view.html', post=post, comments=comments)


@posts_bp.route('/posts/create', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        
        # [VULN: CH08-C03] No sanitization — stored XSS in display name carried through
        db = get_db()
        db.execute('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)',
                   [session['user_id'], title, content])
        db.commit()
        
        return redirect('/posts')
    
    return render_template('posts/create.html')


# [VULN: CH08-C02] Stored XSS in blog post comment
@posts_bp.route('/posts/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    body = request.form.get('body', '')
    
    # INTENTIONALLY VULNERABLE: no sanitization before storage
    db = get_db()
    db.execute("INSERT INTO comments (post_id, user_id, body) VALUES (?,?,?)",
               [post_id, session['user_id'], body])
    db.commit()
    
    flag = None
    if '<script>' in body.lower() or 'onerror' in body.lower() or 'onload' in body.lower():
        flag = get_flag('CH08-C02')
    
    if flag:
        return redirect(f'/posts/{post_id}?flag={flag}')
    return redirect(f'/posts/{post_id}')


# [VULN: CH10-C04] CSRF — post message as victim
@posts_bp.route('/posts/quick', methods=['POST'])
def quick_post():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    db = get_db()
    db.execute('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)',
               [session['user_id'], title, content])
    db.commit()
    
    flag = get_flag('CH10-C04')
    return jsonify({'success': True, 'flag': flag})

"""
routes/messages.py — Internal messaging for The PenTrix
Contains INTENTIONAL vulnerabilities: IDOR, XSS
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag

messages_bp = Blueprint('messages', __name__)

@messages_bp.route('/messages')
def inbox():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    messages = db.execute('''
        SELECT m.*, u.username as sender_name, u.display_name as sender_display
        FROM messages m JOIN users u ON m.sender_id=u.id
        WHERE m.recipient_id=?
        ORDER BY m.created_at DESC
    ''', [session['user_id']]).fetchall()
    
    return render_template('messages/inbox.html', messages=messages)


# [VULN: CH03-C02] IDOR — read another user's private message
@messages_bp.route('/messages/<int:message_id>')
def view_message(message_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    # INTENTIONALLY VULNERABLE: no check that message belongs to current user
    message = db.execute('''
        SELECT m.*, 
            s.username as sender_name, s.display_name as sender_display,
            r.username as recipient_name, r.display_name as recipient_display
        FROM messages m 
        JOIN users s ON m.sender_id=s.id
        JOIN users r ON m.recipient_id=r.id
        WHERE m.id=?
    ''', [message_id]).fetchone()
    
    if not message:
        return "Message not found", 404
    
    flag = None
    # Check if user is reading someone else's message 
    if message['recipient_id'] != session['user_id'] and message['sender_id'] != session['user_id']:
        flag = get_flag('CH03-C02')
    
    # Mark as read
    db.execute('UPDATE messages SET is_read=1 WHERE id=?', [message_id])
    db.commit()
    
    return render_template('messages/view.html', message=message, flag=flag)


@messages_bp.route('/messages/send', methods=['GET', 'POST'])
def send_message():
    if 'user_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        recipient = request.form.get('recipient', '')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        
        db = get_db()
        recipient_user = db.execute('SELECT id FROM users WHERE username=?', [recipient]).fetchone()
        
        if recipient_user:
            # No sanitization — potential XSS when message is viewed
            db.execute('INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)',
                       [session['user_id'], recipient_user['id'], subject, body])
            db.commit()
            return redirect('/messages')
        else:
            return render_template('messages/send.html', error='Recipient not found')
    
    db = get_db()
    users = db.execute('SELECT username, display_name FROM users').fetchall()
    return render_template('messages/send.html', users=users)

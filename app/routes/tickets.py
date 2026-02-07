"""
routes/tickets.py — Support ticket system for The PenTrix
Contains INTENTIONAL vulnerabilities: IDOR, Stored XSS
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag

tickets_bp = Blueprint('tickets', __name__)

@tickets_bp.route('/tickets')
def list_tickets():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    # Show only user's own tickets (proper behavior)
    tickets = db.execute('''
        SELECT t.*, u.username FROM tickets t JOIN users u ON t.user_id=u.id
        WHERE t.user_id=?
        ORDER BY t.created_at DESC
    ''', [session['user_id']]).fetchall()
    
    return render_template('tickets/list.html', tickets=tickets)


# [VULN: CH03-C09] IDOR — view another user's ticket
@tickets_bp.route('/tickets/<int:ticket_id>')
def view_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    # INTENTIONALLY VULNERABLE: no ownership check
    ticket = db.execute('''
        SELECT t.*, u.username, u.display_name
        FROM tickets t JOIN users u ON t.user_id=u.id
        WHERE t.id=?
    ''', [ticket_id]).fetchone()
    
    if not ticket:
        return "Ticket not found", 404
    
    flag = None
    if ticket['user_id'] != session['user_id']:
        flag = get_flag('CH03-C09')
    
    return render_template('tickets/view.html', ticket=ticket, flag=flag)


# [VULN: CH08-C10] Stored XSS in ticket subject
@tickets_bp.route('/tickets/create', methods=['GET', 'POST'])
def create_ticket():
    if 'user_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        
        # INTENTIONALLY VULNERABLE: no sanitization
        db = get_db()
        db.execute('INSERT INTO tickets (user_id, subject, body) VALUES (?, ?, ?)',
                   [session['user_id'], subject, body])
        db.commit()
        
        flag = None
        if '<script>' in subject.lower() or 'onerror' in subject.lower():
            flag = get_flag('CH08-C10')
        
        if flag:
            return redirect(f'/tickets?flag={flag}')
        return redirect('/tickets')
    
    return render_template('tickets/create.html')

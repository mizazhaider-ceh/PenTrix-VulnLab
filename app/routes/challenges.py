"""
routes/challenges.py — Per-chapter challenge pages for The PenTrix
Provides guided challenge interfaces for all 16 chapters + bonus categories
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import FLAGS, HINTS, CHALLENGE_LINKS

challenges_bp = Blueprint('challenges', __name__)

# Chapter metadata — immersive names with narrative subtitles
CHAPTERS = {
    'CH01': {'name': 'Introduction', 'subtitle': 'Initial Recon', 'number': 1, 'difficulty': 1, 'color': '#238636', 'icon': '🔍',
             'briefing': 'You have discovered the public-facing portal of PenTrix Corp. Map the attack surface and identify weak entry points without triggering suspicion.'},
    'CH02': {'name': 'Fingerprinting', 'subtitle': 'Technology Identification', 'number': 2, 'difficulty': 1, 'color': '#238636', 'icon': '🔎',
             'briefing': 'The portal is live. Before launching any attack, a professional maps every technology detail. The more you know, the more precisely you can strike.'},
    'CH03': {'name': 'Broken Access Control', 'subtitle': 'Authorization Flaws', 'number': 3, 'difficulty': 2, 'color': '#d29922', 'icon': '🔓',
             'briefing': 'You have a legitimate low-level account. But the access boundaries are poorly enforced. See how far you can reach beyond what you\'re supposed to access.'},
    'CH04': {'name': 'Sensitive Data Exposure', 'subtitle': 'Information Leakage', 'number': 4, 'difficulty': 2, 'color': '#d29922', 'icon': '📂',
             'briefing': 'PenTrix Corp stores critical data — credentials, financial records, internal configs. How much of it can you access without ever exploiting a vulnerability?'},
    'CH05': {'name': 'Directory Traversal', 'subtitle': 'Path Manipulation', 'number': 5, 'difficulty': 2, 'color': '#d29922', 'icon': '📁',
             'briefing': 'The file system is a locked building. You\'re on the ground floor. But some doors use paths instead of keys — and paths can be extended.'},
    'CH06': {'name': 'Broken Authentication', 'subtitle': 'Credential Attacks', 'number': 6, 'difficulty': 2, 'color': '#d29922', 'icon': '🔑',
             'briefing': 'Authentication is the front door. PenTrix Corp\'s front door has several known weaknesses. Find each one and walk through.'},
    'CH07': {'name': 'Fuzzing & Discovery', 'subtitle': 'Hidden Endpoints', 'number': 7, 'difficulty': 2, 'color': '#d29922', 'icon': '🎯',
             'briefing': 'The visible surface is only the beginning. Beneath the navigation lies a hidden landscape of forgotten endpoints, debug tools, and backup artifacts.'},
    'CH08': {'name': 'Cross-Site Scripting', 'subtitle': 'XSS Injection', 'number': 8, 'difficulty': 3, 'color': '#da3633', 'icon': '💉',
             'briefing': 'The portal accepts user input in many places. Not all input is sanitized before rendering. Make the application execute code it never intended to run.'},
    'CH09': {'name': 'DOM Vulnerabilities', 'subtitle': 'Client-Side Attacks', 'number': 9, 'difficulty': 3, 'color': '#da3633', 'icon': '🌐',
             'briefing': 'Server-side security means nothing if the client-side code is vulnerable. These challenges live entirely in the browser — no server requests needed.'},
    'CH10': {'name': 'CSRF', 'subtitle': 'Cross-Site Request Forgery', 'number': 10, 'difficulty': 3, 'color': '#da3633', 'icon': '🎭',
             'briefing': 'The application trusts that requests come from the legitimate user. Prove that any website can make these requests on the user\'s behalf.'},
    'CH11': {'name': 'Remote Code Execution', 'subtitle': 'Command Injection', 'number': 11, 'difficulty': 4, 'color': '#da3633', 'icon': '💀',
             'briefing': 'The ultimate goal: execute arbitrary commands on the server. These vulnerabilities give you operating system-level access.'},
    'CH12': {'name': 'Clickjacking', 'subtitle': 'UI Redressing', 'number': 12, 'difficulty': 2, 'color': '#d29922', 'icon': '🖱️',
             'briefing': 'The application can be framed. An attacker can overlay invisible actions on top of legitimate-looking content.'},
    'CH13': {'name': 'Insecure Design', 'subtitle': 'Logic Flaws', 'number': 13, 'difficulty': 2, 'color': '#d29922', 'icon': '⚠️',
             'briefing': 'These aren\'t implementation bugs — they\'re architectural flaws. The logic itself is wrong, and no input validation can fix it.'},
    'CH14': {'name': 'API Vulnerabilities', 'subtitle': 'REST & GraphQL', 'number': 14, 'difficulty': 3, 'color': '#da3633', 'icon': '🔌',
             'briefing': 'The REST API powers everything behind the scenes. It was built for speed, not security. Every endpoint is a potential attack vector.'},
    'CH15': {'name': 'CORS Misconfiguration', 'subtitle': 'Cross-Origin Attacks', 'number': 15, 'difficulty': 3, 'color': '#da3633', 'icon': '🌍',
             'briefing': 'Cross-Origin Resource Sharing decides who can read your responses. When misconfigured, any website in the world can steal your data.'},
    'CH16': {'name': 'SQL Injection', 'subtitle': 'Database Exploitation', 'number': 16, 'difficulty': 3, 'color': '#da3633', 'icon': '💾',
             'briefing': 'The database executes whatever it\'s told. The application builds commands from your input. Speak SQL, and the database will obey.'},
    'BONUS-SSRF': {'name': 'SSRF', 'subtitle': 'Server-Side Request Forgery', 'number': 17, 'difficulty': 4, 'color': '#8957e5', 'icon': '🔗',
             'briefing': 'Internal services hide behind the firewall. But the application server sits inside that firewall. Make it fetch what you can\'t reach directly.'},
    'BONUS-XXE': {'name': 'XXE', 'subtitle': 'XML External Entities', 'number': 18, 'difficulty': 4, 'color': '#8957e5', 'icon': '📄',
             'briefing': 'XML is more powerful than it appears. External entities can read files, make network requests, and crash the server.'},
}


@challenges_bp.route('/challenges')
def challenges_index():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    
    # Get user's progress per chapter
    captured = db.execute(
        'SELECT flag_id FROM submissions WHERE user_id=? AND correct=1',
        [session['user_id']]
    ).fetchall()
    captured_ids = set(c['flag_id'] for c in captured)
    
    chapter_progress = {}
    for chapter_key, chapter_info in CHAPTERS.items():
        total = sum(1 for fid in FLAGS if fid.startswith(chapter_key + '-'))
        done = sum(1 for fid in FLAGS if fid.startswith(chapter_key + '-') and fid in captured_ids)
        chapter_progress[chapter_key] = {
            **chapter_info,
            'key': chapter_key,
            'total': total,
            'completed': done,
            'percent': int((done / total * 100) if total > 0 else 0)
        }
    
    return render_template('challenges/index.html', chapters=chapter_progress)


@challenges_bp.route('/challenges/<chapter>')
def chapter_challenges(chapter):
    if 'user_id' not in session:
        return redirect('/login')
    
    chapter_upper = chapter.upper()
    
    if chapter_upper not in CHAPTERS:
        return "Chapter not found", 404
    
    chapter_info = CHAPTERS[chapter_upper]
    
    # Get all challenges for this chapter
    chapter_challenges = []
    for flag_id, description in FLAGS.items():
        if flag_id.startswith(chapter_upper + '-'):
            # Get hints for this challenge
            hints_data = HINTS.get(flag_id, [])
            # Get linkage data
            links = CHALLENGE_LINKS.get(flag_id)
            chapter_challenges.append({
                'flag_id': flag_id,
                'number': int(flag_id.split('-C')[1]) if '-C' in flag_id else 0,
                'description': description,
                'hints': hints_data,
                'links': links
            })
    
    chapter_challenges.sort(key=lambda x: x['number'])
    
    # Get user's progress
    db = get_db()
    captured = db.execute(
        'SELECT flag_id FROM submissions WHERE user_id=? AND correct=1',
        [session['user_id']]
    ).fetchall()
    captured_ids = set(c['flag_id'] for c in captured)
    
    # Get unlocked hints
    unlocked = db.execute(
        'SELECT flag_id, tier FROM hint_unlocks WHERE user_id=?',
        [session['user_id']]
    ).fetchall()
    unlocked_hints = {}
    for u in unlocked:
        if u['flag_id'] not in unlocked_hints:
            unlocked_hints[u['flag_id']] = set()
        unlocked_hints[u['flag_id']].add(u['tier'])
    
    return render_template('challenges/chapter.html',
        chapter=chapter_info,
        chapter_key=chapter_upper,
        challenges=chapter_challenges,
        captured_ids=captured_ids,
        unlocked_hints=unlocked_hints
    )


# Scenarios page
@challenges_bp.route('/challenges/scenarios')
def scenarios():
    if 'user_id' not in session:
        return redirect('/login')
    
    scenarios_data = [
        {
            'id': 'A',
            'name': 'The Insider',
            'difficulty': 'Easy',
            'steps': 3,
            'color': '#238636',
            'description': 'Gain admin access starting as a regular user.',
            'flag_id': 'SCENARIO-A',
            'steps_detail': [
                {'vuln': 'Fingerprinting', 'action': 'Identify stack and find /debug endpoint'},
                {'vuln': 'Broken Authentication', 'action': 'Login with default credentials found in debug'},
                {'vuln': 'Broken Access Control', 'action': 'Access admin panel via IDOR on user ID'},
            ]
        },
        {
            'id': 'B',
            'name': 'Data Heist',
            'difficulty': 'Medium',
            'steps': 5,
            'color': '#d29922',
            'description': 'Exfiltrate a secret internal salary report as an unauthenticated user.',
            'flag_id': 'SCENARIO-B',
            'steps_detail': [
                {'vuln': 'Fuzzing', 'action': 'Find hidden /api/v2/internal endpoint'},
                {'vuln': 'CORS', 'action': 'Exploit origin reflection to read API data'},
                {'vuln': 'Broken Access Control', 'action': 'IDOR on /api/reports/:id'},
                {'vuln': 'Sensitive Data Exposure', 'action': 'API returns hashed password in response'},
                {'vuln': 'SQLi', 'action': 'Crack hash or bypass auth to access salary report'},
            ]
        },
        {
            'id': 'C',
            'name': 'Full Compromise',
            'difficulty': 'Hard',
            'steps': 9,
            'color': '#da3633',
            'description': 'Achieve Remote Code Execution starting from zero knowledge.',
            'flag_id': 'SCENARIO-C',
            'steps_detail': [
                {'vuln': 'Fingerprinting', 'action': 'Map the app, find all endpoints and tech stack'},
                {'vuln': 'Directory Traversal', 'action': 'Read app source code via traversal in file download'},
                {'vuln': 'SQLi', 'action': 'Extract credentials from users table via blind SQLi'},
                {'vuln': 'Broken Authentication', 'action': 'Login as admin using extracted credentials'},
                {'vuln': 'XSS', 'action': 'Stored XSS in admin-visible field to steal session'},
                {'vuln': 'CSRF', 'action': 'Use admin session to activate network tool feature'},
                {'vuln': 'RCE', 'action': 'Command injection in now-enabled ping utility'},
                {'vuln': 'SSRF', 'action': 'Chain SSRF from RCE to access internal Redis'},
                {'vuln': 'Priv Esc', 'action': 'Write cron job via Redis for persistent access'},
            ]
        }
    ]
    
    return render_template('challenges/scenarios.html', scenarios=scenarios_data)

"""
routes/scoreboard.py — Flag submission and leaderboard for The PenTrix
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag, FLAGS, FLAG_VALUES

scoreboard_bp = Blueprint('scoreboard', __name__)

POINTS_PER_FLAG = 100

@scoreboard_bp.route('/scoreboard')
def leaderboard():
    db = get_db()
    
    # Get leaderboard
    leaders = db.execute('''
        SELECT u.username,
            COUNT(DISTINCT s.flag_id) as flags_captured,
            COUNT(DISTINCT s.flag_id) * ? as score,
            MIN(s.submitted_at) as first_solve,
            MAX(s.submitted_at) as last_solve
        FROM users u
        LEFT JOIN submissions s ON u.id=s.user_id AND s.correct=1
        GROUP BY u.id
        HAVING flags_captured > 0
        ORDER BY flags_captured DESC, last_solve ASC
    ''', [POINTS_PER_FLAG]).fetchall()
    
    total_flags = len(FLAGS)
    
    return render_template('scoreboard/index.html', leaders=leaders, total_flags=total_flags)


@scoreboard_bp.route('/scoreboard/submit', methods=['POST'])
def submit_flag():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
    
    flag_value = request.form.get('flag', request.json.get('flag', '') if request.is_json else '')
    flag_id = request.form.get('flag_id', request.json.get('flag_id', '') if request.is_json else '')
    
    if not flag_value:
        return jsonify({'error': 'No flag submitted'}), 400
    
    db = get_db()
    
    # Check if this flag value exists (case-insensitive for UX — accepts FLAG{} and flag{})
    cleaned = flag_value.strip()
    flag_record = db.execute('SELECT * FROM flags WHERE flag_value=? COLLATE NOCASE', [cleaned]).fetchone()
    
    if flag_record:
        # Check for duplicate submission
        existing = db.execute(
            'SELECT * FROM submissions WHERE user_id=? AND flag_id=? AND correct=1',
            [session['user_id'], flag_record['flag_id']]
        ).fetchone()
        
        if existing:
            return jsonify({
                'correct': True,
                'duplicate': True,
                'message': 'You already submitted this flag!',
                'flag_id': flag_record['flag_id']
            })
        
        # Record correct submission
        db.execute(
            'INSERT INTO submissions (user_id, flag_id, correct) VALUES (?, ?, 1)',
            [session['user_id'], flag_record['flag_id']]
        )
        db.commit()
        
        # Get updated score
        score = db.execute(
            'SELECT COUNT(DISTINCT flag_id) as count FROM submissions WHERE user_id=? AND correct=1',
            [session['user_id']]
        ).fetchone()['count']
        
        # Check if chapter is fully completed
        chapter_key = flag_record['flag_id'].split('-')[0]
        chapter_total = db.execute(
            'SELECT COUNT(*) as cnt FROM flags WHERE flag_id LIKE ?',
            [chapter_key + '-%']
        ).fetchone()['cnt']
        chapter_done = db.execute(
            'SELECT COUNT(DISTINCT flag_id) as cnt FROM submissions WHERE user_id=? AND correct=1 AND flag_id LIKE ?',
            [session['user_id'], chapter_key + '-%']
        ).fetchone()['cnt']
        
        chapter_completed = chapter_done >= chapter_total
        total_flags = len(FLAGS)
        all_completed = score >= total_flags
        
        result = {
            'correct': True,
            'duplicate': False,
            'message': f'Flag captured! +{POINTS_PER_FLAG} points',
            'flag_id': flag_record['flag_id'],
            'description': flag_record['description'],
            'score': score * POINTS_PER_FLAG,
            'total_captured': score,
            'total_flags': total_flags,
        }
        
        if chapter_completed:
            result['chapter_completed'] = True
            result['chapter_key'] = chapter_key
            result['chapter_progress'] = f'{chapter_done}/{chapter_total}'
            result['share_text'] = f'🏆 I just completed {chapter_key} in The PenTrix CTF Lab! {chapter_done}/{chapter_total} flags captured. Test your skills at pentrix-lab.com #CTF #CyberSecurity #PenTrix #ThePenTrix'
        
        if all_completed:
            result['all_completed'] = True
            result['share_text'] = f'🎉 I completed ALL {total_flags} challenges in The PenTrix CTF Lab! A masterclass in web security. #CTF #CyberSecurity #PenTrix #ThePenTrix'
        
        return jsonify(result)
    else:
        # Record incorrect attempt
        db.execute(
            'INSERT INTO submissions (user_id, flag_id, correct) VALUES (?, ?, 0)',
            [session['user_id'], flag_id or 'unknown']
        )
        db.commit()
        
        return jsonify({
            'correct': False,
            'message': 'Incorrect flag. Keep trying!'
        })


@scoreboard_bp.route('/scoreboard/my')
def my_progress():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    
    # Get captured flags
    captured = db.execute('''
        SELECT s.flag_id, s.submitted_at, f.description, f.chapter
        FROM submissions s
        JOIN flags f ON s.flag_id=f.flag_id
        WHERE s.user_id=? AND s.correct=1
        ORDER BY s.submitted_at DESC
    ''', [session['user_id']]).fetchall()
    
    # Get stats per chapter
    chapters = {}
    for flag_id in FLAGS:
        chapter = flag_id.split('-')[0]
        if chapter not in chapters:
            chapters[chapter] = {'total': 0, 'captured': 0}
        chapters[chapter]['total'] += 1
    
    for c in captured:
        chapter = c['flag_id'].split('-')[0]
        if chapter in chapters:
            chapters[chapter]['captured'] += 1
    
    # Get incorrect attempts count
    incorrect = db.execute(
        'SELECT COUNT(*) as c FROM submissions WHERE user_id=? AND correct=0',
        [session['user_id']]
    ).fetchone()['c']
    
    total_flags = len(FLAGS)
    captured_count = len(captured)
    
    return render_template('scoreboard/my_progress.html',
        captured=captured,
        chapters=chapters,
        incorrect_attempts=incorrect,
        total_flags=total_flags,
        captured_count=captured_count,
        score=captured_count * POINTS_PER_FLAG
    )


@scoreboard_bp.route('/scoreboard/hints/<flag_id>/<int:tier>')
def get_hint(flag_id, tier):
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
    
    if tier not in (1, 2, 3):
        return jsonify({'error': 'Invalid hint tier'}), 400
    
    db = get_db()
    
    # Check if already unlocked
    existing = db.execute(
        'SELECT * FROM hint_unlocks WHERE user_id=? AND flag_id=? AND tier=?',
        [session['user_id'], flag_id, tier]
    ).fetchone()
    
    hint = db.execute(
        'SELECT * FROM hints WHERE flag_id=? AND tier=?',
        [flag_id, tier]
    ).fetchone()
    
    if not hint:
        return jsonify({'error': 'Hint not found'}), 404
    
    if not existing:
        # Unlock the hint (costs points)
        db.execute(
            'INSERT OR IGNORE INTO hint_unlocks (user_id, flag_id, tier) VALUES (?, ?, ?)',
            [session['user_id'], flag_id, tier]
        )
        db.commit()
    
    return jsonify({
        'hint': hint['content'],
        'tier': tier,
        'cost': hint['points_cost'],
        'already_unlocked': existing is not None
    })


# API for scoreboard summary
@scoreboard_bp.route('/api/scoreboard/summary')
def scoreboard_summary():
    db = get_db()
    leaders = db.execute('''
        SELECT u.username,
            COUNT(DISTINCT s.flag_id) as flags_captured,
            COUNT(DISTINCT s.flag_id) * ? as score
        FROM users u
        LEFT JOIN submissions s ON u.id=s.user_id AND s.correct=1
        GROUP BY u.id
        HAVING flags_captured > 0
        ORDER BY flags_captured DESC
        LIMIT 20
    ''', [POINTS_PER_FLAG]).fetchall()
    
    return jsonify({
        'leaderboard': [{'username': l['username'], 'flags': l['flags_captured'], 'score': l['score']} for l in leaders],
        'total_challenges': len(FLAGS)
    })

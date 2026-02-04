"""
seed.py — Database seeder for The PenTrix
Populates initial data, users, flags, hints, and sample content.
Run during Docker build or manually to reset data.
"""
import os
import sys

# Set database path for seeding
os.environ.setdefault('DATABASE_PATH', '/app/data/pentrix.db')

from db import init_db
from flags import FLAGS, FLAG_VALUES, HINTS, generate_flag

def seed_database():
    """Seed the database with all initial data."""
    conn = init_db()
    cursor = conn.cursor()
    
    # ═══════════════════════════════════════
    # SEED USERS — intentionally weak passwords stored in PLAINTEXT
    # ═══════════════════════════════════════
    seed_users = [
        # (username, password, email, display_name, role, salary, ssn, credit_card, email_verified, balance)
        ('admin', 'admin', 'admin@pentrix.corp', 'System Administrator', 'superadmin', 150000, '123-45-6789', '4111-1111-1111-1111', 1, 50000.0),
        ('alice', 'password123', 'alice@pentrix.corp', 'Alice Johnson', 'user', 75000, '234-56-7890', '4222-2222-2222-2222', 1, 1000.0),
        ('bob', 'letmein', 'bob@pentrix.corp', 'Bob Smith', 'user', 68000, '345-67-8901', '4333-3333-3333-3333', 1, 1500.0),
        ('charlie', 'qwerty', 'charlie@pentrix.corp', 'Charlie Davis', 'user', 95000, '456-78-9012', '4444-4444-4444-4444', 1, 2000.0),
        ('hr_manager', 'hr2024', 'hr@pentrix.corp', 'HR Manager', 'admin', 120000, '567-89-0123', '4555-5555-5555-5555', 1, 10000.0),
        ('dev_user', 'dev_secret', 'dev@pentrix.corp', 'Developer Account', 'user', 85000, '678-90-1234', '4666-6666-6666-6666', 1, 3000.0),
    ]
    
    for user in seed_users:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO users (username, password, email, display_name, role, salary, ssn, credit_card, email_verified, balance)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', user)
        except Exception as e:
            print(f"Warning: Could not insert user {user[0]}: {e}")
    
    # ═══════════════════════════════════════
    # SEED API KEYS
    # ═══════════════════════════════════════
    api_keys = [
        (1, 'sk-pentrix-admin-key-1234', 'admin'),
        (6, 'sk-pentrix-dev-key-5678', 'read'),
        (5, 'sk-pentrix-hr-key-9012', 'read,write'),
    ]
    
    for key in api_keys:
        try:
            cursor.execute('INSERT OR IGNORE INTO api_keys (user_id, key_value, permissions) VALUES (?, ?, ?)', key)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED FLAGS
    # ═══════════════════════════════════════
    for flag_id, description in FLAGS.items():
        flag_value = FLAG_VALUES[flag_id]
        # Extract chapter from flag_id
        chapter = flag_id.split('-')[0]
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO flags (flag_id, flag_value, chapter, description)
                VALUES (?, ?, ?, ?)
            ''', (flag_id, flag_value, chapter, description))
        except Exception as e:
            print(f"Warning: Could not insert flag {flag_id}: {e}")
    
    # ═══════════════════════════════════════
    # SEED HINTS
    # ═══════════════════════════════════════
    for flag_id, hint_list in HINTS.items():
        for hint in hint_list:
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO hints (flag_id, tier, content, points_cost)
                    VALUES (?, ?, ?, ?)
                ''', (flag_id, hint['tier'], hint['content'], hint['points_cost']))
            except Exception:
                pass
    
    # ═══════════════════════════════════════
    # SEED SAMPLE POSTS (for realism + XSS targets)
    # ═══════════════════════════════════════
    posts = [
        (1, 'Welcome to PenTrix Corp Portal', 'Welcome to our new internal portal! Please use this system for all project management and communication.', 1),
        (2, 'Q4 Project Deadline Update', 'All teams please note the updated deadline for Q4 deliverables. Check your project dashboards for details.', 1),
        (3, 'Office Holiday Schedule 2024', 'Please refer to the HR section for the complete holiday schedule. Remember to submit leave requests early.', 1),
        (4, 'Server Maintenance Notice', 'Scheduled maintenance window: Every Sunday 2AM-6AM. Please save your work before this window.', 1),
        (5, 'New Employee Onboarding Guide', 'Welcome new hires! Please complete your profile setup and verify your email to access all portal features.', 1),
    ]
    
    for post in posts:
        try:
            cursor.execute('INSERT OR IGNORE INTO posts (user_id, title, content, is_public) VALUES (?, ?, ?, ?)', post)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED SAMPLE COMMENTS
    # ═══════════════════════════════════════
    comments = [
        (1, 2, 'Great to be here! Looking forward to the new system.'),
        (1, 3, 'Thanks for the update on the deadline.'),
        (2, 4, 'Will the holiday schedule be updated for remote workers?'),
        (3, 1, 'Good timing on the maintenance notice.'),
    ]
    
    for comment in comments:
        try:
            cursor.execute('INSERT OR IGNORE INTO comments (post_id, user_id, body) VALUES (?, ?, ?)', comment)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED SAMPLE MESSAGES (IDOR targets)
    # ═══════════════════════════════════════
    messages = [
        (1, 2, 'Welcome aboard!', 'Hi Alice, welcome to PenTrix Corp. Please complete your onboarding checklist.', 0),
        (1, 5, 'Salary Review - CONFIDENTIAL', 'HR Manager, please process the salary adjustments for Q4. Attached is the master spreadsheet.', 0),
        (4, 1, 'Server Access Request', 'Admin, I need SSH access to the production servers for the maintenance window. My SSH key is already uploaded.', 0),
        (5, 4, 'Re: Salary Review', 'Admin, I have processed the adjustments. Charlie\'s new salary is $95,000.', 0),
        (2, 3, 'Project Collaboration', 'Hey Bob, want to collaborate on the new frontend project? I have some ideas.', 1),
        (6, 1, 'API Key Request', 'Admin, I need a new API key for the staging environment. The current one (sk-pentrix-dev-key-5678) needs elevated permissions.', 0),
    ]
    
    for msg in messages:
        try:
            cursor.execute('INSERT OR IGNORE INTO messages (sender_id, recipient_id, subject, body, is_read) VALUES (?, ?, ?, ?, ?)', msg)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED CORPORATE NARRATIVE MESSAGES
    # Support the in-app narrative intelligence layer
    # ═══════════════════════════════════════
    narrative_messages = [
        (6, 1, 'SSRF in /tools/fetch', 'Admin, I was testing the fetch tool and realized I can request http://internal:8080/flag from within the app. The internal service returns sensitive data with no auth. Should we add a URL whitelist?', 0),
        (1, 6, 'RE: SSRF in /tools/fetch', 'Good catch. I\'ll add it to the backlog. For now, internal:8080 is only reachable from the web container. Also, someone should check the ping tool — I heard it doesn\'t sanitize semicolons.', 0),
        (4, 5, 'Password Policy Concern', 'HR, did you know all our passwords are stored in plaintext? I can see them in the database. Also, the /reports/export endpoint shows everyone\'s SSN without authorization checks.', 0),
        (5, 1, 'URGENT: Data Exposure', 'Admin, Charlie told me about the plaintext passwords. We also need to address the /reports/export endpoint. Any user can access salary and SSN data. This is a compliance nightmare.', 0),
        (2, 3, 'Found something weird', 'Hey Bob, I was browsing the /files endpoint and noticed I can download anyone\'s files by changing the ID. /files/download/1, /files/download/2 etc. Also, SVG uploads execute JavaScript when viewed!', 0),
        (3, 4, 'GraphQL Introspection', 'Charlie, did you know the /graphql endpoint has introspection enabled? I used it to enumerate all queries and mutations. Found user data, admin operations, and flag lookups all exposed.', 0),
    ]
    
    for msg in narrative_messages:
        try:
            cursor.execute('INSERT OR IGNORE INTO messages (sender_id, recipient_id, subject, body, is_read) VALUES (?, ?, ?, ?, ?)', msg)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED SAMPLE FILES
    # ═══════════════════════════════════════
    files = [
        (1, 'annual_report_2024.pdf', '/app/static/uploads/annual_report_2024.pdf', 0),
        (5, 'salary_master_q4.xlsx', '/app/static/uploads/salary_master_q4.xlsx', 1),
        (4, 'server_config.txt', '/app/static/uploads/server_config.txt', 1),
        (2, 'project_plan.docx', '/app/static/uploads/project_plan.docx', 0),
        (6, 'api_documentation.md', '/app/static/uploads/api_documentation.md', 0),
    ]
    
    for f in files:
        try:
            cursor.execute('INSERT OR IGNORE INTO files (user_id, filename, filepath, is_private) VALUES (?, ?, ?, ?)', f)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED SAMPLE TICKETS (XSS + IDOR targets)
    # ═══════════════════════════════════════
    tickets = [
        (2, 'Cannot access file uploads', 'I am unable to upload files larger than 5MB. Please increase the limit.', 'open'),
        (3, 'Password reset not working', 'The password reset email is not being sent to my address.', 'open'),
        (4, 'VPN Connection Issues', 'Getting timeout errors when connecting to the corporate VPN from home.', 'closed'),
        (6, 'API rate limit too low', 'The current rate limit is too restrictive for our CI/CD pipeline. Please increase.', 'open'),
        (2, 'Profile picture upload fails', 'SVG files are not being accepted as profile pictures.', 'open'),
    ]
    
    for ticket in tickets:
        try:
            cursor.execute('INSERT OR IGNORE INTO tickets (user_id, subject, body, status) VALUES (?, ?, ?, ?)', ticket)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED NARRATIVE TICKETS — Organic clues via support reports
    # ═══════════════════════════════════════
    narrative_tickets = [
        (3, 'CORS issue on external requests', 'When I make a fetch from an external page, the server reflects my Origin header in Access-Control-Allow-Origin. This lets any website read authenticated responses. See /api/docs for affected endpoints.', 'open'),
        (2, 'XML import processes external entities', 'The /tools/xml-import endpoint processes XML with external entities enabled. I was able to read /etc/passwd using an XXE payload. DTD processing should be disabled.', 'open'),
        (6, 'Clickjacking — no X-Frame-Options', 'None of the pages set X-Frame-Options or Content-Security-Policy frame-ancestors. I was able to embed /account/transfer in an iframe and overlay it with a fake button. Classic clickjacking.', 'open'),
        (4, 'Command injection in ping tool', 'The /tools/ping endpoint passes user input directly to os.popen() without sanitization. I entered 127.0.0.1; id and got command execution. This is critical — RCE via a simple semicolon.', 'open'),
    ]
    
    for ticket in narrative_tickets:
        try:
            cursor.execute('INSERT OR IGNORE INTO tickets (user_id, subject, body, status) VALUES (?, ?, ?, ?)', ticket)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED COUPONS (insecure design targets)
    # ═══════════════════════════════════════
    coupons = [
        ('WELCOME2024', 20, 1),
        ('HOLIDAY50', 50, 1),
        ('VIP100', 100, 1),
        ('UNLIMITED', 10, 999),  # Intentional: practically unlimited uses
    ]
    
    for coupon in coupons:
        try:
            cursor.execute('INSERT OR IGNORE INTO coupons (code, discount, uses_left) VALUES (?, ?, ?)', coupon)
        except Exception:
            pass
    
    # ═══════════════════════════════════════
    # SEED APPROVAL REQUESTS
    # ═══════════════════════════════════════
    requests = [
        (2, 'access_request', 'Request access to admin panel for reporting', 'pending'),
        (3, 'budget_approval', 'Q4 budget increase for server infrastructure', 'pending'),
    ]
    
    for req in requests:
        try:
            cursor.execute('INSERT OR IGNORE INTO approval_requests (user_id, request_type, description, status) VALUES (?, ?, ?, ?)', req)
        except Exception:
            pass
    
    conn.commit()
    conn.close()
    print(f"✅ Database seeded successfully with {len(FLAGS)} flags and {len(HINTS)} challenge hints!")

def create_flag_files():
    """Create physical flag files for directory traversal challenges."""
    flag_dir = '/app/flags'
    os.makedirs(flag_dir, exist_ok=True)
    
    # Create flag files for traversal challenges
    traversal_flags = {
        'ch05_c02.txt': generate_flag('CH05-C02'),
        'ch11_c01.txt': generate_flag('CH11-C01'),
        'secret_flag.txt': generate_flag('CH01-C01'),
    }
    
    for filename, flag_value in traversal_flags.items():
        filepath = os.path.join(flag_dir, filename)
        try:
            with open(filepath, 'w') as f:
                f.write(flag_value + '\n')
        except Exception as e:
            print(f"Warning: Could not create flag file {filepath}: {e}")
    
    print(f"✅ Created {len(traversal_flags)} flag files in {flag_dir}")

def create_backup_files():
    """Create backup files that should be discoverable."""
    # Create app.py.bak for CH07-C03
    bak_content = f"""# PenTrix Corp Internal Portal - Backup
# Created: 2024-01-15
# WARNING: This file contains sensitive configuration
# {generate_flag('CH07-C03')}

SECRET_KEY = 'super_secret_key_12345'
DATABASE_URL = 'sqlite:////app/data/pentrix.db'
ADMIN_PASSWORD = 'admin'
API_KEY = 'sk-pentrix-internal-key-9876'
"""
    try:
        with open('/app/app.py.bak', 'w') as f:
            f.write(bak_content)
    except Exception:
        pass
    
    # Create config.json for CH04-C08
    config_content = f'{{"secret_key": "super_secret_key_12345", "api_key": "sk-pentrix-internal-key-9876", "flag": "{generate_flag("CH04-C08")}", "db_backup_path": "/app/data/backup/", "internal_service": "http://internal:8080"}}'
    try:
        with open('/app/config.json', 'w') as f:
            f.write(config_content)
    except Exception:
        pass

    print("✅ Created backup and config files")

if __name__ == '__main__':
    print("🚀 Seeding PenTrix database...")
    seed_database()
    create_flag_files()
    create_backup_files()
    print("✅ All seeding complete!")

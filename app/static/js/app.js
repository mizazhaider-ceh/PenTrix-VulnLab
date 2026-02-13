/**
 * app.js — Main application JavaScript
 * ══════════════════════════════════════
 * PenTrix Corp Portal — Client-side logic
 * 
 * [VULN: CH04-C03] API key hardcoded below
 * [VULN: CH02-C08] Version info in comments
 * 
 * Version: 2.3.3-internal
 * Build: 20240115-dev
 * Author: dev_team@pentrix-corp.internal
 * Internal API: http://internal:8080/api
 * Database: sqlite:////app/data/pentrix.db
 */

// ═══════════════════════════════════════
// [VULN: CH04-C03] Hardcoded API key — discoverable via source inspection
// ═══════════════════════════════════════
const API_KEY = 'sk-pentrix-internal-key-9876';  // [VULN: CH14-C02] exposed API key
const API_BASE = '/api';
const APP_VERSION = '2.3.3';
const DEBUG_MODE = true;  // [VULN: CH02-C01] debug mode flag

// [VULN: CH04-C06] Hardcoded internal URLs
const INTERNAL_ENDPOINTS = {
    users: '/api/users',
    config: '/api/v1/config',
    internal: '/api/v2/internal',
    graphql: '/api/graphql',
    export: '/api/private/export',
    reports: '/api/reports/',
    // TODO: Remove before production
    admin_secret: '/admin2',
    debug_panel: '/debug',
    backup: '/backup/'
};

// ═══════════════════════════════════════
// AJAX helper with API key
// ═══════════════════════════════════════
function apiRequest(url, options = {}) {
    const defaults = {
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY  // [VULN] sends key with every request
        },
        credentials: 'include'  // [VULN: CH15-C04] always sends cookies
    };
    
    return fetch(url, { ...defaults, ...options })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .catch(error => {
            if (DEBUG_MODE) {
                console.error('[PenTrix Debug]', error);  // [VULN: CH02] verbose errors
            }
            throw error;
        });
}

// ═══════════════════════════════════════
// Dashboard functionality
// ═══════════════════════════════════════
function loadDashboard() {
    // Load user info
    apiRequest('/api/users')
        .then(data => {
            if (data.users) {
                console.log('[Debug] Users loaded:', data.users.length);
            }
        })
        .catch(() => {});
}

// ═══════════════════════════════════════
// Search with live results
// ═══════════════════════════════════════
function liveSearch(query) {
    if (!query || query.length < 2) return;
    
    fetch('/dashboard/search?q=' + encodeURIComponent(query))
        .then(r => r.text())
        .then(html => {
            var results = document.getElementById('search-results');
            if (results) {
                results.innerHTML = html;  // [VULN: CH08-C01] reflected content rendered
            }
        });
}

// ═══════════════════════════════════════
// Flag submission with psychology & share
// ═══════════════════════════════════════
function submitFlag(flagValue) {
    return fetch('/scoreboard/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        credentials: 'include',
        body: 'flag=' + encodeURIComponent(flagValue)
    })
    .then(r => r.json())
    .then(data => {
        if (data.correct) {
            if (data.duplicate) {
                showNotification('Already captured! You submitted this flag before.', 'info');
            } else {
                // Milestone messages based on total count
                var total = data.total_captured || 0;
                var msg = data.message || 'Flag captured!';
                var milestones = {
                    1: '🎯 First blood! Your journey begins.',
                    5: '🔥 5 flags! You\'re getting the hang of this.',
                    10: '💪 10 flags! A natural pentester.',
                    25: '⚡ 25 flags! Quarter-way there. Impressive.',
                    50: '🏅 50 flags! You\'re in the top tier now.',
                    75: '🌟 75 flags! A true hacker emerges.',
                    100: '💎 100 flags! Triple digits. Elite status.',
                    150: '🔮 150 flags! Almost there. The finish line awaits.',
                    183: '🏆 ALL 183 FLAGS! You are a PenTrix Master!'
                };
                if (milestones[total]) {
                    msg += '<br><span style="font-size:0.9em;color:var(--accent);">' + milestones[total] + '</span>';
                }
                showNotification(msg, 'success');
                launchConfetti();
                
                // Chapter completion celebration
                if (data.chapter_completed) {
                    setTimeout(function() {
                        showShareModal(data.share_text, data.chapter_key, false);
                    }, 1500);
                }
                
                // ALL flags celebration
                if (data.all_completed) {
                    setTimeout(function() {
                        showShareModal(data.share_text, null, true);
                    }, 2000);
                }
            }
        } else {
            showNotification(data.message || 'Incorrect flag', 'error');
        }
        return data;
    });
}

// ═══════════════════════════════════════
// Social Share Modal
// ═══════════════════════════════════════
function showShareModal(shareText, chapterKey, isAllComplete) {
    var existing = document.getElementById('share-modal');
    if (existing) existing.remove();
    
    var title = isAllComplete 
        ? '🏆 ALL CHALLENGES COMPLETE!' 
        : '🎉 Chapter ' + (chapterKey || '') + ' Complete!';
    var subtitle = isAllComplete
        ? 'You\'ve mastered every vulnerability in The PenTrix. Share your achievement!'
        : 'You\'ve conquered this chapter. Let the world know!';
    
    var linkedInUrl = 'https://www.linkedin.com/sharing/share-offsite/?url=' + encodeURIComponent('https://github.com/pentrix-lab') + '&summary=' + encodeURIComponent(shareText);
    var twitterUrl = 'https://twitter.com/intent/tweet?text=' + encodeURIComponent(shareText);
    
    var modal = document.createElement('div');
    modal.id = 'share-modal';
    modal.innerHTML = '<div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9998;backdrop-filter:blur(4px);" onclick="document.getElementById(\'share-modal\').remove()"></div>' +
        '<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:9999;background:var(--card-bg);border:1px solid var(--border-color);border-radius:16px;padding:36px;max-width:480px;width:90%;text-align:center;box-shadow:0 24px 80px rgba(0,0,0,0.5);">' +
        '<div style="font-size:2.5rem;margin-bottom:12px;">' + (isAllComplete ? '🏆' : '🎉') + '</div>' +
        '<h2 style="color:var(--text-primary);font-size:1.3rem;margin-bottom:6px;">' + title + '</h2>' +
        '<p style="color:var(--text-muted);font-size:0.88rem;margin-bottom:20px;">' + subtitle + '</p>' +
        '<textarea id="share-text" readonly style="width:100%;height:80px;background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:8px;color:var(--text-secondary);padding:12px;font-size:0.82rem;resize:none;margin-bottom:16px;">' + shareText + '</textarea>' +
        '<div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;">' +
        '<a href="' + linkedInUrl + '" target="_blank" rel="noopener" class="btn btn-primary" style="display:inline-flex;align-items:center;gap:6px;background:#0077B5;border-color:#0077B5;">🔗 Share on LinkedIn</a>' +
        '<a href="' + twitterUrl + '" target="_blank" rel="noopener" class="btn btn-sm" style="display:inline-flex;align-items:center;gap:6px;background:#1DA1F2;color:white;border-color:#1DA1F2;">🐦 Tweet</a>' +
        '<button onclick="copyToClipboard(document.getElementById(\'share-text\').value)" class="btn btn-sm" style="display:inline-flex;align-items:center;gap:6px;">📋 Copy</button>' +
        '</div>' +
        '<button onclick="document.getElementById(\'share-modal\').remove()" style="margin-top:16px;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:0.82rem;">Close</button>' +
        '<p style="color:var(--text-muted);font-size:0.72rem;margin-top:12px;opacity:0.7;">— from Izaz and The PenTrix 🔐</p>' +
        '</div>';
    document.body.appendChild(modal);
}

// ═══════════════════════════════════════
// Notification system
// ═══════════════════════════════════════
function showNotification(message, type = 'info') {
    var container = document.getElementById('notifications') || document.body;
    var notif = document.createElement('div');
    notif.className = 'notification notification-' + type;
    notif.innerHTML = message;  // [VULN: minor] innerHTML with controlled data
    container.appendChild(notif);
    
    setTimeout(function() {
        notif.classList.add('fade-out');
        setTimeout(function() { notif.remove(); }, 300);
    }, 4000);
}

// ═══════════════════════════════════════
// File upload preview
// ═══════════════════════════════════════
function previewFile(input) {
    if (input.files && input.files[0]) {
        var file = input.files[0];
        var preview = document.getElementById('file-preview');
        
        // [VULN: CH13-C10] Client-side only validation — easily bypassed
        var allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain'];
        if (!allowedTypes.includes(file.type)) {
            // Only client-side check — server accepts anything
            showNotification('Warning: File type ' + file.type + ' may not be allowed', 'warning');
        }
        
        if (preview && file.type.startsWith('image/')) {
            var reader = new FileReader();
            reader.onload = function(e) {
                preview.src = e.target.result;
                preview.style.display = 'block';
            };
            reader.readAsDataURL(file);
        }
    }
}

// ═══════════════════════════════════════
// Sidebar toggle
// ═══════════════════════════════════════
function toggleSidebar() {
    var sidebar = document.getElementById('sidebar');
    var main = document.getElementById('main-content');
    if (sidebar) {
        sidebar.classList.toggle('collapsed');
        if (main) main.classList.toggle('expanded');
    }
}

// ═══════════════════════════════════════
// Copy to clipboard utility
// ═══════════════════════════════════════
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showNotification('Copied to clipboard!', 'success');
    }).catch(function() {
        // Fallback
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showNotification('Copied!', 'success');
    });
}

// ═══════════════════════════════════════
// Challenge hint unlock
// ═══════════════════════════════════════
function unlockHint(flagId, tier) {
    fetch('/scoreboard/hints/' + encodeURIComponent(flagId) + '/' + tier, {
        credentials: 'include'
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) {
            showNotification(data.error, 'error');
        } else {
            var hintEl = document.getElementById('hint-' + flagId + '-' + tier);
            if (hintEl) {
                hintEl.innerHTML = data.hint;
                hintEl.classList.add('unlocked');
            }
            showNotification('Hint unlocked! (-' + data.cost + ' points)', 'info');
        }
    });
}

// ═══════════════════════════════════════
// Init on page load
// ═══════════════════════════════════════
document.addEventListener('DOMContentLoaded', function() {
    // Debug console info
    if (DEBUG_MODE) {
        console.log('%c╔══════════════════════════════════════╗', 'color: #10b981; font-weight: bold');
        console.log('%c║   🔐 PenTrix Corp Internal Portal   ║', 'color: #10b981; font-size: 14px; font-weight: bold');
        console.log('%c╚══════════════════════════════════════╝', 'color: #10b981; font-weight: bold');
        console.log('%c[BUILD] Version: ' + APP_VERSION + '-dev (Debug Mode: ON)', 'color: #f59e0b');
        console.log('%c[VULN] API Key leaked: ' + API_KEY, 'color: #ef4444');
        console.log('%c[VULN] Secret Key: super_secret_key_12345', 'color: #ef4444');
        console.log('%c[INFO] Endpoints:', 'color: #38bdf8', INTERNAL_ENDPOINTS);
        console.log('%c[INFO] Try: fetch("/debug").then(r=>r.json()).then(d=>console.log(d))', 'color: #a78bfa');
        console.log('%c[INFO] JWT Secret: super_secret_key_12345 (HS256)', 'color: #ef4444');
        console.log('%c[TODO] Remove debug logging before production deployment!', 'color: #f59e0b; font-weight: bold');
    }
    
    // [VULN: CH04-C03] Leaked config in window object
    window.__PENTRIX_CONFIG__ = {
        apiKey: API_KEY,
        version: APP_VERSION,
        internalService: 'http://internal:8080',
        redisUrl: 'redis://pentrix_redis:6379',
        jwtSecret: 'super_secret_key_12345',
        adminEmail: 'admin@pentrix-corp.internal',
        endpoints: INTERNAL_ENDPOINTS
    };
    
    // Auto-load dashboard if on that page
    if (window.location.pathname.startsWith('/dashboard')) {
        loadDashboard();
    }
});

/**
 * dom-lab.js — DOM Vulnerability Playground
 * ══════════════════════════════════════════
 * INTENTIONALLY VULNERABLE JavaScript for Chapter 9 challenges.
 * Every vulnerability is labeled with: // [VULN: CH09-C##]
 */

// ═══════════════════════════════════════
// [VULN: CH09-C01] DOM XSS via URL hash fragment
// ═══════════════════════════════════════
function initHashXSS() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        var decoded = decodeURIComponent(hash);
        // INTENTIONALLY VULNERABLE: writes decoded hash directly to innerHTML
        var el = document.getElementById('hash-output');
        if (el) {
            el.innerHTML = 'Welcome, ' + decoded;  // [VULN: CH09-C01] XSS
        }
    }
}

// ═══════════════════════════════════════
// [VULN: CH09-C02] DOM XSS via postMessage listener
// ═══════════════════════════════════════
function initPostMessageXSS() {
    window.addEventListener('message', function(event) {
        // INTENTIONALLY VULNERABLE: no origin check, no sanitization
        var el = document.getElementById('postmessage-output');
        if (el) {
            el.innerHTML = event.data;  // [VULN: CH09-C02] XSS via postMessage
        }
        
        // Also update notification area
        var notif = document.getElementById('notification');
        if (notif) {
            notif.innerHTML = '<div class="alert">' + event.data + '</div>';
        }
    });
}

// ═══════════════════════════════════════
// [VULN: CH09-C03] Open redirect via ?redirect= parameter
// ═══════════════════════════════════════
function initOpenRedirect() {
    var params = new URLSearchParams(window.location.search);
    var redirect = params.get('redirect');
    
    if (redirect) {
        // INTENTIONALLY VULNERABLE: no validation on redirect target
        var el = document.getElementById('redirect-info');
        if (el) {
            el.innerHTML = 'Redirecting to: <a href="' + redirect + '">' + redirect + '</a>';
        }
        
        // Auto-redirect after 2 seconds if autoredirect param set
        if (params.get('auto') === 'true') {
            setTimeout(function() {
                window.location = redirect;  // [VULN: CH09-C03] open redirect
            }, 2000);
        }
    }
}

// ═══════════════════════════════════════
// [VULN: CH09-C04] DOM Clobbering via form id attribute
// ═══════════════════════════════════════
function initDOMClobbering() {
    // INTENTIONALLY VULNERABLE: references DOM elements by ID which can be clobbered
    var config = window.config || { apiUrl: '/api/safe', role: 'user' };
    
    var el = document.getElementById('clobber-output');
    if (el) {
        el.innerHTML = 'Config API URL: ' + config.apiUrl + '<br>Role: ' + config.role;
    }
    
    // If an attacker injects <form id="config"><input name="apiUrl" value="https://evil.com"></form>
    // then window.config will be the form element, and config.apiUrl will be the input
}

// ═══════════════════════════════════════
// [VULN: CH09-C05] Client-side template injection (AngularJS)
// ═══════════════════════════════════════
function initCSTE() {
    var params = new URLSearchParams(window.location.search);
    var name = params.get('name') || '';
    
    // INTENTIONALLY VULNERABLE: user input put into AngularJS template context
    var el = document.getElementById('angular-output');
    if (el) {
        // This will be processed by AngularJS if angular-old.js is loaded
        el.setAttribute('ng-bind-html', name);
        el.innerHTML = name;  // [VULN: CH09-C05] CSTI
    }
}

// ═══════════════════════════════════════
// [VULN: CH09-C06] DOM XSS via document.write
// ═══════════════════════════════════════
function initDocumentWriteXSS() {
    var params = new URLSearchParams(window.location.search);
    var title = params.get('title');
    
    if (title) {
        // INTENTIONALLY VULNERABLE: user input passed to document.write
        var container = document.getElementById('docwrite-container');
        if (container) {
            container.innerHTML = '';  // clear
            // Use innerHTML on a specific container instead of document.write
            // (same vulnerability, works better in modern browsers)
            container.innerHTML = '<h3>' + title + '</h3>';  // [VULN: CH09-C06] XSS
        }
    }
}

// ═══════════════════════════════════════
// [VULN: CH09-C07] DOM XSS via innerHTML assignment
// ═══════════════════════════════════════
function initInnerHTMLXSS() {
    var params = new URLSearchParams(window.location.search);
    var bio = params.get('bio');
    
    if (bio) {
        // INTENTIONALLY VULNERABLE: direct innerHTML from URL parameter
        var el = document.getElementById('bio-output');
        if (el) {
            el.innerHTML = bio;  // [VULN: CH09-C07] XSS via innerHTML
        }
    }
}

// ═══════════════════════════════════════
// [VULN: CH09-C08] Open redirect via javascript: URI
// ═══════════════════════════════════════
function initJavascriptURI() {
    var params = new URLSearchParams(window.location.search);
    var link = params.get('link');
    
    if (link) {
        // INTENTIONALLY VULNERABLE: allows javascript: protocol in href
        var el = document.getElementById('dynamic-link');
        if (el) {
            el.href = link;  // [VULN: CH09-C08] javascript: URI injection
            el.innerHTML = 'Click here: ' + link;
            el.style.display = 'inline-block';
        }
    }
}

// ═══════════════════════════════════════
// [VULN: CH09-C09] Prototype pollution via merge function
// ═══════════════════════════════════════
function merge(target, source) {
    for (var key in source) {
        if (source.hasOwnProperty(key)) {
            // INTENTIONALLY VULNERABLE: no __proto__ check
            if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
                if (!target[key]) target[key] = {};
                merge(target[key], source[key]);  // [VULN: CH09-C09] recursive merge
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}

function initPrototypePollution() {
    var params = new URLSearchParams(window.location.search);
    var jsonStr = params.get('config');
    
    if (jsonStr) {
        try {
            var userConfig = JSON.parse(decodeURIComponent(jsonStr));
            var appConfig = {};
            
            // INTENTIONALLY VULNERABLE: merge without prototype protection
            merge(appConfig, userConfig);
            
            var el = document.getElementById('proto-output');
            if (el) {
                // If __proto__.isAdmin was polluted, this will show true
                var testObj = {};
                el.innerHTML = 'Config merged. isAdmin: ' + (testObj.isAdmin || 'false') +
                               '<br>Polluted: ' + (({}).isAdmin ? 'YES - Prototype pollution successful!' : 'No');
                
                if (({}).isAdmin) {
                    el.innerHTML += '<br><strong>FLAG hint: Prototype pollution achieved!</strong>';
                }
            }
        } catch(e) {
            var el = document.getElementById('proto-output');
            if (el) el.innerHTML = 'Error parsing JSON: ' + e.message;
        }
    }
}

// ═══════════════════════════════════════
// [VULN: CH09-C10] DOM XSS via location.search eval
// ═══════════════════════════════════════
function initEvalXSS() {
    var params = new URLSearchParams(window.location.search);
    var expr = params.get('calc');
    
    if (expr) {
        try {
            // INTENTIONALLY VULNERABLE: eval() on user input
            var result = eval(expr);  // [VULN: CH09-C10] XSS/RCE via eval
            
            var el = document.getElementById('eval-output');
            if (el) {
                el.innerHTML = 'Result: ' + result;
            }
        } catch(e) {
            var el = document.getElementById('eval-output');
            if (el) el.innerHTML = 'Error: ' + e.message;
        }
    }
}


// ═══════════════════════════════════════
// Theme toggler (benign feature)
// ═══════════════════════════════════════
function initTheme() {
    var params = new URLSearchParams(window.location.search);
    var theme = params.get('theme');
    if (theme) {
        document.body.className = theme;  // allows class injection (minor)
    }
}


// ═══════════════════════════════════════
// Initialize all DOM labs on page load
// ═══════════════════════════════════════
document.addEventListener('DOMContentLoaded', function() {
    initHashXSS();
    initPostMessageXSS();
    initOpenRedirect();
    initDOMClobbering();
    initCSTE();
    initDocumentWriteXSS();
    initInnerHTMLXSS();
    initJavascriptURI();
    initPrototypePollution();
    initEvalXSS();
    initTheme();
    
    console.log('[PenTrix DOM Lab] All DOM vulnerability demos initialized.');
    console.log('[PenTrix DOM Lab] Try these URL parameters:');
    console.log('  #<script>alert(1)</script>                    → CH09-C01 Hash XSS');
    console.log('  ?redirect=https://evil.com&auto=true          → CH09-C03 Open Redirect');
    console.log('  ?title=<img src=x onerror=alert(1)>           → CH09-C06 document.write XSS');
    console.log('  ?bio=<svg onload=alert(1)>                    → CH09-C07 innerHTML XSS');
    console.log('  ?link=javascript:alert(1)                     → CH09-C08 javascript: URI');
    console.log('  ?config={"__proto__":{"isAdmin":true}}        → CH09-C09 Prototype Pollution');
    console.log('  ?calc=alert(document.cookie)                  → CH09-C10 eval XSS');
});

// Listen for hash changes too (for CH09-C01)
window.addEventListener('hashchange', initHashXSS);

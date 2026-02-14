/**
 * angular-old.js — Minimal AngularJS 1.x Stub for CSTI Challenge (CH09-C05)
 * ============================================================================
 * This is a minimal stub simulating AngularJS 1.x expression evaluation
 * for the Client-Side Template Injection challenge.
 *
 * INTENTIONALLY VULNERABLE — DO NOT USE IN PRODUCTION
 *
 * In real AngularJS, expressions like {{7*7}} are evaluated in scope context.
 * This stub provides just enough functionality for the CSTI demo.
 */

(function(window) {
    'use strict';

    var angular = {
        version: { full: '1.5.8-pentrix-stub' },
        module: function() { return angular; },
        controller: function() { return angular; },
        directive: function() { return angular; }
    };

    // Simple expression evaluator for AngularJS-style {{expressions}}
    function evaluateExpression(expr) {
        try {
            // [VULN: CH09-C05] Evaluates expressions within {{ }}
            return new Function('return (' + expr + ')')();
        } catch(e) {
            return expr;
        }
    }

    // Process AngularJS-style template expressions in the DOM
    function processTemplates() {
        var elements = document.querySelectorAll('[ng-app], [data-ng-app], .ng-scope');
        
        // Also process the angular-output element specifically
        var outputEl = document.getElementById('angular-output');
        if (outputEl) {
            elements = Array.prototype.slice.call(elements);
            elements.push(outputEl);
        }

        elements.forEach(function(el) {
            var html = el.innerHTML;
            var pattern = /\{\{(.+?)\}\}/g;
            var match;
            var newHtml = html;

            while ((match = pattern.exec(html)) !== null) {
                var expr = match[1].trim();
                var result = evaluateExpression(expr);
                newHtml = newHtml.replace(match[0], result);
            }

            if (newHtml !== html) {
                el.innerHTML = newHtml;
            }
        });
    }

    // Auto-bootstrap on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            processTemplates();
        });
    } else {
        // DOM already loaded, run on next tick to let other scripts set up
        setTimeout(processTemplates, 100);
    }

    // Also observe DOM changes to process dynamically added content
    if (window.MutationObserver) {
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'childList' || mutation.type === 'characterData') {
                    setTimeout(processTemplates, 50);
                }
            });
        });

        document.addEventListener('DOMContentLoaded', function() {
            observer.observe(document.body, {
                childList: true,
                subtree: true,
                characterData: true
            });
        });
    }

    // Expose globally
    window.angular = angular;
    window._pentrixProcessTemplates = processTemplates;

    console.log('[PenTrix] AngularJS 1.5.8 stub loaded (CSTI challenge active)');

})(window);

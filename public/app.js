/* PenTrix VulnLab shell enhancements. Progressive: the page works without
   this file. Copy buttons degrade to selectable text, filters degrade to
   GET forms, reveal animations degrade to visible content. */
(function () {
  'use strict';
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var raf = window.requestAnimationFrame || function (fn) { fn(); };
  var canObserve = 'IntersectionObserver' in window && !reduced;
  if (canObserve) document.documentElement.classList.add('js');

  /* Copy buttons: [data-copy] copies the payload/flag text beside it. */
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-copy]') : null;
    if (!btn) return;
    var scope = btn.closest('.payload') || btn.closest('.flag-well') || document;
    var src = scope.querySelector('.payload-body, code');
    var text = src ? src.textContent : '';
    var done = function () {
      if (btn.dataset.done) return;
      btn.dataset.done = '1';
      var old = btn.textContent;
      btn.classList.add('copied');
      btn.textContent = 'Copied';
      setTimeout(function () { btn.classList.remove('copied'); btn.textContent = old; delete btn.dataset.done; }, 1500);
    };
    var fallback = function () {
      if (!src) return;
      var r = document.createRange();
      r.selectNodeContents(src);
      var s = window.getSelection();
      s.removeAllRanges();
      s.addRange(r);
      try { document.execCommand('copy'); } catch (_) { /* selection stays */ }
      done();
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  });

  /* Restart-volatility notice (P1-3): the server fills the banner only for
     sessions that survived a lab restart, and only once. Dismiss just
     hides it; the next page load no longer renders it. */
  Array.prototype.forEach.call(document.querySelectorAll('[data-boot-notice]'), function (el) {
    el.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-boot-dismiss]') : null;
      if (btn) el.hidden = true;
    });
  });

  /* Claim-status widgets (beacon challenges): poll the module's claim-status
     endpoint and flip the status pill when the server has captured the flag. */
  Array.prototype.forEach.call(document.querySelectorAll('[data-status-url]'), function (el) {
    var url = el.getAttribute('data-status-url');
    var txt = el.querySelector('.claim-text');
    var check = function () {
      fetch(url, { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (j) {
        el.classList.toggle('status-captured', !!j.captured);
        el.classList.toggle('status-missing', !j.captured);
        if (txt) txt.textContent = j.captured ? 'Flag captured' : 'No valid beacon received yet';
      }).catch(function () { /* keep last state */ });
    };
    check();
    setInterval(check, 3000);
  });

  /* Live filters: enhance the GET filter forms so results update without a
     reload. Without JS the forms submit normally (server-side filtering). */
  function wireFilter(formId, opts) {
    var form = document.getElementById(formId);
    if (!form) return;
    var items = Array.prototype.slice.call(document.querySelectorAll(opts.items));
    var empty = document.querySelector(opts.empty);
    var live = document.querySelector('[data-filter-live]');
    var apply = function () {
      var q = (form.querySelector('[name=q]') || {}).value || '';
      q = q.toLowerCase().trim();
      var sel = form.querySelector('[name=difficulty],[name=status]');
      var f = sel ? String(sel.value).toLowerCase() : 'all';
      var shown = 0;
      items.forEach(function (it) {
        var hay = (it.getAttribute('data-search') || '').toLowerCase();
        var key = (it.getAttribute('data-key') || '').toLowerCase();
        var show = (!q || hay.indexOf(q) !== -1) && (f === 'all' || key === f);
        var hidden = it.style.display === 'none';
        if (it._ft) { clearTimeout(it._ft); it._ft = null; }
        if (show) {
          if (hidden) {
            it.style.display = '';
            if (!reduced) {
              /* fade in: display first, then two frames so the transition runs */
              it.style.opacity = '0';
              raf(function () {
                raf(function () { it.style.opacity = '1'; });
              });
              it._ft = setTimeout(function () { it.style.opacity = ''; it._ft = null; }, 260);
            }
          } else { it.style.opacity = ''; }
          shown++;
        } else if (!hidden) {
          if (!reduced) {
            it.style.opacity = '0';
            it._ft = setTimeout(function () { it.style.display = 'none'; it.style.opacity = ''; it._ft = null; }, 220);
          } else { it.style.display = 'none'; }
        }
      });
      if (empty) empty.hidden = shown !== 0;
      /* Announce the new result count (and the empty state, in the empty
         element's own words) in the page's polite live region, so screen
         reader users hear what sighted users see when results vanish or
         come back. Only a changed text is announced by the browser. */
      if (live) {
        live.textContent = shown === 0
          ? (empty ? empty.textContent.trim() : 'No results match your filter.')
          : shown + ' ' + (shown === 1 ? (opts.one || 'result') : (opts.unit || 'results')) + ' shown.';
      }
      if (opts.after) opts.after(shown);
    };
    form.addEventListener('submit', function (e) { e.preventDefault(); apply(); });
    form.addEventListener('input', apply);
    var reset = form.querySelector('[type=reset]');
    if (reset) reset.addEventListener('click', function () { setTimeout(apply, 0); });
  }

  /* Home: filter module cards. */
  wireFilter('home-filter', { items: '.grid .clay-card', empty: '[data-home-empty]', unit: 'modules', one: 'module' });

  /* Scoreboard: filter challenge rows, hide modules with no visible rows. */
  wireFilter('sb-filter', {
    items: '.sb-module tbody tr',
    empty: '[data-sb-empty]',
    unit: 'challenges',
    one: 'challenge',
    after: function () {
      Array.prototype.forEach.call(document.querySelectorAll('.sb-module'), function (sec) {
        var visible = Array.prototype.filter.call(sec.querySelectorAll('tbody tr'), function (tr) {
          return tr.style.display !== 'none';
        }).length;
        sec.style.display = visible ? '' : 'none';
      });
    }
  });

  /* Entrance stagger: cards fade-rise with 40ms steps, capped at 8 items.
     Under .js the stylesheet hides .reveal elements until the observer
     adds .in, so the observer is load-bearing, not just an enhancement:
     if it never fires for an element (occluded layout, observer quirks),
     the content would stay invisible. The 2s force-reveal below is the
     safety net: anything still hidden after 2 seconds is shown. Never
     used on scoreboard rows (they must paint instantly). */
  if (canObserve) {
    var els = Array.prototype.slice.call(document.querySelectorAll('.reveal'));
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); }
      });
    }, { threshold: 0.05 });
    els.forEach(function (el, i) {
      el.style.transitionDelay = Math.min(i, 8) * 40 + 'ms';
      io.observe(el);
    });
    setTimeout(function () {
      els.forEach(function (el) {
        if (!el.classList.contains('in')) { el.classList.add('in'); io.unobserve(el); }
      });
    }, 2000);
  }
  /* Page transition: subtle 160ms fade on same-origin navigation.
     Skipped under reduced motion; modifier clicks, new tabs, downloads,
     hash links and forms are untouched. */
  if (!reduced) {
    document.addEventListener('click', function (e) {
      if (document.documentElement.classList.contains('page-exit')) return;
      var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
      if (!a || e.defaultPrevented || e.button !== 0) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      if ((a.target && a.target !== '_self') || a.hasAttribute('download')) return;
      var href = a.getAttribute('href');
      if (!href || href.charAt(0) === '#') return;
      var url;
      try { url = new URL(a.href, document.baseURI); } catch (_) { return; }
      if (url.origin !== location.origin) return;
      if (url.pathname === location.pathname && url.search === location.search) return;
      e.preventDefault();
      document.documentElement.classList.add('page-exit');
      setTimeout(function () { location.href = a.href; }, 160);
    });
  }
})();

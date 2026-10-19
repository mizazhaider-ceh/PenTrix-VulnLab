/* PenTrix VulnLab shell enhancements. Progressive: the page works without
   this file. Copy buttons degrade to selectable text, filters degrade to
   GET forms, reveal animations degrade to visible content. */
(function () {
  'use strict';
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
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

  /* Live filters: enhance the GET filter forms so results update without a
     reload. Without JS the forms submit normally (server-side filtering). */
  function wireFilter(formId, opts) {
    var form = document.getElementById(formId);
    if (!form) return;
    var items = Array.prototype.slice.call(document.querySelectorAll(opts.items));
    var empty = document.querySelector(opts.empty);
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
        it.style.display = show ? '' : 'none';
        if (show) shown++;
      });
      if (empty) empty.hidden = shown !== 0;
      if (opts.after) opts.after(shown);
    };
    form.addEventListener('submit', function (e) { e.preventDefault(); apply(); });
    form.addEventListener('input', apply);
    var reset = form.querySelector('[type=reset]');
    if (reset) reset.addEventListener('click', function () { setTimeout(apply, 0); });
  }

  /* Home: filter module cards. */
  wireFilter('home-filter', { items: '.grid .clay-card', empty: '[data-home-empty]' });

  /* Scoreboard: filter challenge rows, hide modules with no visible rows. */
  wireFilter('sb-filter', {
    items: '.sb-module tbody tr',
    empty: '[data-sb-empty]',
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
     Content is visible by default; the observer only enhances. Never used
     on scoreboard rows (they must paint instantly). */
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
  }
})();

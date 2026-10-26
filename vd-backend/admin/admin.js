(function () {
  'use strict';
  var csrf = '', cur = '', timer = 0;
  var $ = function (i) { return document.getElementById(i); };
  function el(t, c, x) { var e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; }   // textContent only: no XSS
  function api(m, p, b) {
    var h = { Accept: 'application/json' }; if (b) h['Content-Type'] = 'application/json'; if (m !== 'GET') h['X-CSRF-Token'] = csrf;
    return fetch('/api/admin' + p, { method: m, headers: h, body: b ? JSON.stringify(b) : undefined, credentials: 'same-origin' }).then(function (r) {
      if (r.status === 401) { show(false); throw new Error('auth'); }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  function show(on) { $('login').hidden = on; $('app').hidden = !on; clearInterval(timer); if (on) { load(); timer = setInterval(function () { if (!document.hidden) load(); }, 5000); } }
  function t(ms) { return new Date(ms).toLocaleString(); }
  function load() {
    api('GET', '/threads').then(function (d) {
      var ul = $('threads'); ul.textContent = '';
      d.threads.forEach(function (x) {
        var li = el('li'), b = el('button', x.guestId === cur ? 'on' : '', x.guestId.slice(0, 10) + '…'); b.type = 'button';
        b.appendChild(el('small', '', (x.sender === 'guest' ? '' : 'You: ') + x.last)); b.appendChild(el('small', '', t(x.at)));
        b.onclick = function () { cur = x.guestId; $('th').textContent = 'Guest ' + x.guestId; $('rf').hidden = false; open(); load(); };
        li.appendChild(b); ul.appendChild(li);
      });
      if (cur) open();
    }).catch(function () {});
  }
  function open() {
    api('GET', '/threads/' + encodeURIComponent(cur)).then(function (d) {
      var box = $('msgs'), atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 80; box.textContent = '';
      d.messages.forEach(function (m) {
        var e = el('div', 'm ' + (m.sender === 'guest' ? 'g' : 'a')); e.title = t(m.created_at);
        if (m.att_id) {
          var u = '/api/admin/files/' + encodeURIComponent(m.att_id), md;
          if (/^video\//.test(m.att_mime)) { md = el('video'); md.controls = true; md.preload = 'metadata'; md.src = u; }
          else { md = el('img'); md.loading = 'lazy'; md.alt = 'Customer photo'; md.src = u; var l = el('a'); l.href = u; l.target = '_blank'; l.rel = 'noopener'; l.appendChild(md); md = l; }
          e.appendChild(md);
        }
        if (m.body && m.body !== '[Photo]' && m.body !== '[Video]') e.appendChild(el('div', '', m.body));
        box.appendChild(e);
      });
      if (atEnd) box.scrollTop = box.scrollHeight;
    }).catch(function () {});
  }
  $('lf').addEventListener('submit', function (e) {
    e.preventDefault(); $('le').textContent = '';
    fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ username: $('u').value, password: $('p').value }) })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) { csrf = d.csrf; $('p').value = ''; show(true); })
      .catch(function (x) { $('le').textContent = x.message === '429' ? 'Too many attempts. Wait 15 minutes.' : 'Sign-in failed.'; });
  });
  $('rf').addEventListener('submit', function (e) {
    e.preventDefault(); var v = $('rt').value.trim(); if (!v || !cur) return;
    api('POST', '/threads/' + encodeURIComponent(cur) + '/reply', { text: v }).then(function () { $('rt').value = ''; open(); load(); }).catch(function () {});
  });
  $('out').addEventListener('click', function () { api('POST', '/logout', {}).catch(function () {}).then(function () { csrf = ''; cur = ''; show(false); }); });
  fetch('/api/admin/session', { credentials: 'same-origin' }).then(function (r) { if (!r.ok) throw 0; return r.json(); }).then(function (d) { csrf = d.csrf; show(true); }).catch(function () { show(false); });
})();
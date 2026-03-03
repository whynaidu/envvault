/* ============================================
   EnvVault — v2 JavaScript
   Scroll reveals, terminal animation,
   counter animation, tabs, copy, nav
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {
  initReveals();
  initNav();
  initTerminal();
  initTabs();
  initCopy();
  initCounters();
});

/* --- Scroll Reveal --- */
function initReveals() {
  const els = document.querySelectorAll('[data-reveal]');
  if (!els.length) return;

  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        const delay = parseInt(e.target.dataset.reveal || '0', 10);
        setTimeout(() => e.target.classList.add('in'), delay);
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -60px 0px' });

  els.forEach((el) => io.observe(el));
}

/* --- Navigation --- */
function initNav() {
  const nav = document.querySelector('.nav');
  const ham = document.querySelector('.nav__ham');
  const links = document.querySelector('.nav__links');

  if (nav) {
    let ticking = false;
    window.addEventListener('scroll', () => {
      if (!ticking) {
        requestAnimationFrame(() => {
          nav.classList.toggle('scrolled', window.scrollY > 30);
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  if (ham && links) {
    ham.addEventListener('click', () => {
      const isOpen = links.classList.toggle('open');
      ham.setAttribute('aria-expanded', isOpen);
      document.body.style.overflow = isOpen ? 'hidden' : '';
    });
    links.querySelectorAll('a').forEach((a) => {
      a.addEventListener('click', () => {
        links.classList.remove('open');
        ham.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      });
    });
    // Close menu on outside click
    document.addEventListener('click', (e) => {
      if (links.classList.contains('open') && !links.contains(e.target) && !ham.contains(e.target)) {
        links.classList.remove('open');
        ham.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      }
    });
  }
}

/* --- Terminal Typing --- */
function initTerminal() {
  const el = document.getElementById('hero-term');
  if (!el) return;

  const seq = [
    { t: 'prompt', s: '$ ' },
    { t: 'cmd', s: 'envvault init', d: 500 },
    { t: 'br' },
    { t: 'ok', s: '  \u2713 Vault initialized at .envvault/dev.vault', d: 350 },
    { t: 'br' },
    { t: 'info', s: '  Detected .env \u2014 imported 4 secrets', d: 250 },
    { t: 'br' }, { t: 'br' },
    { t: 'prompt', s: '$ ', d: 700 },
    { t: 'cmd', s: 'envvault set API_KEY', d: 500 },
    { t: 'br' },
    { t: 'out', s: '  Enter value: ', d: 250 },
    { t: 'dim', s: '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022', d: 400 },
    { t: 'br' },
    { t: 'ok', s: '  \u2713 Stored (AES-256-GCM encrypted)', d: 350 },
    { t: 'br' }, { t: 'br' },
    { t: 'prompt', s: '$ ', d: 700 },
    { t: 'cmd', s: 'envvault run -- node server.js', d: 500 },
    { t: 'br' },
    { t: 'info', s: '  Injecting 5 secrets into environment...', d: 400 },
    { t: 'br' },
    { t: 'out', s: '  Server running on ', d: 250 },
    { t: 'cmd', s: 'http://localhost:3000', d: 0 },
  ];

  let running = false;
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting && !running) {
        running = true;
        animate(el, seq);
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.1 });

  io.observe(el);
}

async function animate(container, seq) {
  container.innerHTML = '';
  let line = mkLine();
  container.appendChild(line);

  for (const s of seq) {
    if (s.d) await wait(s.d);
    if (s.t === 'br') { line = mkLine(); container.appendChild(line); continue; }

    const sp = document.createElement('span');
    sp.className = `t-${s.t}`;

    if (s.t === 'cmd') {
      line.appendChild(sp);
      for (const ch of s.s) { sp.textContent += ch; await wait(30 + Math.random() * 25); }
    } else {
      sp.textContent = s.s;
      line.appendChild(sp);
    }
  }

  const cur = document.createElement('span');
  cur.className = 't-cursor';
  cur.innerHTML = '\u00a0';
  line.appendChild(cur);

  await wait(5000);
  animate(container, seq);
}

function mkLine() {
  const d = document.createElement('div');
  d.style.minHeight = '1.85em';
  return d;
}

function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

/* --- Counter Animation --- */
function initCounters() {
  const counters = document.querySelectorAll('[data-count]');
  if (!counters.length) return;

  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        countUp(e.target);
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.5 });

  counters.forEach((el) => io.observe(el));
}

function countUp(el) {
  const target = parseFloat(el.dataset.count);
  const suffix = el.dataset.suffix || '';
  const prefix = el.dataset.prefix || '';
  const decimal = el.dataset.decimal === 'true';
  const duration = 1200;
  const start = performance.now();

  function tick(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = eased * target;

    if (decimal) {
      el.textContent = prefix + current.toFixed(1) + suffix;
    } else {
      el.textContent = prefix + Math.round(current) + suffix;
    }

    if (progress < 1) requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
}

/* --- Tabs --- */
function initTabs() {
  document.querySelectorAll('[data-tabs]').forEach((group) => {
    const tabs = group.querySelectorAll('[data-tab]');
    const pWrap = document.querySelector(`[data-panels="${group.dataset.tabs}"]`);
    if (!pWrap) return;
    const panels = pWrap.querySelectorAll('[data-panel]');

    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const id = tab.dataset.tab;
        tabs.forEach((t) => t.classList.remove('on'));
        tab.classList.add('on');
        panels.forEach((p) => p.classList.toggle('on', p.dataset.panel === id));
      });
    });
  });
}

/* --- Copy --- */
function initCopy() {
  document.querySelectorAll('[data-copy-text]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const text = btn.dataset.copyText;
      if (!text || !navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(() => {
        btn.classList.add('ok');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.classList.remove('ok'); btn.textContent = 'Copy'; }, 2000);
      }).catch(() => {});
    });
  });
}

// vpngw portal behaviour (no inline scripts: strict CSP).
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]');
  if (csrf) {
    document.body.addEventListener("htmx:configRequest", (e) => {
      e.detail.headers["X-CSRF-Token"] = csrf.content;
    });
  }

  // Confirmation for destructive actions.
  document.addEventListener("submit", (e) => {
    const msg = e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  }, true);

  // Show / hide secrets.
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-toggle-secret]");
    if (!t) return;
    const el = document.getElementById(t.getAttribute("data-toggle-secret"));
    if (!el) return;
    const hidden = el.getAttribute("data-hidden") !== "false";
    el.textContent = hidden ? el.getAttribute("data-value") : "•".repeat(Math.min(24, el.getAttribute("data-value").length));
    el.setAttribute("data-hidden", hidden ? "false" : "true");
    t.textContent = hidden ? "Hide" : "Show";
  });

  // Copy to clipboard.
  document.addEventListener("click", async (e) => {
    const t = e.target.closest("[data-copy]");
    if (!t) return;
    const src = document.getElementById(t.getAttribute("data-copy"));
    const value = src ? (src.getAttribute("data-value") || src.textContent) : t.getAttribute("data-copy-value");
    try {
      await navigator.clipboard.writeText(value.trim());
    } catch (_) {
      const ta = document.createElement("textarea");
      ta.value = value.trim(); document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    const old = t.textContent;
    t.textContent = "Copied"; t.classList.add("copied");
    setTimeout(() => { t.textContent = old; t.classList.remove("copied"); }, 1400);
  });

  // Tabs: <div class="tabs" data-tabs="group"> buttons with data-tab="id">.
  function activate(group, id) {
    document.querySelectorAll('[data-tabs="' + group + '"] [data-tab]').forEach((b) => {
      b.classList.toggle("active", b.getAttribute("data-tab") === id);
    });
    document.querySelectorAll('[data-tab-group="' + group + '"]').forEach((p) => {
      p.classList.toggle("active", p.id === id);
    });
    try { localStorage.setItem("tab:" + group, id); } catch (_) {}
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-tab]");
    if (!b) return;
    const group = b.closest("[data-tabs]").getAttribute("data-tabs");
    activate(group, b.getAttribute("data-tab"));
  });
  function detectPlatform() {
    const ua = navigator.userAgent;
    if (/iPhone|iPad|iPod/.test(ua)) return "ios";
    if (/Android/.test(ua)) return "android";
    if (/Mac OS X/.test(ua)) return "macos";
    if (/Windows/.test(ua)) return "windows";
    if (/Linux|X11/.test(ua)) return "linux";
    return "windows";
  }
  document.querySelectorAll("[data-tabs]").forEach((t) => {
    const group = t.getAttribute("data-tabs");
    let id = null;
    try { id = localStorage.getItem("tab:" + group); } catch (_) {}
    if (t.hasAttribute("data-platform-tabs")) {
      const want = t.getAttribute("data-prefix") + detectPlatform();
      if (!id && document.getElementById(want)) id = want;
    }
    if (!id || !document.getElementById(id)) {
      const first = t.querySelector("[data-tab]");
      if (first) id = first.getAttribute("data-tab");
    }
    if (id) activate(group, id);
  });

  // Client-side table sort: <table data-sortable>, <th data-key="n|s">.
  function sortTable(table, idx, numeric, dir) {
    const tbody = table.tBodies[0];
    const rows = Array.from(tbody.rows);
    rows.sort((a, b) => {
      const x = a.cells[idx] ? (a.cells[idx].getAttribute("data-sort") || a.cells[idx].textContent) : "";
      const y = b.cells[idx] ? (b.cells[idx].getAttribute("data-sort") || b.cells[idx].textContent) : "";
      const r = numeric ? (parseFloat(x) || 0) - (parseFloat(y) || 0) : x.localeCompare(y);
      return dir === "asc" ? r : -r;
    });
    rows.forEach((r) => tbody.appendChild(r));
  }
  function applySort(table) {
    const s = table.getAttribute("data-sort-state");
    if (!s) return;
    const [idx, dir] = s.split(":");
    const th = table.tHead.rows[0].cells[+idx];
    table.tHead.querySelectorAll("th").forEach((h) => h.classList.remove("sorted-asc", "sorted-desc"));
    th.classList.add(dir === "asc" ? "sorted-asc" : "sorted-desc");
    sortTable(table, +idx, th.getAttribute("data-key") === "n", dir);
  }
  document.addEventListener("click", (e) => {
    const th = e.target.closest("table[data-sortable] th.sortable");
    if (!th) return;
    const table = th.closest("table");
    const idx = th.cellIndex;
    const cur = table.getAttribute("data-sort-state") || "";
    const dir = cur === idx + ":asc" ? "desc" : "asc";
    table.setAttribute("data-sort-state", idx + ":" + dir);
    applySort(table);
  });

  // Narrow screens show the rows of <table class="stack"> as blocks: every
  // cell is labelled with its column header (CSS data-label).
  function labelCells(table) {
    const heads = Array.from(table.querySelectorAll("thead th")).map((th) => th.textContent.trim());
    table.querySelectorAll("tbody tr, tfoot tr").forEach((tr) => {
      let i = 0;
      Array.from(tr.cells).forEach((td) => {
        if (heads[i]) td.setAttribute("data-label", heads[i]);
        i += td.colSpan || 1;
      });
    });
  }
  document.querySelectorAll("table.stack").forEach(labelCells);

  // The active page of a scrolled navigation bar is in view.
  const nav = document.querySelector(".nav");
  const current = nav && nav.querySelector("a.active");
  if (current && nav.scrollWidth > nav.clientWidth) {
    const n = nav.getBoundingClientRect(), a = current.getBoundingClientRect();
    nav.scrollLeft += a.left - n.left - (n.width - a.width) / 2;
  }

  // Live sessions over SSE: <tbody data-sse="/admin/sessions/stream">.
  document.querySelectorAll("[data-sse]").forEach((tbody) => {
    const table = tbody.closest("table");
    const filters = document.querySelectorAll("[data-sse-filter]");
    let es = null;
    function connect() {
      const params = new URLSearchParams();
      filters.forEach((f) => { if (f.value) params.set(f.name, f.value); });
      if (es) es.close();
      es = new EventSource(tbody.getAttribute("data-sse") + "?" + params.toString());
      es.addEventListener("sessions", (ev) => {
        const data = JSON.parse(ev.data);
        tbody.innerHTML = data.rows;
        const foot = table.tFoot;
        if (foot) foot.innerHTML = data.foot;
        const counter = document.getElementById("session-count");
        if (counter) counter.textContent = data.count;
        applySort(table);
        if (table.classList.contains("stack")) labelCells(table);
        if (window.htmx) window.htmx.process(tbody);
      });
    }
    filters.forEach((f) => f.addEventListener("input", () => { clearTimeout(f._t); f._t = setTimeout(connect, 300); }));
    connect();
  });

  // Auto-submit selects.
  document.addEventListener("change", (e) => {
    if (e.target.matches("[data-autosubmit]")) e.target.form.submit();
  });
})();

// Progressive enhancement only: every page works without this file.
// Filters stay plain GET forms (the URL is the state); this script applies them
// live, keeps the URL in sync, adds copy buttons and the "/" search shortcut.
(() => {
  "use strict";
  const d = document;
  d.documentElement.classList.add("js");

  // copy buttons next to every command
  for (const btn of d.querySelectorAll("[data-copy]")) {
    btn.hidden = false;
    btn.addEventListener("click", async () => {
      const pre = btn.closest(".cmd").querySelector("pre");
      const text = pre.textContent;
      let ok = true;
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        const range = d.createRange();
        range.selectNodeContents(pre);
        const sel = getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        ok = false;
      }
      const label = btn.textContent;
      btn.textContent = ok ? "copied" : "selected";
      setTimeout(() => { btn.textContent = label; }, 1200);
    });
  }

  // live filters: field name -> data-<name> on [data-row]; "q" searches data-search
  for (const form of d.querySelectorAll("form[data-filter]")) {
    const scope = d.querySelector(form.dataset.filter) || d;
    const rows = [...scope.querySelectorAll("[data-row]")];
    const groups = [...scope.querySelectorAll("[data-group]")];
    const count = form.querySelector("[data-count]");
    const empty = scope.querySelector("[data-empty]");
    const apply = () => {
      const crit = [...new FormData(form).entries()]
        .map(([k, v]) => [k, String(v).trim()])
        .filter(([k, v]) => v !== "" && k !== "format");
      let shown = 0;
      for (const row of rows) {
        const ok = crit.every(([k, v]) => k === "q"
          ? (row.dataset.search || "").includes(v.toLowerCase())
          : row.dataset[k] === v);
        row.hidden = !ok;
        if (ok) shown++;
      }
      for (const g of groups) g.hidden = !g.querySelector("[data-row]:not([hidden])");
      if (count) count.textContent = String(shown);
      if (empty) empty.hidden = shown !== 0;
      const qs = new URLSearchParams(crit).toString();
      history.replaceState(null, "", location.pathname + (qs ? "?" + qs : ""));
    };
    form.addEventListener("input", apply);
    form.addEventListener("change", apply);
    form.addEventListener("submit", (e) => { e.preventDefault(); apply(); });
  }

  // "/" focuses the search field
  d.addEventListener("keydown", (e) => {
    if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.target.closest("input, textarea, select, [contenteditable]")) return;
    const q = d.querySelector("form[data-filter] input[name=q]");
    if (!q) return;
    e.preventDefault();
    q.focus();
    q.select();
  });

  // compose: ask the server (single source of truth) for the validated command
  const compose = d.querySelector("form[data-compose]");
  if (compose) {
    const errs = d.querySelector("[data-compose-errors]");
    const ok = d.querySelector("[data-compose-ok]");
    const unavail = d.querySelector("[data-compose-unavailable]");
    const net = d.querySelector("[data-compose-net]");
    let timer, seq = 0;
    const refresh = () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const mine = ++seq;
        const qs = new URLSearchParams(new FormData(compose));
        qs.set("go", "1");
        history.replaceState(null, "", location.pathname + "?" + qs);
        let j;
        try {
          const r = await fetch("/api/compose?" + qs, { headers: { Accept: "application/json" } });
          j = await r.json();
        } catch { return; }
        if (mine !== seq) return;
        errs.replaceChildren(...j.errors.map((m) => {
          const li = d.createElement("li");
          li.textContent = m;
          return li;
        }));
        errs.hidden = j.errors.length === 0;
        ok.hidden = !j.valid;
        if (j.valid) {
          const pres = ok.querySelectorAll("pre");
          [j.command, ...j.then].forEach((c, i) => { if (pres[i]) pres[i].textContent = c; });
        }
        const u = Object.entries(j.unavailable_here || {});
        unavail.hidden = u.length === 0;
        unavail.textContent = u.map(([k, v]) => `${k}: ${v}. `).join("")
          + "Unavailable profiles are reported SKIPPED with this reason.";
        net.hidden = !j.external_traffic;
      }, 120);
    };
    compose.addEventListener("input", refresh);
    compose.addEventListener("change", refresh);
    compose.addEventListener("submit", (e) => { e.preventDefault(); refresh(); });
  }
})();

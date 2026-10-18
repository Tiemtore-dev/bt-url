"use strict";

// Toutes les données affichées viennent de tiers (sources TI, DNS, RDAP…) : on construit le DOM avec textContent uniquement.
const $ = (id) => document.getElementById(id);

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "style") Object.assign(node.style, v); // CSSOM : autorisé par la CSP (pas d'attribut style)
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) node.append(c.nodeType ? c : document.createTextNode(String(c)));
  return node;
}
const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };

const VERDICTS = {
  CONFIRMED_MALICIOUS: ["Malveillante (confirmée)", "v-malicious"],
  HIGH_RISK: ["Risque élevé", "v-high"],
  SUSPICIOUS: ["Suspecte", "v-suspicious"],
  CLEAN: ["Aucune menace détectée", "v-clean"],
  UNKNOWN: ["Indéterminé", "v-unknown"],
};
const SOURCE_VERDICTS = {
  MALICIOUS: ["Malveillant", "v-malicious"], SUSPICIOUS: ["Suspect", "v-suspicious"],
  CLEAN: ["Rien trouvé", "v-clean"], UNKNOWN: ["Inconnu", "v-unknown"], ERROR: ["Erreur", "v-unknown"],
};
const BOOL_FEATURES_UNIT = "bool";
let lastJson = null;
let countdownTimer = null;

function pill(map, key) {
  const [label, cls] = map[key] || [key, "v-unknown"];
  return el("span", { class: "pill " + cls, text: label });
}

function formatValue(f) {
  if (f.missing_suspected) return el("span", { class: "na", text: "Non disponible" });
  if (f.unit === BOOL_FEATURES_UNIT) return f.value ? "Oui" : "Non";
  if (f.value === null || f.value === undefined || f.value === "") return el("span", { class: "na", text: "—" });
  if (typeof f.value === "number") {
    const v = Number.isInteger(f.value) ? f.value : Math.round(f.value * 100) / 100;
    return f.unit ? `${v.toLocaleString("fr-FR")} ${f.unit}` : v.toLocaleString("fr-FR");
  }
  return String(f.value);
}

function showError(message, retryAfter) {
  clear($("error"));
  $("error").append(el("p", { text: message }));
  $("error").hidden = false;
  $("result").hidden = true;
  $("error").focus();
  if (retryAfter) startCountdown(retryAfter);
}

function startCountdown(seconds) {
  clearInterval(countdownTimer);
  const btn = $("submit");
  let left = seconds;
  btn.disabled = true;
  const tick = () => {
    if (left <= 0) { clearInterval(countdownTimer); btn.disabled = false; btn.textContent = "Analyser"; return; }
    btn.textContent = `Patientez ${left} s`;
    left -= 1;
  };
  tick();
  countdownTimer = setInterval(tick, 1000);
}

function renderVerdict(r) {
  const risk = r.risk;
  const [label, cls] = VERDICTS[risk.verdict] || VERDICTS.UNKNOWN;
  const badge = $("verdict-badge");
  badge.textContent = label;
  badge.className = "badge " + cls;
  const pct = risk.score == null ? 0 : Math.round(risk.score * 100);
  const meter = $("score-meter");
  meter.className = "meter " + cls;
  meter.setAttribute("aria-valuenow", String(pct));
  meter.setAttribute("aria-valuetext", risk.score == null ? "indéterminé" : `${pct} sur 100`);
  $("score-fill").style.width = pct + "%";
  $("score-text").textContent = risk.score == null
    ? "Indéterminé" : `${pct} / 100 — confiance ${Math.round(risk.confidence * 100)} %`;
  $("target").textContent = r.target.url;

  const reasons = $("reasons");
  clear(reasons);
  for (const reason of risk.reasons) reasons.append(el("li", { text: reason }));

  const caveats = [];
  if (risk.verdict === "CLEAN") caveats.push("Aucune détection n'est pas une preuve d'innocuité : les attaques récentes sont souvent inconnues des bases.");
  if (risk.verdict === "HIGH_RISK" && !risk.decisive_source) caveats.push("Verdict issu du modèle et des indices de forme, sans confirmation d'une base de menaces : à vérifier.");
  for (const n of r.notes || []) caveats.push(n);
  $("caveat").textContent = caveats.join(" ");

  const c = r.cache || {};
  $("cache-note").textContent = c.hit
    ? `Résultat en cache (analysé il y a ${c.age_seconds < 90 ? c.age_seconds + " s" : Math.round(c.age_seconds / 60) + " min"}).`
    : `Analysé en ${((r.meta.scan_duration_ms || 0) / 1000).toFixed(1)} s.`;
}

function renderSources(r) {
  const body = $("sources").querySelector("tbody");
  clear(body);
  if (!r.sources.length) {
    body.append(el("tr", {}, el("td", { colspan: "4", class: "na", text: "Aucune source configurée sur ce serveur." })));
    return;
  }
  for (const s of r.sources) {
    const name = s.authoritative ? `${s.name} (autoritaire)` : s.name;
    body.append(el("tr", {},
      el("td", { text: name }), el("td", {}, pill(SOURCE_VERDICTS, s.verdict)),
      el("td", { text: s.error || s.detections || "—" }),
      el("td", { class: "num", text: s.response_time_ms ? `${s.response_time_ms} ms` : "—" })));
  }
}

function renderML(r) {
  const summary = $("ml-summary");
  const feats = $("features");
  clear(summary); clear(feats);
  const ml = r.ml;
  if (!ml || ml.score === undefined) {
    let msg = "Modèle indisponible.";
    if (ml && ml.status === "training") {
      msg = "Le modèle d'apprentissage automatique est en cours d'entraînement : il n'est pas utilisé pour l'instant. "
        + "Le verdict repose sur les sources de Threat Intelligence et sur les indices de forme de l'URL.";
    } else if (ml && ml.enabled === false) {
      msg = "Modèle non utilisé pour cette cible (hôte non public).";
    }
    summary.append(el("p", { class: "na", text: msg }));
    return;
  }
  const labels = { MALICIOUS: "malveillante", SUSPICIOUS: "à surveiller", BENIGN: "bénigne" };
  summary.append(el("p", {}, "Le modèle estime l'URL ", el("strong", { text: labels[ml.label] || ml.label }),
    ` (probabilité ${Math.round(ml.score * 100)} %, seuil de décision ${Math.round(ml.threshold * 100)} %). `,
    "Il sert d'indice complémentaire : seul, il ne confirme jamais une URL malveillante."));
  if (ml.input_url && ml.input_url !== r.target.url) {
    summary.append(el("p", { class: "hint", text: `URL fournie au modèle : ${ml.input_url} (« www. » retiré : le modèle le surestime comme sous-domaine).` }));
  }
  const bar = el("div", { class: "ml-bar", role: "img",
    "aria-label": `Score ${Math.round(ml.score * 100)} %, seuil ${Math.round(ml.threshold * 100)} %` });
  bar.append(el("div", { class: "ml-marker", style: { left: `${ml.score * 100}%` } }, el("span", { text: `score ${Math.round(ml.score * 100)} %` })));
  const thr = el("div", { class: "ml-marker thr", style: { left: `${ml.threshold * 100}%`, opacity: "0.55" } }, el("span", { text: `seuil ${Math.round(ml.threshold * 100)} %` }));
  bar.append(thr);
  summary.append(bar);

  const groups = new Map();
  for (const f of ml.features || []) {
    if (!groups.has(f.group)) groups.set(f.group, []);
    groups.get(f.group).push(f);
  }
  let first = true;
  for (const [group, items] of groups) {
    const rows = items.map((f) => el("tr", {},
      el("th", { scope: "row", text: f.label }),
      el("td", { class: "num" }, formatValue(f)),
      el("td", { class: "desc", text: f.description })));
    const det = el("details", { class: "group" }, el("summary", { text: `${group} (${items.length})` }),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "Donnée" }), el("th", { scope: "col", text: "Valeur" }), el("th", { scope: "col", text: "Signification" }))),
        el("tbody", {}, rows))));
    if (first) det.open = true;
    first = false;
    feats.append(det);
  }
}

function kv(dl, pairs) {
  clear(dl);
  for (const [k, v] of pairs) dl.append(el("dt", { text: k }), el("dd", {}, v));
}

function renderUrlAnalysis(r) {
  const f = r.url_features;
  const yn = (b) => (b ? "Oui" : "Non");
  const typo = r.typosquatting.detected
    ? r.typosquatting.matches.map((m) => `${m.legitimate_domain} (distance ${m.distance})`).join(", ") : "Aucun";
  const b64 = (r.embedded_base64 || []).map((p) => p.decoded).join(" ; ") || "Aucun";
  kv($("url-analysis"), [
    ["Hôte", r.target.hostname + (r.target.public ? "" : " (non public : aucune connexion effectuée)")],
    ["HTTPS", yn(f.uses_https)], ["Hôte = adresse IP", yn(f.has_ip_in_url)],
    ["« @ » dans l'URL", yn(f.has_userinfo)], ["Domaine punycode", yn(f.is_punycode)],
    ["Longueur / profondeur / paramètres", `${f.url_length} car. / ${f.path_depth} niveaux / ${f.param_count} param.`],
    ["Entropie", String(f.entropy)],
    ["Mots-clés suspects", f.suspicious_keywords.join(", ") || "Aucun"],
    ["Typosquatting", typo], ["Contenu base64 décodé", b64],
  ]);
}

function renderNetwork(r) {
  const pairs = [];
  if (r.ssl) {
    pairs.push(["Certificat valide", r.ssl.valid ? "Oui" : `Non${r.ssl.error ? " — " + r.ssl.error : ""}`]);
    if (r.ssl.valid) {
      pairs.push(["Émetteur", r.ssl.issuer || "—"], ["Sujet", r.ssl.subject || "—"],
        ["Expire dans", r.ssl.days_remaining == null ? "—" : `${r.ssl.days_remaining} jours`],
        ["Protocole", r.ssl.protocol || "—"]);
    }
  } else pairs.push(["Certificat", "Non vérifié"]);
  if (r.url_shortener) pairs.push(["Lien raccourci vers", r.url_shortener.final_url]);
  kv($("net-analysis"), pairs);

  const chain = $("redirects");
  clear(chain);
  const hops = r.redirects ? r.redirects.chain : [];
  if (hops.length > 1) for (const h of hops) chain.append(el("li", { text: h }));
  const blocked = r.redirects && r.redirects.blocked;
  if (blocked) chain.append(el("li", { text: `Bloqué (hôte non public) : ${blocked}` }));
  chain.hidden = !chain.childElementCount;
}

function render(r) {
  lastJson = r;
  renderVerdict(r); renderSources(r); renderML(r); renderUrlAnalysis(r); renderNetwork(r);
  $("raw").textContent = JSON.stringify(r, null, 2);
  $("error").hidden = true;
  $("result").hidden = false;
  $("result").focus({ preventScroll: false });
  $("result").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

async function analyze(url) {
  $("loading").hidden = false; $("error").hidden = true; $("submit").disabled = true;
  try {
    const resp = await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }),
    });
    let data = null;
    try { data = await resp.json(); } catch (_) { /* corps non JSON */ }
    if (!resp.ok) {
      const msg = (data && data.error && data.error.message)
        || (resp.status === 422 ? "URL invalide." : `Erreur ${resp.status}`);
      showError(msg, resp.status === 429 || resp.status === 503 ? parseInt(resp.headers.get("Retry-After") || "0", 10) : 0);
      return;
    }
    render(data);
  } catch (_) {
    showError("Impossible de joindre le service. Vérifiez votre connexion.");
  } finally {
    $("loading").hidden = true;
    if (!countdownTimer || $("submit").textContent === "Analyser") $("submit").disabled = false;
  }
}

async function loadStatus() {
  try {
    const s = await (await fetch("/api/status")).json();
    const q = s.quota;
    $("status").textContent =
      `${s.sources.length} source(s) de menaces · modèle ${{ training: "en cours d'entraînement", loaded: "chargé" }[s.ml] || "indisponible"} · ` +
      `${s.limits.per_ip_per_minute} analyses/min par adresse · quota du jour : ${q.daily_remaining}/${q.daily_limit}`;
  } catch (_) {
    $("status").textContent = "État du service indisponible.";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadStatus();
  $("form").addEventListener("submit", (e) => {
    e.preventDefault();
    const url = $("url").value.trim();
    if (url.length < 3) { showError("Saisissez une URL."); return; }
    analyze(url).then(loadStatus);
  });
  for (const b of document.querySelectorAll("[data-example]")) {
    b.addEventListener("click", () => { $("url").value = b.dataset.example; $("url").focus(); });
  }
  $("copy-json").addEventListener("click", async (e) => {
    try { await navigator.clipboard.writeText($("raw").textContent); e.target.textContent = "Copié ✓"; }
    catch (_) { e.target.textContent = "Copie impossible"; }
    setTimeout(() => (e.target.textContent = "Copier"), 1500);
  });
  $("download-json").addEventListener("click", () => {
    if (!lastJson) return;
    const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(lastJson, null, 2)], { type: "application/json" })),
      download: "bt-url-analyse.json" });
    a.click(); URL.revokeObjectURL(a.href);
  });
});

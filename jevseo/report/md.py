"""Markdown report: readable anywhere, with chart images and Mermaid pies for GitHub and Obsidian."""
from __future__ import annotations

import base64
from collections import Counter
from html import escape
from pathlib import Path
from urllib.parse import quote, urlparse

from jevseo.env import hosted_mode


def cell(v) -> str:
    value = escape(str("" if v is None else v), quote=False).replace("\n", " ").replace("\r", " ")
    for token in ("\\", "`", "!", "[", "]", "(", ")", "|"):
        value = value.replace(token, "\\" + token)
    return value


def label(v) -> str:
    return cell((v or "").replace("_", " "))


def report_link(v) -> str:
    """Keep only the validated HTTP(S) links supplied by report rules."""
    url = str(v or "")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        return "#"
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        return "#"
    if parsed.scheme not in ("http", "https") or not host or parsed.username is not None or parsed.password is not None:
        return "#"
    return quote(url, safe=":/?#@!$&'*+,;=-._~%")


def narrative_text(n: dict, value) -> str:
    return cell(value) if n.get("automatic") else str(value)


WIDTH = {"gauge": 220, "severity": 320, "page_types": 360, "intents": 360, "positions": 380, "referring_domains": 380}


def img(vm: dict, name: str, alt: str) -> str:
    """HTML image tags so GitHub and Obsidian show charts at a readable size."""
    p = vm["charts"].png.get(name)
    if not p:
        return ""
    src = f"data:image/png;base64,{base64.b64encode(p.read_bytes()).decode('ascii')}" if hosted_mode() else f"charts/{p.name}"
    return f'<img src="{src}" alt="{alt}" width="{WIDTH.get(name, 640)}">\n'


def pie(title: str, counts: dict) -> str:
    if not counts:
        return ""
    body = "\n".join('    "' + cell(str(k).replace("_", " ")).replace('"', '\\"') + f'" : {v}' for k, v in counts.items() if v)
    return f"```mermaid\npie showData title {cell(title)}\n{body}\n```\n"


def write_md(vm: dict, path: Path) -> Path:
    d, s, n = vm["d"], vm["scores"], vm["narrative"]
    L = []
    add = L.append
    add(f"# Jev SEO audit: {cell(vm['domain'])}\n")
    add(f"Audited {cell(d['run']['finished_at'])} · {vm['n_fetched']} URLs crawled · {vm['n_pages']} HTML pages · {vm['n_judgments']} Jev judgments · Jev cost ${(vm['ledger'].get('cost_usd') or 0):.4f}\n")
    add(f"**Overall score: {s['overall']}/100 (grade {s['grade']})**" + (f". {cell('; '.join(s['caps']))}" if s["caps"] else "") + "\n")
    if s.get("partial"):
        add(f"> **Partial audit:** {cell('; '.join(s['partial']))}. The overall score covers only the areas that were assessed.\n")
    add(img(vm, "gauge", "Overall score"))
    add("| Area | Score | Weight | How it is scored |\n|---|---:|---:|---|")
    for c, name in s["category_names"].items():
        v = s["categories"][c]
        add(f"| {name} | {v if v is not None else 'n/a'} | {s['weights'][c]} | {s['notes'][c]} |")
    add("")
    add(img(vm, "categories", "Score by area"))

    toc = ["Executive summary", "How this audit was made", "Priority actions"] + (["Search visibility (DataForSEO)"] if vm.get("dfs") else []) + ["What the crawl found"] + (["How Jev reads the site"] if vm["jev_available"] else []) + ["Findings by area", "Robots access", "Page inventory", "Method and limits"]
    anchor = lambda h: "#" + "".join(c for c in h.lower().replace(" ", "-") if c.isalnum() or c == "-")  # noqa: E731
    add("**Contents:** " + " · ".join(f"[{h}]({anchor(h)})" for h in toc) + "\n")
    add("## Executive summary\n")
    for para in n["executive_summary"]:
        add(narrative_text(n, para) + "\n")
    add("**What is working**\n")
    add("\n".join(f"- {narrative_text(n, x)}" for x in n["strengths"]) + "\n")
    add("**What is holding the site back**\n")
    add("\n".join(f"- {narrative_text(n, x)}" for x in n["risks"]) + "\n")
    add("### Plan\n")
    for block in n["plan"]:
        add(f"**{narrative_text(n, block['horizon'])}**\n")
        add("\n".join(f"- {narrative_text(n, x)}" for x in block["items"]) + "\n")
    if n.get("closing"):
        add(narrative_text(n, n["closing"]) + "\n")
    add(f"_Written by: {narrative_text(n, n['author'])}._\n")

    add("## How this audit was made\n")
    add("A source finds, code decides, Jev judges, " + ("code writes an evidence-only summary." if n.get("automatic") else "the supplied narrative explains the evidence.") + " Code crawls, counts and scores. Jev (TypeSafe's System One model) answers narrow typed questions about meaning, with probabilities. Missing data is shown as missing.\n")
    add("```mermaid\nflowchart LR\n  A[Crawl<br/>" + f"{vm['n_fetched']} URLs" + "] --> B[Rules<br/>" + f"{sum(1 for f in d['findings'] if f['origin'] == 'rule')} findings" + "] --> C[Jev judges<br/>" + f"{vm['n_judgments']} judgments" + "] --> D[PageSpeed<br/>" + f"{len(vm['perf_runs'])} runs" + "] --> E[Score and write<br/>" + f"{len(vm['actions'])} actions" + "]\n  style C fill:#d45bb6,color:#fff\n```\n")

    add("## Priority actions\n")
    add(img(vm, "impact_effort", "Impact versus effort"))
    add("| ID | Action | Priority | Impact | Effort | Pages | By | Verify |\n|---|---|---|---:|---|---:|---|---:|")
    for a in vm["actions"]:
        add(f"| {a['action_id']} | {cell(a['title'])}{' (quick win)' if a['quick_win'] else ''} | {a['priority']} {a['priority_text']} | {a['impact']} | {a['effort_text']} | {a['count']} | {a['by']} | {a['needs_review'] or ''} |")
    add("")
    add(pie("Actions by severity", {k: vm["sev_counts"].get(k, 0) for k in ("critical", "high", "medium", "low")}))
    add(img(vm, "severity_by_category", "Actions by area and severity"))

    x = vm.get("dfs")
    if x:
        ov, bl = x["overview"], x["backlinks"]
        add("## Search visibility (DataForSEO)\n")
        add(f"Location {x['location_code']}, language {x['language_code']}. Traffic (ETV) is DataForSEO's estimate, not measured visits.\n")
        add(f"| Ranking keywords | Est. monthly visits | Referring domains | Backlinks | AI answer mentions |\n|---:|---:|---:|---:|---:|\n| {ov.get('count')} | {round(ov['etv']) if ov.get('etv') is not None else 'n/a'} | {bl.get('referring_domains')} | {bl.get('backlinks')} | {(x['mentions'] or {}).get('total')} |\n")
        add(img(vm, "positions", "Ranking keywords by position"))
        add(img(vm, "referring_domains", "Referring domains compared"))
        add("| Keyword | Position | Searches/mo | Ranking page | Jev relevance |\n|---|---:|---:|---|---:|")
        for k in x["ranked"][:20]:
            add(f"| {cell(k['keyword'])} | {k.get('position')} | {k.get('volume')} | {cell(k['page'])} | {'' if k['relevance'] is None else format(k['relevance'], '.2f')} |")
        add("\n### Keywords worth winning\n")
        add(img(vm, "opportunities", "Keyword opportunities"))
        add("| Keyword | Searches/mo | Difficulty | Intent | Jev relevance | Page to own it |\n|---|---:|---:|---|---:|---|")
        for k in x["opportunities"]:
            rel = "" if k.get("relevance") is None else f"{k['relevance']:.2f}"
            add(f"| {cell(k['keyword'])} | {k.get('volume')} | {k.get('difficulty') if k.get('difficulty') is not None else 'n/a'} | {cell(k.get('intent'))} | {rel} | {cell(k['target'])} |")
        add("")
        if x["serps"]:
            add("| Keyword | Site position | AI Overview | Top 3 |\n|---|---:|---|---|")
            for sp in x["serps"]:
                aio = ("yes, cites the site" if sp["ai_overview_cites_site"] else "yes, site not cited") if sp["ai_overview"] else "none"
                add(f"| {cell(sp['keyword'])} | {sp['own_position'] or 'not in top 10'} | {aio} | {cell(', '.join(t['domain'] for t in sp['top'][:3]))} |")
            add("")

    add("## What the crawl found\n")
    add(img(vm, "funnel", "From discovered URLs to Jev judgments"))
    add(img(vm, "site_map", "Site structure by click depth"))

    if vm["jev_available"]:
        add("## How Jev reads the site\n")
        for c in vm["site_cards"]:
            conf = f", confidence {c['confidence']:.2f}" if "confidence" in c else ""
            flag = "" if c["band"] in ("act", "yes", "no") else " _(verify)_"
            add(f"- **{cell(c['question'])}** {cell(c['answer'])}{conf}{flag}")
        add("")
        jp = d["jev"]["pages"]
        add(pie("Page types (Jev)", dict(Counter(a["page_type"]["value"] for a in jp.values() if a).most_common())))
        add(pie("Search intent (Jev)", dict(Counter(a["intent"]["value"] for a in jp.values() if a).most_common())))
        add(img(vm, "jev_heatmap", "Jev page quality heatmap"))
        add(img(vm, "jev_confidence", "How sure Jev was"))
        add("### Where to invest\n")
        add(img(vm, "invest", "Importance versus judged quality"))
        if vm["invest_pages"]:
            add("| Important but weak | Importance | Quality | Jev suggests |\n|---|---:|---:|---|")
            for p in vm["invest_pages"]:
                add(f"| {cell(p['short'])} | {p['importance']:.2f} | {p['quality']:.2f} | {cell((p['action'] or '').replace('_', ' '))} |")
            add("")
        if vm["jev_pairs"]:
            add("**Pages that may compete for the same searches**\n")
            add("| Page A | Page B | Title overlap | P(compete) |\n|---|---|---:|---:|")
            for p in vm["jev_pairs"][:20]:
                add(f"| {cell(p['a'])} | {cell(p['b'])} | {p['title_overlap']} | {p['judgment']['value']:.2f} |")
            add("")

    add("## Findings by area\n")
    for c, name in s["category_names"].items():
        acts = vm["findings_by_cat"][c]
        if not acts:
            continue
        add(f"### {name} ({s['categories'][c] if s['categories'][c] is not None else 'n/a'})\n")
        if c == "performance":
            add(img(vm, "lighthouse", "Lighthouse scores"))
            add(img(vm, "cwv", "Core Web Vitals field data"))
        for a in acts:
            tags = [a["priority"], a["severity"], a["by"]]
            if a["needs_review"]:
                tags.append(f"{a['needs_review']} to verify")
            if a["heuristic"]:
                tags.append("heuristic")
            add(f"**{a['action_id']} · {cell(a['title'])}** `{'` `'.join(tags)}`\n")
            add(f"- Evidence: {a['count']} affected · {cell(a['evidence'])}")
            add(f"- Fix: {cell(a['fix'])} ([source]({report_link(a['source'])}))")
            add("- URLs: " + ", ".join(cell(u) for u in a["urls"][:8]) + (f" and {a['count'] - 8} more" if a["count"] > 8 else ""))
            add("")

    add("## Robots access\n")
    add("| User agent | Access |\n|---|---|")
    for b, ok in {**vm["search_bots"], **vm["ai_bots"]}.items():
        add(f"| {cell(b)} | {'allowed' if ok else 'blocked'} |")
    add("")

    add("## Page inventory\n")
    add("| Page | Depth | Words | Inlinks | Type (Jev) | Intent (Jev) | Importance | Action (Jev) |\n|---|---:|---:|---:|---|---|---:|---|")
    for p in vm["pages"]:
        imp = f"{p['importance']:.2f}" if p["importance"] is not None else ""
        add(f"| {cell(p['url'])} | {p['depth'] if p['depth'] != 99 else ''} | {p['words']} | {p['inlinks']} | {label(p['page_type'])} | {label(p['intent'])} | {imp} | {label(p['action'])} |")
    add("")

    add("## Method and limits\n")
    add("- Area score: 100 minus, per finding, severity amount (critical 25, high 12, medium 6, low 2) × (0.5 + 0.5 × share of pages affected). Content and AI readiness blend 70% Jev judgment with 30% rules. Performance blends 50% Lighthouse mobile with 50% crawl observations.")
    add("- Overall: weighted mean of scored areas; unscored areas are excluded, never zero.")
    add("- Impact: severity weight × (0.6 + 0.4 × reach) × (0.6 + 0.8 × highest Jev importance of affected pages), scaled to 100.")
    add("- Jev answers are decisive at confidence 0.80 (Choice, Score) or P(yes) at least 0.80 or at most 0.20 (Noul). Others are flagged to verify.")
    lg = vm["ledger"]
    add(f"- Jev: model {lg.get('model_returned') or 'n/a'}, {lg.get('requests', 0)} requests, {lg.get('input_tokens', 0)} input tokens, {lg.get('failed', 0)} failed, cost ${(lg.get('cost_usd') or 0):.4f}.")
    if vm.get("dfs"):
        x = vm["dfs"]
        add(f"- DataForSEO: {x['ledger']['requests']} requests, ${x['ledger']['cost_usd']:.4f}" + (f"; data reused from the collection at {x['reused_from']}" if x.get("reused_from") else "") + ". Rankings, volumes, difficulty and traffic (ETV) are DataForSEO estimates. No Search Console or analytics data was used.")
    else:
        add("- No Search Console, analytics, backlink or keyword data was used (run with --full for DataForSEO).")
    add("- Scores rank work; they do not predict rankings or traffic.")
    add(f"\n_Generated by jev-seo {cell(d['tool']['version'])}._\n")
    path.write_text("\n".join(L))
    return path

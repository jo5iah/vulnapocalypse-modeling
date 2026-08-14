#!/usr/bin/env python3
"""Assemble a fully self-contained HTML edition of the model document.

Inputs, for stem S (default ODEtoVuln_daily)
  S.md          the model document, embedded verbatim and rendered in-browser
  S.ipynb       source of the figures: each "## Visualization" markdown cell paired with
                the figure the code cells below it emit, plus any code cell tagging
                itself FIGURE_NAME for inlining at a `figure:<name>` marker in S.md
  vendor/       katex.min.{js,css} + fonts/*.woff2, markdown-it.min.js, and the
                web-encoded animation named below

Output
  S.html        one file, zero network requests: libraries, fonts, figures and the
                animation are all inlined as base64 data URIs.

Usage
  python build_html.py                        # builds ODEtoVuln_daily.html
  python build_html.py <stem>                 # builds <stem>.html from <stem>.{md,ipynb}
  python build_html.py ODEtoVuln_daily index  # builds index.html, for GitHub Pages
"""

import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
VENDOR = ROOT / "vendor"

# `python build_html.py [stem] [output-stem]` — stem selects the document (default
# ODEtoVuln_daily); the optional second argument names the output, for hosting as index.html.
STEM = sys.argv[1] if len(sys.argv) > 1 else "ODEtoVuln_daily"
OUT_STEM = sys.argv[2] if len(sys.argv) > 2 else STEM
MD_PATH = ROOT / f"{STEM}.md"
NB_PATH = ROOT / f"{STEM}.ipynb"
OUT_PATH = ROOT / f"{OUT_STEM}.html"
VIDEO_PATH = VENDOR / "phase3d_daily_web.mp4"

KATEX_VERSION, MARKDOWNIT_VERSION = "0.16.11", "14.1.0"


def data_uri(mime: str, payload: bytes) -> str:
    return f"data:{mime};base64,{base64.b64encode(payload).decode()}"


def inline_css() -> str:
    """KaTeX CSS with every woff2 embedded; the woff/ttf fallbacks are dropped."""
    css = (VENDOR / "katex.min.css").read_text()
    css = re.sub(
        r"url\(fonts/([A-Za-z0-9_-]+\.woff2)\)",
        lambda m: f"url({data_uri('font/woff2', (VENDOR / 'fonts' / m.group(1)).read_bytes())})",
        css,
    )
    css = re.sub(r',url\(fonts/[A-Za-z0-9_.-]+\)\s*format\("(?:woff|truetype)"\)', "", css)
    if "url(fonts/" in css:
        raise SystemExit("unresolved font reference in katex.min.css")
    return css


def inline_js(name: str) -> str:
    """Guard against a literal </script> inside minified sources closing the tag early."""
    return (VENDOR / name).read_text().replace("</script", r"<\/script")


def visualizations(nb: dict) -> list[dict]:
    """Pair each '## Visualization' markdown cell with the last figure the cells below it emit."""
    cells, out = nb["cells"], []
    for i, cell in enumerate(cells):
        source = "".join(cell["source"])
        if cell["cell_type"] != "markdown" or not source.startswith("## Visualization"):
            continue
        png = None
        for follower in cells[i + 1:]:
            if follower["cell_type"] == "markdown":
                break
            for output in follower.get("outputs", []):
                if "image/png" in output.get("data", {}):
                    png = base64.b64decode(output["data"]["image/png"])
        if png is None:
            raise SystemExit(f"no figure found after markdown cell {i}")
        title = source.splitlines()[0].lstrip("# ").strip()
        out.append({"markdown": source, "png": png, "title": title})
    return out


def named_figures(nb: dict) -> dict:
    """Figures a code cell tags with FIGURE_NAME, for inlining at `figure:<name>` markers."""
    found = {}
    for cell in nb["cells"]:
        source = "".join(cell["source"])
        m = re.search(r'FIGURE_NAME\s*=\s*"([A-Za-z0-9_-]+)"', source)
        if cell["cell_type"] != "code" or not m:
            continue
        for output in cell.get("outputs", []):
            if "image/png" in output.get("data", {}):
                found[m.group(1)] = base64.b64decode(output["data"]["image/png"])
    return found


def figure_block(viz: dict, is_video: bool) -> str:
    """One visualization: its notebook commentary, then the figure (or the animation)."""
    caption = f"From <code>{NB_PATH.name}</code> — {viz['title']}"
    if is_video:
        media = (
            f'<video controls loop muted playsinline preload="metadata"\n'
            f'         poster="{data_uri("image/png", viz["png"])}">\n'
            f'    <source src="{data_uri("video/mp4", VIDEO_PATH.read_bytes())}" type="video/mp4">\n'
            f"    Your browser cannot play the embedded MP4; see the .mp4 beside this file.\n"
            f"  </video>"
        )
        caption += " · 360 viewpoints, 30 fps · press play"
    else:
        media = f'<img alt="{viz["title"]}" src="{data_uri("image/png", viz["png"])}">'
    return (
        '<section class="viz">\n'
        '  <script type="text/plain" class="viz-md">\n'
        f"{viz['markdown']}\n"
        "  </script>\n"
        f"  <figure>\n  {media}\n"
        f"    <figcaption>{caption}</figcaption>\n"
        "  </figure>\n"
        "</section>"
    )


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Modeling Exploited Vulnerabilities in a Software Ecosystem</title>

<!-- KaTeX {katex_v} + markdown-it {mdit_v}, inlined (fonts embedded as base64) -->
<style>
{katex_css}
</style>
<script>
{katex_js}
</script>
<script>
{markdownit_js}
</script>

<style>
  :root {{
    --bg: #fbfaf8;
    --panel: #ffffff;
    --ink: #1c1b1a;
    --muted: #6b6864;
    --rule: #e3e0da;
    --accent: #7a4b2a;
    --accent-soft: #f3ede6;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #16181c;
      --panel: #1d2025;
      --ink: #e8e6e3;
      --muted: #a3a09b;
      --rule: #313640;
      --accent: #d8a26a;
      --accent-soft: #262a31;
    }}
  }}
  * {{ box-sizing: border-box; }}
  html {{ -webkit-text-size-adjust: 100%; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font: 16px/1.65 ui-serif, Georgia, "Times New Roman", serif;
  }}
  main {{
    max-width: 62rem;
    margin: 0 auto;
    padding: 3.5rem 1.5rem 6rem;
  }}
  article {{
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: 10px;
    padding: 2.75rem 3rem;
  }}
  @media (max-width: 640px) {{
    article {{ padding: 1.5rem 1.15rem; }}
    main {{ padding: 1.5rem 0.75rem 4rem; }}
  }}
  h1, h2, h3 {{
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    line-height: 1.25;
    letter-spacing: -0.01em;
  }}
  h1 {{
    font-size: 1.9rem;
    margin: 0 0 1.75rem;
    padding-bottom: 0.9rem;
    border-bottom: 2px solid var(--accent);
  }}
  h2 {{
    font-size: 1.35rem;
    margin: 2.6rem 0 1rem;
    color: var(--accent);
  }}
  h3 {{
    font-size: 1.08rem;
    margin: 1.9rem 0 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
  }}
  p {{ margin: 0 0 1rem; }}
  strong {{ color: var(--ink); }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.9em;
    background: var(--accent-soft);
    padding: 0.1em 0.32em;
    border-radius: 3px;
  }}
  hr {{
    border: 0;
    border-top: 1px solid var(--rule);
    margin: 2.5rem 0;
  }}
  ul, ol {{ padding-left: 1.4rem; margin: 0 0 1.1rem; }}
  li {{ margin: 0.35rem 0; }}

  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 1.25rem 0 1.75rem;
    font-family: ui-sans-serif, system-ui, sans-serif;
    font-size: 0.94rem;
  }}
  th, td {{
    text-align: left;
    padding: 0.6rem 0.85rem;
    border-bottom: 1px solid var(--rule);
    vertical-align: top;
  }}
  th {{
    background: var(--accent-soft);
    font-weight: 600;
    border-bottom: 2px solid var(--rule);
  }}
  tbody tr:last-child td {{ border-bottom: 0; }}

  /* Display equations get a tinted, scrollable frame so wide expressions never clip. */
  .katex-display {{
    margin: 1.4rem 0;
    padding: 1.1rem 1rem;
    background: var(--accent-soft);
    border-left: 3px solid var(--accent);
    border-radius: 4px;
    overflow-x: auto;
    overflow-y: hidden;
  }}
  .katex {{ font-size: 1.05em; }}
  .katex-display > .katex {{ font-size: 1.12em; }}

  /* Figures carry their own commentary, lifted from the notebook. */
  #figures {{
    margin-top: 3rem;
    padding-top: 2.5rem;
    border-top: 2px solid var(--accent);
  }}
  .figures-note {{
    font-family: ui-sans-serif, system-ui, sans-serif;
    font-size: 0.9rem;
    color: var(--muted);
    margin: 0 0 1rem;
  }}
  figure {{
    margin: 1.5rem 0 2.5rem;
  }}
  figure img, figure video {{
    display: block;
    width: 100%;
    height: auto;
    background: #fcfcfb;
    border: 1px solid var(--rule);
    border-radius: 6px;
  }}
  figcaption {{
    font-family: ui-sans-serif, system-ui, sans-serif;
    font-size: 0.82rem;
    color: var(--muted);
    margin-top: 0.6rem;
  }}
  figcaption code {{ background: none; padding: 0; }}

  h2[id], h3[id] {{ scroll-margin-top: 1rem; }}
  section.viz {{ scroll-margin-top: 1rem; }}
  .toc {{
    background: var(--accent-soft);
    border-left: 3px solid var(--accent);
    border-radius: 4px;
    padding: 1rem 1.25rem 1rem 1.75rem;
    margin: 1.5rem 0 2rem;
    font-family: ui-sans-serif, system-ui, sans-serif;
    font-size: 0.92rem;
  }}
  .toc ul {{ margin: 0; padding-left: 1.1rem; }}
  .toc > ul {{ padding-left: 1.1rem; }}
  .toc li {{ margin: 0.18rem 0; }}
  .toc a {{ color: var(--ink); text-decoration: none; border-bottom: 1px solid var(--rule); }}
  .toc a:hover {{ border-bottom-color: var(--accent); }}
  .toc .toc-note {{ color: var(--muted); font-size: 0.85rem; margin: 0.5rem 0 0; }}

  footer {{
    margin-top: 1.75rem;
    font-family: ui-sans-serif, system-ui, sans-serif;
    font-size: 0.8rem;
    color: var(--muted);
    text-align: center;
  }}
</style>
</head>
<body>
<main>
  <article>
    <div id="content"></div>
    <div id="figures">
      <p class="figures-note">The sections below are generated by <code>{notebook}</code>: each
      one carries that notebook's own commentary followed by the figure it produces.</p>
{figure_blocks}
    </div>
  </article>
  <footer>Rendered from <code>{markdown_file}</code> &middot; figures from
  <code>{notebook}</code> &middot; built by <code>build_html.py</code></footer>
</main>

<!-- Figures inlined into the document body at `figure:<name>` markers -->
<script id="inline-figures" type="application/json">{inline_figures}</script>

<!-- Markdown source, verbatim from the source document -->
<script id="md-source" type="text/plain">
{markdown}</script>

<script>
// Render markdown with math: pull the math out first so markdown-it cannot treat _ or *
// inside LaTeX as emphasis, then hand each snippet to KaTeX.
function renderMarkdown(src) {{
  var math = [];
  function stash(tex, display) {{
    math.push({{ tex: tex, display: display }});
    return 'MATHPLACEHOLDER' + (math.length - 1) + 'ENDMATH';
  }}
  var escapeHtml = function (s) {{
    return s.replace(/[&<>]/g, function (c) {{
      return {{ '&': '&amp;', '<': '&lt;', '>': '&gt;' }}[c];
    }});
  }};
  var protectedSrc = src
    .replace(/\\$\\$([\\s\\S]+?)\\$\\$/g, function (_, tex) {{ return stash(tex, true); }})
    .replace(/\\$([^$\\n]+?)\\$/g, function (_, tex) {{ return stash(tex, false); }});

  var html = window.markdownit
    ? window.markdownit({{ html: false, linkify: true, typographer: false }}).render(protectedSrc)
    : '<pre>' + escapeHtml(protectedSrc) + '</pre>';

  return html.replace(/MATHPLACEHOLDER(\\d+)ENDMATH/g, function (_, i) {{
    var m = math[+i];
    if (!window.katex) {{
      return (m.display ? '<pre class="katex-display">' : '<code>') + escapeHtml(m.tex) +
             (m.display ? '</pre>' : '</code>');
    }}
    try {{
      return window.katex.renderToString(m.tex.trim(),
        {{ displayMode: m.display, throwOnError: false, strict: false }});
    }} catch (e) {{
      return '<code>' + escapeHtml(m.tex) + '</code>';
    }}
  }});
}}

// GitHub-style slug, so anchors in the markdown resolve against rendered headings
function slugify(text) {{
  return text.toLowerCase().replace(/[^0-9a-z -]+/g, '').trim().replace(/ +/g, '-');
}}

function addHeadingIds(root) {{
  root.querySelectorAll('h1, h2, h3, h4').forEach(function (h) {{
    var viz = /^Visualization +([0-9]+)/.exec(h.textContent.trim());
    var id = viz ? 'viz-' + viz[1] : slugify(h.textContent);
    if (id && !document.getElementById(id)) {{
      h.id = id;
    }}
  }});
}}

window.addEventListener('DOMContentLoaded', function () {{
  document.getElementById('content').innerHTML =
    renderMarkdown(document.getElementById('md-source').textContent);
  addHeadingIds(document.getElementById('content'));

  // style the contents block: the marker paragraph plus the list that follows it
  var marker = Array.prototype.find.call(
    document.querySelectorAll('#content p'),
    function (el) {{ return el.textContent.trim() === 'Contents'; }});
  if (marker) {{
    var box = document.createElement('nav');
    box.className = 'toc';
    var list = marker.nextElementSibling;
    var note = list ? list.nextElementSibling : null;
    marker.parentNode.insertBefore(box, marker);
    box.appendChild(marker);
    if (list) {{ box.appendChild(list); }}
    if (note && note.tagName === 'P' && note.textContent.indexOf('Links resolve') === 0) {{
      note.className = 'toc-note';
      box.appendChild(note);
    }}
  }}

  // resolve `figure:<name>` image markers against the inlined figure data
  var figures = JSON.parse(document.getElementById('inline-figures').textContent || '{{}}');
  document.querySelectorAll('#content img[src^="figure:"]').forEach(function (img) {{
    var key = img.getAttribute('src').slice('figure:'.length);
    if (figures[key]) {{
      img.src = figures[key];
      var fig = document.createElement('figure');
      var cap = document.createElement('figcaption');
      cap.textContent = img.getAttribute('alt') || '';
      img.parentNode.insertBefore(fig, img);
      fig.appendChild(img);
      fig.appendChild(cap);
    }}
  }});

  // Each visualization's commentary sits beside its figure; render it in place.
  document.querySelectorAll('section.viz').forEach(function (section) {{
    var holder = section.querySelector('script.viz-md');
    var prose = document.createElement('div');
    prose.innerHTML = renderMarkdown(holder.textContent);
    section.insertBefore(prose, section.querySelector('figure'));
    holder.remove();
    addHeadingIds(section);
  }});

  // a hash present at load only resolves once the headings above exist
  if (location.hash) {{
    var target = document.getElementById(location.hash.slice(1));
    if (target) {{
      target.scrollIntoView();
    }}
  }}
}});
</script>
</body>
</html>
"""


def main() -> None:
    nb = json.loads(NB_PATH.read_text())
    inline = {k: data_uri("image/png", v) for k, v in named_figures(nb).items()}
    vizzes = visualizations(nb)
    blocks = [figure_block(v, is_video="3-D" in v["title"]) for v in vizzes]

    html = PAGE.format(
        katex_v=KATEX_VERSION,
        mdit_v=MARKDOWNIT_VERSION,
        katex_css=inline_css(),
        katex_js=inline_js("katex.min.js"),
        markdownit_js=inline_js("markdown-it.min.js"),
        figure_blocks="\n".join(blocks),
        markdown=MD_PATH.read_text(),
        markdown_file=MD_PATH.name,
        notebook=NB_PATH.name,
        inline_figures=json.dumps(inline),
    )
    OUT_PATH.write_text(html)

    # The embedded markdown must stay byte-identical to the source document.
    embedded = html.partition('<script id="md-source" type="text/plain">\n')[2].partition("</script>")[0]
    if embedded != MD_PATH.read_text():
        raise SystemExit(f"embedded markdown does not match {MD_PATH.name}")

    print(f"{OUT_PATH.name}: {OUT_PATH.stat().st_size / 1e6:.2f} MB, "
          f"{len(vizzes)} visualizations ({', '.join(v['title'].split('—')[0].strip() for v in vizzes)})")
    # XML namespace URIs (w3.org) are identifiers, not fetches; the markdown-it banner is a comment.
    benign = ("www.w3.org", "markdown-it/markdown-it")
    external = [u for u in re.findall(r"https?://[^\"' )]+", html) if not any(b in u for b in benign)]
    print(f"inlined document figures: {list(inline) or 'none'}")
    print("network requests:", external or "none — fully self-contained")


if __name__ == "__main__":
    main()

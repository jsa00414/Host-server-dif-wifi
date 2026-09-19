#!/usr/bin/env bash
# Apply Troop 3 site patches (no-zoom, stable mobile hero/stats, copyright).
set -euo pipefail

ROOT="${1:-/opt/sites/troop3}"

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])

# 1) Lock viewport scale
index = root / "index.html"
text = index.read_text(encoding="utf-8")
viewport = (
    'content="width=device-width, initial-scale=1, maximum-scale=1, '
    'minimum-scale=1, user-scalable=no, viewport-fit=cover"'
)
text, n = re.subn(r'content="width=device-width[^"]*"', viewport, text, count=1)
if n == 0:
    raise SystemExit(f"viewport meta not found in {index}")

early = """
    <script>
      /* TROOP3-NO-ZOOM-EARLY */
      (function () {
        function block(e) {
          if (e.ctrlKey || e.metaKey) e.preventDefault();
        }
        function blockKeys(e) {
          if (!(e.ctrlKey || e.metaKey)) return;
          var k = e.key;
          if (k === "+" || k === "-" || k === "=" || k === "_" || k === "0") {
            e.preventDefault();
          }
        }
        function blockGesture(e) { e.preventDefault(); }
        window.addEventListener("wheel", block, { passive: false, capture: true });
        window.addEventListener("mousewheel", block, { passive: false, capture: true });
        window.addEventListener("DOMMouseScroll", block, { passive: false, capture: true });
        window.addEventListener("keydown", blockKeys, { capture: true });
        document.addEventListener("gesturestart", blockGesture, { passive: false, capture: true });
        document.addEventListener("gesturechange", blockGesture, { passive: false, capture: true });
        document.addEventListener("gestureend", blockGesture, { passive: false, capture: true });
      })();
    </script>
"""
if "TROOP3-NO-ZOOM-EARLY" not in text:
    if "</head>" not in text:
        raise SystemExit(f"no </head> in {index}")
    text = text.replace("</head>", early + "\n  </head>", 1)
index.write_text(text, encoding="utf-8")
print(f"updated {index}")

# 2) CSS: no-zoom + mobile hero/stats stretch fix
css = root / "src" / "index.css"
css_text = css.read_text(encoding="utf-8")
marker = "/* TROOP3-NO-ZOOM */"
block = """/* TROOP3-NO-ZOOM */
html {
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
  touch-action: manipulation;
}

html,
body {
  overscroll-behavior-x: none;
  touch-action: pan-x pan-y;
}

input,
textarea,
select,
button {
  font-size: 16px;
  touch-action: manipulation;
}

"""
if marker in css_text:
    css_text = re.sub(
        r"/\* TROOP3-NO-ZOOM \*/.*?(?=\n:root|\Z)",
        "",
        css_text,
        count=1,
        flags=re.S,
    )
css_text = block + css_text.lstrip()

# Lock base .hero height to svh only (dvh stretches when mobile chrome hides)
css_text = re.sub(
    r"(\.hero \{[^}]*?)"
    r"height: calc\(100vh - var\(--header\)\);\s*"
    r"height: calc\(100dvh - var\(--header\)\);\s*"
    r"height: calc\(100svh - var\(--header\)\);\s*"
    r"min-height: calc\(100vh - var\(--header\)\);\s*"
    r"min-height: calc\(100dvh - var\(--header\)\);\s*"
    r"min-height: calc\(100svh - var\(--header\)\);",
    r"\1/* TROOP3-STABLE-HERO */\n"
    r"  height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));\n"
    r"  min-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));\n"
    r"  max-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));",
    css_text,
    count=1,
    flags=re.S,
)

# Mobile hero block: stable svh + non-stretching stats bar
old_mobile_hero = """  .hero {
    display: flex;
    flex-direction: column;
    height: calc(100vh - var(--header));
    height: calc(100dvh - var(--header));
    height: calc(100svh - var(--header));
    min-height: calc(100svh - var(--header));
    max-height: calc(100svh - var(--header));
    overflow: hidden;
  }"""
new_mobile_hero = """  .hero {
    display: flex;
    flex-direction: column;
    /* svh only — dvh/vh resize with the browser chrome and stretch the stats bar */
    height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));
    min-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));
    max-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));
    overflow: hidden;
  }"""
if old_mobile_hero in css_text:
    css_text = css_text.replace(old_mobile_hero, new_mobile_hero)
    print("patched mobile .hero height")
elif "svh only — dvh/vh resize" in css_text:
    print("mobile .hero already patched")
else:
    print("WARN: mobile .hero block not found")

old_stats = """  .hero .stats {
    position: relative;
    bottom: auto;
    left: auto;
    right: auto;
    flex: 0 0 auto;
    width: 100%;
    max-width: 100%;
    min-width: 0;
    min-height: 0;
    grid-template-columns: 1fr 1fr;
    background: var(--forest);
    align-content: stretch;
    padding-bottom: env(safe-area-inset-bottom, 0px);
  }"""
new_stats = """  .hero .stats {
    position: relative;
    bottom: auto;
    left: auto;
    right: auto;
    flex: 0 0 auto;
    flex-grow: 0;
    flex-shrink: 0;
    width: 100%;
    max-width: 100%;
    min-width: 0;
    min-height: 0;
    height: auto;
    grid-template-columns: 1fr 1fr;
    grid-auto-rows: max-content;
    background: var(--forest);
    align-content: start;
    align-items: stretch;
    /* fixed padding — safe-area inset changes on scroll and stretches this bar */
    padding-bottom: 0;
  }"""
if old_stats in css_text:
    css_text = css_text.replace(old_stats, new_stats)
    print("patched mobile .hero .stats")
elif "grid-auto-rows: max-content" in css_text:
    print("mobile .hero .stats already patched")
else:
    print("WARN: mobile .hero .stats block not found")

# Header must clear the iPhone Dynamic Island / status bar.
# With viewport-fit=cover, a plain top:0;height:78px header draws UNDER the
# notch and the logo looks vertically "stretched" / too low in empty cream space.
old_header = """.site-header {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 50;
  height: var(--header);
  max-height: var(--header);
  display: flex;
  align-items: center;
  background: rgba(246, 241, 228, 0.96);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--line);
  /* keep height fixed — do not add safe-area padding here (it changes on scroll) */
}"""
new_header = """.site-header {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 50;
  box-sizing: border-box;
  padding-top: env(safe-area-inset-top, 0px);
  height: calc(var(--header) + env(safe-area-inset-top, 0px));
  max-height: calc(var(--header) + env(safe-area-inset-top, 0px));
  display: flex;
  align-items: center;
  background: rgba(246, 241, 228, 0.96);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--line);
}"""
# Also match upstream without our prior max-height comment patch
old_header_upstream = """.site-header {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 50;
  height: var(--header);
  display: flex;
  align-items: center;
  background: rgba(246, 241, 228, 0.96);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--line);
}"""
if old_header in css_text:
    css_text = css_text.replace(old_header, new_header)
    print("patched .site-header (from prior patch)")
elif old_header_upstream in css_text:
    css_text = css_text.replace(old_header_upstream, new_header)
    print("patched .site-header (upstream)")
elif "safe-area-inset-top" in css_text and ".site-header" in css_text:
    print(".site-header already has safe-area")
else:
    print("WARN: .site-header block not found")

# Keep page content below the taller safe-area header
old_shell = """.site-shell {
  padding-top: var(--header);
  container-type: inline-size;
  container-name: site;
}"""
new_shell = """.site-shell {
  padding-top: calc(var(--header) + env(safe-area-inset-top, 0px));
  container-type: inline-size;
  container-name: site;
}"""
if old_shell in css_text:
    css_text = css_text.replace(old_shell, new_shell)
    print("patched .site-shell")
elif "padding-top: calc(var(--header) + env(safe-area-inset-top" in css_text:
    print(".site-shell already patched")
else:
    print("WARN: .site-shell block not found")

# Hero heights must subtract the same safe-area so the first screen still fits
css_text = css_text.replace(
    "height: calc(100svh - var(--header));\n  min-height: calc(100svh - var(--header));\n  max-height: calc(100svh - var(--header));",
    "height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));\n  min-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));\n  max-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));",
)
# mobile hero block comment variant
css_text = css_text.replace(
    """    /* svh only — dvh/vh resize with the browser chrome and stretch the stats bar */
    height: calc(100svh - var(--header));
    min-height: calc(100svh - var(--header));
    max-height: calc(100svh - var(--header));""",
    """    /* svh only — dvh/vh resize with the browser chrome and stretch the stats bar */
    height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));
    min-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));
    max-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));""",
)
# TroOP3-STABLE-HERO block
css_text = css_text.replace(
    """  /* TROOP3-STABLE-HERO */
  height: calc(100svh - var(--header));
  min-height: calc(100svh - var(--header));
  max-height: calc(100svh - var(--header));""",
    """  /* TROOP3-STABLE-HERO */
  height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));
  min-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));
  max-height: calc(100svh - var(--header) - env(safe-area-inset-top, 0px));""",
)

css.write_text(css_text, encoding="utf-8")
print(f"updated {css}")

# 3) Runtime zoom lock — NO visualViewport transform (that stretched layout on scroll)
no_zoom = root / "src" / "noZoom.ts"
no_zoom.write_text(
    """/** Block browser zoom so the full Troop 3 site stays in frame. */
function isZoomChord(e: KeyboardEvent): boolean {
  if (!(e.ctrlKey || e.metaKey)) return false;
  return e.key === "+" || e.key === "-" || e.key === "=" || e.key === "_" || e.key === "0";
}

function blockWheel(e: WheelEvent) {
  if (e.ctrlKey || e.metaKey) e.preventDefault();
}

function blockKey(e: KeyboardEvent) {
  if (isZoomChord(e)) e.preventDefault();
}

function blockGesture(e: Event) {
  e.preventDefault();
}

export function installNoZoom(): void {
  const wheelOpts: AddEventListenerOptions = { passive: false, capture: true };
  window.addEventListener("wheel", blockWheel, wheelOpts);
  window.addEventListener("mousewheel", blockWheel as EventListener, wheelOpts);
  window.addEventListener("keydown", blockKey, true);
  document.addEventListener("gesturestart", blockGesture, { passive: false, capture: true });
  document.addEventListener("gesturechange", blockGesture, { passive: false, capture: true });
  document.addEventListener("gestureend", blockGesture, { passive: false, capture: true });

  window.addEventListener(
    "touchmove",
    (e) => {
      if (e.touches.length > 1) e.preventDefault();
    },
    { passive: false, capture: true },
  );
}

installNoZoom();
""",
    encoding="utf-8",
)
print(f"wrote {no_zoom}")

main = root / "src" / "main.tsx"
mt = main.read_text(encoding="utf-8")
if 'import "./noZoom"' not in mt and "from \"./noZoom\"" not in mt:
    if 'import "./admin.css";' in mt:
        mt = mt.replace('import "./admin.css";', 'import "./admin.css";\nimport "./noZoom";')
    elif 'import "./index.css";' in mt:
        mt = mt.replace('import "./index.css";', 'import "./index.css";\nimport "./noZoom";')
    else:
        mt = 'import "./noZoom";\n' + mt
    main.write_text(mt, encoding="utf-8")
    print(f"updated {main}")
else:
    print(f"already imports noZoom in {main}")

# 4) Admin editor preview: never scale above 1
editor = root / "src" / "pages" / "admin" / "AdminEditor.tsx"
if editor.is_file():
    et = editor.read_text(encoding="utf-8")
    if "never zoom in past 1" in et:
        print(f"already patched {editor}")
    else:
        old = """      const nextScale =
        device === "phone"
          ? Math.min(1, (canvas.clientWidth - 48) / frame.width)
          : canvas.clientWidth / frame.width;
      setScale(nextScale > 0 ? nextScale : 1);"""
        new = """      // Fit the full preview in the canvas — never zoom in past 1.
      const available =
        device === "phone" ? canvas.clientWidth - 48 : canvas.clientWidth;
      const nextScale = Math.min(1, available / frame.width);
      setScale(nextScale > 0 ? nextScale : 1);"""
        if old not in et:
            raise SystemExit(f"scale block not found in {editor}")
        editor.write_text(et.replace(old, new), encoding="utf-8")
        print(f"updated {editor}")

# 5) Footer copyright credit
layout = root / "src" / "components" / "Layout.tsx"
if layout.is_file():
    lt = layout.read_text(encoding="utf-8")
    credit = (
        "          Copyright © {new Date().getFullYear()} Troop 3 Ambler. Content drawn from\n"
        "          troop3ambler.com. Redesigned by James Aemisegger using Cursor AI."
    )
    if "James Aemisegger using Cursor AI" in lt:
        print(f"already patched copyright in {layout}")
    else:
        old = (
            "          Copyright © {new Date().getFullYear()} Troop 3 Ambler. Content drawn from\n"
            "          troop3ambler.com."
        )
        if old not in lt:
            raise SystemExit(f"copyright block not found in {layout}")
        layout.write_text(lt.replace(old, credit), encoding="utf-8")
        print(f"updated copyright in {layout}")
PY

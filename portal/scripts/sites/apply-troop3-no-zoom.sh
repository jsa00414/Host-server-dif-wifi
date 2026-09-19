#!/usr/bin/env bash
# Apply Troop 3 site patches (no-zoom, stable mobile hero/stats, copyright).
# Note: do NOT add safe-area-inset-top to the fixed header — that left a large
# empty gap below the footer on mobile Safari/Chrome.
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

# 2) CSS patches
css = root / "src" / "index.css"
css_text = css.read_text(encoding="utf-8")

# Strip any previous safe-area header/shell/hero experiments
css_text = css_text.replace(
    "calc(100svh - var(--header) - env(safe-area-inset-top, 0px))",
    "calc(100svh - var(--header))",
)
css_text = css_text.replace(
    "padding-top: calc(var(--header) + env(safe-area-inset-top, 0px));",
    "padding-top: var(--header);",
)

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

# Lock base .hero height to svh only
css_text = re.sub(
    r"(\.hero \{[^}]*?)"
    r"height: calc\(100vh - var\(--header\)\);\s*"
    r"height: calc\(100dvh - var\(--header\)\);\s*"
    r"height: calc\(100svh - var\(--header\)\);\s*"
    r"min-height: calc\(100vh - var\(--header\)\);\s*"
    r"min-height: calc\(100dvh - var\(--header\)\);\s*"
    r"min-height: calc\(100svh - var\(--header\)\);",
    r"\1/* TROOP3-STABLE-HERO */\n"
    r"  height: calc(100svh - var(--header));\n"
    r"  min-height: calc(100svh - var(--header));\n"
    r"  max-height: calc(100svh - var(--header));",
    css_text,
    count=1,
    flags=re.S,
)

# Also normalize an already-patched STABLE-HERO that still had safe-area
css_text = re.sub(
    r"/\* TROOP3-STABLE-HERO \*/\s*"
    r"height: calc\(100svh - var\(--header\)(?: - env\(safe-area-inset-top, 0px\))?\);\s*"
    r"min-height: calc\(100svh - var\(--header\)(?: - env\(safe-area-inset-top, 0px\))?\);\s*"
    r"max-height: calc\(100svh - var\(--header\)(?: - env\(safe-area-inset-top, 0px\))?\);",
    "/* TROOP3-STABLE-HERO */\n"
    "  height: calc(100svh - var(--header));\n"
    "  min-height: calc(100svh - var(--header));\n"
    "  max-height: calc(100svh - var(--header));",
    css_text,
    count=1,
)

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
    height: calc(100svh - var(--header));
    min-height: calc(100svh - var(--header));
    max-height: calc(100svh - var(--header));
    overflow: hidden;
  }"""
if old_mobile_hero in css_text:
    css_text = css_text.replace(old_mobile_hero, new_mobile_hero)
    print("patched mobile .hero height")
elif "svh only — dvh/vh resize" in css_text:
    # ensure no safe-area left in that block
    css_text = re.sub(
        r"(/\* svh only[^*]*\*/\s*)"
        r"height: calc\(100svh - var\(--header\)(?: - env\(safe-area-inset-top, 0px\))?\);\s*"
        r"min-height: calc\(100svh - var\(--header\)(?: - env\(safe-area-inset-top, 0px\))?\);\s*"
        r"max-height: calc\(100svh - var\(--header\)(?: - env\(safe-area-inset-top, 0px\))?\);",
        r"\1height: calc(100svh - var(--header));\n"
        r"    min-height: calc(100svh - var(--header));\n"
        r"    max-height: calc(100svh - var(--header));",
        css_text,
        count=1,
    )
    print("normalized mobile .hero height")
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
    padding-bottom: 0;
  }"""
if old_stats in css_text:
    css_text = css_text.replace(old_stats, new_stats)
    print("patched mobile .hero .stats")
elif "grid-auto-rows: max-content" in css_text:
    print("mobile .hero .stats already patched")
else:
    print("WARN: mobile .hero .stats block not found")

# Revert any safe-area header back to plain fixed height
old_header_safe = """.site-header {
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
new_header = """.site-header {
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
}"""
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
if old_header_safe in css_text:
    css_text = css_text.replace(old_header_safe, new_header)
    print("reverted .site-header safe-area")
elif old_header_upstream in css_text:
    css_text = css_text.replace(old_header_upstream, new_header)
    print("normalized .site-header")
else:
    print(".site-header left as-is / already plain")

# Sticky footer: keep green footer flush to the bottom of the viewport
# when the page is shorter than the screen (and remove leftover gap).
footer_fix = """
/* TROOP3-FOOTER-FLUSH */
html,
body,
#root {
  min-height: 100%;
}

#root {
  display: flex;
  flex-direction: column;
}

.site-shell {
  flex: 1 0 auto;
  display: flex;
  flex-direction: column;
  min-height: 100svh;
  box-sizing: border-box;
}

.site-shell > *:not(.site-footer) {
  flex: 0 0 auto;
}

.site-footer {
  margin-top: auto;
}
"""
if "/* TROOP3-FOOTER-FLUSH */" in css_text:
    css_text = re.sub(
        r"/\* TROOP3-FOOTER-FLUSH \*/.*?(?=\n/\* |\n:root|\Z)",
        "",
        css_text,
        count=1,
        flags=re.S,
    )
# append near end
css_text = css_text.rstrip() + "\n" + footer_fix
print("added footer flush")

css.write_text(css_text, encoding="utf-8")
print(f"updated {css}")

# 3) Runtime zoom lock — no visualViewport transform
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

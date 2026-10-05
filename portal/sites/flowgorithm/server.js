#!/usr/bin/env node
/**
 * Flowgorithm — educational flowchart programming in the browser.
 * Run: node server.js
 * Open: http://localhost:3000
 */

const http = require("http");
const { URL } = require("url");

const PORT = Number(process.env.PORT) || 3000;

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, minimum-scale=1, user-scalable=no, viewport-fit=cover" />
  <title>Flowgorithm</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg0: #0f1c24;
      --bg1: #152833;
      --panel: #1a303c;
      --panel-2: #213845;
      --line: #2f4a58;
      --text: #e8f1f4;
      --muted: #8aa3af;
      --accent: #2eb8a6;
      --accent-2: #f0b429;
      --danger: #e85d5d;
      --io: #3d8bfd;
      --decide: #e6c35c;
      --process: #5ad4c0;
      --terminal: #9b8cff;
      --shadow: 0 18px 40px rgba(0, 0, 0, 0.35);
      --font: "Figtree", sans-serif;
      --mono: "IBM Plex Mono", monospace;
      --app-height: 100dvh;
    }

    * { box-sizing: border-box; }
    html {
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
    }
    html, body {
      margin: 0;
      width: 100%;
      max-width: 100%;
      height: var(--app-height);
      max-height: var(--app-height);
      overflow: hidden;
      overscroll-behavior: none;
      touch-action: manipulation;
      font-family: var(--font);
      color: var(--text);
      background:
        radial-gradient(1200px 600px at 10% -10%, rgba(46, 184, 166, 0.18), transparent 55%),
        radial-gradient(900px 500px at 100% 0%, rgba(240, 180, 41, 0.12), transparent 50%),
        linear-gradient(160deg, var(--bg0), var(--bg1));
    }

    body {
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
      min-height: 0;
    }

    header.app-bar {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.85rem 1.25rem;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      backdrop-filter: blur(10px);
      background: rgba(15, 28, 36, 0.92);
      min-width: 0;
      flex-shrink: 0;
      z-index: 40;
    }

    .brand {
      display: flex;
      align-items: baseline;
      gap: 0.55rem;
      min-width: 0;
      flex-shrink: 1;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.35rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      white-space: nowrap;
    }
    .brand span {
      color: var(--muted);
      font-size: 0.78rem;
      font-weight: 500;
      white-space: nowrap;
    }

    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      align-items: center;
      flex: 1;
      min-width: 0;
    }

    /* Desktop: fixed vertical topbar (left rail) */
    @media (min-width: 981px) {
      body {
        grid-template-columns: 92px minmax(0, 1fr);
        grid-template-rows: minmax(0, 1fr);
      }

      header.app-bar {
        position: fixed;
        top: 0;
        left: 0;
        bottom: 0;
        width: 92px;
        height: var(--app-height);
        max-height: var(--app-height);
        flex-direction: column;
        align-items: stretch;
        justify-content: flex-start;
        gap: 0.85rem;
        padding: 1rem 0.55rem;
        border-bottom: none;
        border-right: 1px solid rgba(255,255,255,0.06);
        overflow-x: hidden;
        overflow-y: auto;
        overscroll-behavior: contain;
      }

      .brand {
        flex-direction: column;
        align-items: center;
        text-align: center;
        gap: 0.15rem;
        flex-shrink: 0;
      }
      .brand h1 {
        font-size: 0.78rem;
        letter-spacing: 0.02em;
        white-space: normal;
        line-height: 1.15;
        writing-mode: horizontal-tb;
      }
      .brand span {
        display: none;
      }

      .toolbar {
        flex-direction: column;
        flex-wrap: nowrap;
        align-items: stretch;
        flex: 1;
        gap: 0.35rem;
        width: 100%;
      }

      .toolbar button,
      .toolbar .file-btn {
        width: 100%;
        justify-content: center;
        text-align: center;
        padding: 0.55rem 0.35rem;
        font-size: 0.72rem;
      }

      main {
        grid-column: 2;
        grid-row: 1;
        height: var(--app-height);
        max-height: var(--app-height);
      }
    }

    button, .file-btn {
      font-family: var(--font);
      font-weight: 600;
      font-size: 0.85rem;
      border: 1px solid transparent;
      border-radius: 0.55rem;
      padding: 0.45rem 0.8rem;
      cursor: pointer;
      color: var(--text);
      background: var(--panel-2);
      transition: transform 120ms ease, background 120ms ease, border-color 120ms ease;
    }
    button:hover, .file-btn:hover {
      background: #2a4654;
      border-color: rgba(255,255,255,0.08);
    }
    button:active { transform: translateY(1px); }
    button.primary {
      background: linear-gradient(135deg, #2eb8a6, #249889);
      color: #06221e;
    }
    button.primary:hover { background: linear-gradient(135deg, #3dccb9, #2eb8a6); }
    button.warn { background: #3a2a18; color: #ffd27a; }
    button.ghost,
    .file-btn.ghost {
      background: transparent;
      border-color: var(--line);
      color: var(--muted);
    }
    button:disabled,
    .file-btn:disabled,
    button[disabled] {
      opacity: 0.4;
      cursor: not-allowed;
      filter: grayscale(0.35);
    }
    button.warn:disabled {
      background: var(--panel-2);
      color: var(--muted);
      filter: none;
      opacity: 0.45;
    }

    .file-btn { display: inline-flex; align-items: center; }
    .file-btn input { display: none; }

    main {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 300px;
      min-height: 0;
      min-width: 0;
      height: 100%;
      overflow: hidden;
      gap: 0;
    }

    .side {
      background: rgba(26, 48, 60, 0.88);
      border-left: 1px solid rgba(255,255,255,0.05);
      padding: 1rem;
      overflow: auto;
      min-height: 0;
      min-width: 0;
      display: grid;
      /* Functions + Inspector + Variables compact; Console fills leftover */
      grid-template-rows: auto auto auto minmax(0, 1fr);
      gap: 0.65rem;
      align-content: start;
    }
    .side > div {
      min-width: 0;
      min-height: 0;
    }

    .fn-panel {
      display: grid;
      gap: 0.45rem;
    }
    .fn-row {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: 0.35rem;
      align-items: center;
    }
    .fn-row select,
    .fn-panel input,
    .fn-panel select {
      width: 100%;
      font-family: var(--mono);
      font-size: 0.78rem;
      color: var(--text);
      background: #122029;
      border: 1px solid var(--line);
      border-radius: 0.45rem;
      padding: 0.4rem 0.45rem;
    }
    .fn-row button {
      padding: 0.4rem 0.55rem;
      min-width: 2rem;
    }
    .fn-params {
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--muted);
      line-height: 1.35;
    }

    h2 {
      margin: 0 0 0.75rem;
      font-size: 0.72rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 700;
    }

    .workspace {
      position: relative;
      min-height: 0;
      min-width: 0;
      height: 100%;
      overflow: hidden;
      /* Classic Flowgorithm chart surface */
      background-color: #eceff3;
      background-image:
        linear-gradient(rgba(60, 80, 100, 0.07) 1px, transparent 1px),
        linear-gradient(90deg, rgba(60, 80, 100, 0.07) 1px, transparent 1px);
      background-size: 24px 24px;
      box-shadow: inset 0 0 0 1px rgba(0,0,0,0.06);
    }

    #canvas {
      width: 100%;
      height: 100%;
      max-width: 100%;
      max-height: 100%;
      display: block;
      cursor: grab;
      touch-action: none;
      -webkit-user-select: none;
      user-select: none;
    }
    #canvas.dragging { cursor: grabbing; }

    .inspector label {
      display: block;
      font-size: 0.75rem;
      color: var(--muted);
      margin: 0.55rem 0 0.25rem;
    }
    .inspector input, .inspector select, .inspector textarea {
      width: 100%;
      font-family: var(--mono);
      font-size: 0.82rem;
      color: var(--text);
      background: #122029;
      border: 1px solid var(--line);
      border-radius: 0.45rem;
      padding: 0.5rem 0.55rem;
    }
    .inspector textarea { min-height: 4.5rem; resize: vertical; }
    .empty-state {
      color: var(--muted);
      font-size: 0.9rem;
      line-height: 1.4;
    }

    .console-wrap {
      display: grid;
      grid-template-rows: auto minmax(0, 1fr) auto;
      min-height: 0;
      height: 100%;
      max-height: 100%;
      border-top: 1px solid rgba(255,255,255,0.06);
      background: #101c23;
      border-radius: 0.65rem;
      overflow: hidden;
    }
    .console-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.45rem 0.65rem;
      background: #152631;
      font-size: 0.75rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
    }
    #console {
      margin: 0;
      padding: 0.65rem;
      overflow: auto;
      font-family: var(--mono);
      font-size: 0.78rem;
      line-height: 1.45;
      white-space: pre-wrap;
      color: #d7ebe6;
    }
    #console .err { color: #ff8f8f; }
    #console .out { color: #9be7d8; }
    #console .sys { color: #8aa3af; }
    .prompt-row {
      display: flex;
      gap: 0.35rem;
      align-items: center;
      padding: 0.45rem;
      border-top: 1px solid rgba(255,255,255,0.06);
    }
    .prompt-row input {
      flex: 1;
      min-width: 0;
      font-family: var(--mono);
      font-size: 0.8rem;
      color: var(--text);
      background: #122029;
      border: 1px solid var(--line);
      border-radius: 0.4rem;
      padding: 0.45rem 0.55rem;
    }
    .prompt-row button {
      flex-shrink: 0;
      white-space: nowrap;
    }

    .vars {
      font-family: var(--mono);
      font-size: 0.78rem;
      background: #101c23;
      border-radius: 0.65rem;
      padding: 0.55rem 0.65rem;
      min-height: 2.25rem;
      max-height: 5.5rem;
      overflow: auto;
      color: #c9dde5;
      white-space: pre-wrap;
    }

    .inspector .hint {
      margin-top: 0.45rem;
      font-size: 0.72rem;
    }

    /* Flowgorithm-style Add Shape popup (click a connector arrow) */
    .add-menu-backdrop {
      position: fixed;
      inset: 0;
      z-index: 80;
      background: rgba(15, 28, 36, 0.28);
      display: none;
    }
    .add-menu-backdrop.open { display: block; }

    .add-menu {
      position: fixed;
      z-index: 90;
      display: none;
      width: min(560px, calc(100vw - 24px));
      max-height: min(520px, calc(100dvh - 24px));
      overflow: auto;
      background: #f7f8fa;
      border: 1px solid #9aa7b5;
      border-radius: 6px;
      box-shadow: 0 14px 40px rgba(0,0,0,0.28);
      color: #1a2430;
      font-family: var(--font);
      padding: 0.55rem;
    }
    .add-menu.open { display: block; }
    .add-menu-grid {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 0.55rem;
    }
    .add-section {
      background: #fff;
      border: 1px solid #c5ced8;
      border-radius: 4px;
      overflow: hidden;
    }
    .add-section h3 {
      margin: 0;
      padding: 0.35rem 0.55rem;
      font-size: 0.78rem;
      font-weight: 700;
      background: #9ec5e8;
      color: #102028;
      border-bottom: 1px solid #7aaad0;
    }
    .add-section .cols {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 0.35rem;
      padding: 0.45rem;
    }
    .add-section .cols.three { grid-template-columns: repeat(3, 1fr); }
    .add-section .cols.one { grid-template-columns: 1fr; }
    .add-col-label {
      grid-column: 1 / -1;
      font-size: 0.68rem;
      font-weight: 700;
      color: #5a6a7a;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-top: 0.15rem;
    }
    .add-item {
      appearance: none;
      border: none;
      background: transparent;
      padding: 0.2rem;
      cursor: pointer;
      display: grid;
      gap: 0.2rem;
      justify-items: center;
      font-family: var(--font);
      color: #102028;
    }
    .add-item:hover { background: rgba(158, 197, 232, 0.35); border-radius: 4px; }
    .add-item:disabled { opacity: 0.4; cursor: not-allowed; }
    .add-glyph {
      width: 88px;
      height: 34px;
      display: grid;
      place-items: center;
      font-size: 0.72rem;
      font-weight: 700;
      color: #102028;
      border: 1.5px solid #1f2a32;
    }
    .add-glyph.input { background: #bdd7ee; clip-path: polygon(12% 0, 100% 0, 88% 100%, 0 100%); border: none; outline: 1.5px solid #1f2a32; }
    .add-glyph.output { background: #c6efce; clip-path: polygon(12% 0, 100% 0, 88% 100%, 0 100%); border: none; outline: 1.5px solid #1f2a32; }
    .add-glyph.declare { background: #fff2cc; border-left-width: 5px; }
    .add-glyph.assign { background: #fff2cc; }
    .add-glyph.if {
      background: #f4cccc;
      width: 56px;
      height: 40px;
      clip-path: polygon(50% 0, 100% 50%, 50% 100%, 0 50%);
      border: none;
      outline: 1.5px solid #1f2a32;
    }
    .add-glyph.call { background: #d9d2e9; border-left-width: 4px; border-right-width: 4px; }
    .add-glyph.while,
    .add-glyph.for,
    .add-glyph.do {
      background: #f8cbad;
      border-radius: 16px;
    }
    .add-glyph.comment {
      background: #fff;
      border-style: dashed;
    }
    .add-glyph.breakpoint {
      background: #e06666;
      color: #fff;
      width: 34px;
      border-radius: 6px;
      clip-path: polygon(30% 0, 70% 0, 100% 30%, 100% 70%, 70% 100%, 30% 100%, 0 70%, 0 30%);
      border: none;
      outline: 1.5px solid #1f2a32;
    }
    .add-item span.cap {
      font-size: 0.7rem;
      font-weight: 600;
    }
    .add-menu-foot {
      margin-top: 0.45rem;
      font-size: 0.72rem;
      color: #5a6a7a;
      text-align: center;
    }

    @media (max-width: 700px) {
      .add-menu-grid { grid-template-columns: 1fr; }
    }

    @media (max-width: 980px) {
      header.app-bar {
        flex-wrap: wrap;
        padding: 0.65rem 0.85rem;
        gap: 0.55rem;
      }
      .brand span { display: none; }
      .brand h1 { font-size: 1.15rem; }
      main {
        grid-template-columns: 1fr;
        grid-template-rows: minmax(0, 1fr) minmax(0, 36%);
        overflow: hidden;
      }
      .side {
        border: none;
        border-top: 1px solid rgba(255,255,255,0.05);
        padding: 0.55rem 0.85rem;
        grid-template-rows: auto auto auto minmax(0, 1fr);
        overflow: auto;
        max-height: 100%;
      }
      .inspector .hint { display: none; }
      .console-wrap {
        min-height: 0;
        height: auto;
        max-height: none;
      }
      .vars {
        min-height: 1.75rem;
        max-height: 3.5rem;
      }
      /* Keep iOS from zooming/stretching the page on focus */
      .inspector input,
      .inspector select,
      .inspector textarea,
      .prompt-row input,
      button,
      .file-btn {
        font-size: 16px;
      }
    }

    @supports not (height: 100dvh) {
      :root { --app-height: 100vh; }
    }
  </style>
  <script>
    /* Keep layout locked to the visible viewport (mobile browser chrome). */
    (function () {
      function setAppHeight() {
        var h = window.visualViewport ? window.visualViewport.height : window.innerHeight;
        document.documentElement.style.setProperty("--app-height", h + "px");
      }
      setAppHeight();
      window.addEventListener("resize", setAppHeight);
      if (window.visualViewport) {
        window.visualViewport.addEventListener("resize", setAppHeight);
        window.visualViewport.addEventListener("scroll", setAppHeight);
      }
      document.addEventListener("gesturestart", function (e) { e.preventDefault(); }, { passive: false });
    })();
  </script>
</head>
<body>
  <header class="app-bar">
    <div class="brand">
      <h1>Flowgorithm</h1>
      <span>flowchart → program</span>
    </div>
    <div class="toolbar">
      <button type="button" class="primary" id="btn-run">Run</button>
      <button type="button" class="warn" id="btn-stop" disabled>Stop</button>
      <button type="button" class="ghost" id="btn-step">Step</button>
      <button type="button" class="ghost" id="btn-new">New</button>
      <button type="button" class="ghost" id="btn-example">Example</button>
      <label class="file-btn ghost" id="btn-open">Open<input type="file" id="file-open" accept=".json,.fprg,application/json,text/xml" /></label>
      <button type="button" class="ghost" id="btn-save">Save</button>
      <button type="button" class="ghost" id="btn-delete" title="Delete selected">Delete</button>
    </div>
  </header>

  <main>
    <section class="workspace">
      <svg id="canvas" xmlns="http://www.w3.org/2000/svg"></svg>
    </section>

    <section class="side">
      <div>
        <h2>Functions</h2>
        <div class="fn-panel">
          <div class="fn-row">
            <select id="fn-select" title="Active function"></select>
            <button type="button" class="ghost" id="btn-fn-add" title="Add function">+</button>
            <button type="button" class="ghost" id="btn-fn-del" title="Delete function">−</button>
          </div>
          <div id="fn-meta"></div>
          <div class="fn-params" id="fn-params"></div>
        </div>
      </div>
      <div>
        <h2>Inspector</h2>
        <div class="inspector" id="inspector">
          <p class="empty-state">Select a shape to edit its properties.</p>
        </div>
      </div>
      <div>
        <h2>Variables</h2>
        <div class="vars" id="vars">(idle)</div>
      </div>
      <div class="console-wrap">
        <div class="console-head">
          <span>Console</span>
          <button type="button" class="ghost" id="btn-clear-console" style="padding:0.2rem 0.45rem;font-size:0.7rem">Clear</button>
        </div>
        <pre id="console"></pre>
        <div class="prompt-row">
          <input id="stdin" placeholder="Input value…" disabled />
          <button type="button" id="btn-submit" disabled>Enter</button>
        </div>
      </div>
    </section>
  </main>

  <div class="add-menu-backdrop" id="add-backdrop" hidden></div>
  <div class="add-menu" id="add-menu" role="dialog" aria-label="Add shape" hidden>
    <div class="add-menu-grid">
      <div>
        <div class="add-section" style="margin-bottom:0.55rem">
          <h3>Miscellaneous</h3>
          <div class="cols">
            <button type="button" class="add-item" data-add="comment"><span class="add-glyph comment">Comment</span><span class="cap">Comment</span></button>
            <button type="button" class="add-item" data-add="breakpoint"><span class="add-glyph breakpoint">BP</span><span class="cap">Breakpoint</span></button>
          </div>
        </div>
        <div class="add-section">
          <h3>Statement</h3>
          <div class="cols three">
            <div class="add-col-label">Input / Output</div>
            <button type="button" class="add-item" data-add="input"><span class="add-glyph input">Input</span><span class="cap">Input</span></button>
            <button type="button" class="add-item" data-add="output"><span class="add-glyph output">Output</span><span class="cap">Output</span></button>
            <span></span>
            <div class="add-col-label">Variables</div>
            <button type="button" class="add-item" data-add="declare"><span class="add-glyph declare">Declare</span><span class="cap">Declare</span></button>
            <button type="button" class="add-item" data-add="assign"><span class="add-glyph assign">Assign</span><span class="cap">Assign</span></button>
            <span></span>
            <div class="add-col-label">Control</div>
            <button type="button" class="add-item" data-add="if"><span class="add-glyph if">If</span><span class="cap">If</span></button>
            <button type="button" class="add-item" data-add="call"><span class="add-glyph call">Call</span><span class="cap">Call</span></button>
            <span></span>
            <div class="add-col-label">Looping</div>
            <button type="button" class="add-item" data-add="while"><span class="add-glyph while">While</span><span class="cap">While</span></button>
            <button type="button" class="add-item" data-add="for"><span class="add-glyph for">For</span><span class="cap">For</span></button>
            <button type="button" class="add-item" data-add="do"><span class="add-glyph do">Do</span><span class="cap">Do</span></button>
          </div>
        </div>
      </div>
      <div>
        <div class="add-section" style="margin-bottom:0.55rem">
          <h3>Turtle Graphics</h3>
          <div class="cols one">
            <button type="button" class="add-item" disabled title="Coming soon"><span class="add-glyph assign">Forward</span><span class="cap">Forward</span></button>
            <button type="button" class="add-item" disabled title="Coming soon"><span class="add-glyph assign">Turn</span><span class="cap">Turn</span></button>
            <button type="button" class="add-item" disabled title="Coming soon"><span class="add-glyph output">Clear</span><span class="cap">Clear</span></button>
          </div>
        </div>
        <div class="add-section">
          <h3>Files</h3>
          <div class="cols">
            <button type="button" class="add-item" disabled title="Coming soon"><span class="add-glyph input">Read</span><span class="cap">Read</span></button>
            <button type="button" class="add-item" disabled title="Coming soon"><span class="add-glyph output">Write</span><span class="cap">Write</span></button>
            <button type="button" class="add-item" disabled title="Coming soon"><span class="add-glyph assign">Open</span><span class="cap">Open</span></button>
            <button type="button" class="add-item" disabled title="Coming soon"><span class="add-glyph assign">Close</span><span class="cap">Close</span></button>
          </div>
        </div>
      </div>
    </div>
    <p class="add-menu-foot">Click a connector arrow, then choose a shape to insert — like Flowgorithm.</p>
  </div>

  <script>
  (() => {
    /* Classic Flowgorithm-inspired chart style */
    const STYLE = {
      fill: {
        start: "#c6efce",
        end: "#c6efce",
        declare: "#fff2cc",
        assign: "#fff2cc",
        input: "#bdd7ee",
        output: "#c6efce",
        if: "#f4cccc",
        while: "#f8cbad",
        for: "#f8cbad",
        do: "#f8cbad",
        comment: "#ffffff",
        breakpoint: "#e06666",
        call: "#d9d2e9",
      },
      stroke: "#1f2a32",
      line: "#1f2a32",
      trueStroke: "#2e7d32",
      falseStroke: "#c62828",
      text: "#102028",
      selected: "#1565c0",
      link: "#6a1b9a",
      exec: "#ef6c00",
      size: {
        start: { w: 150, h: 48 },
        end: { w: 150, h: 48 },
        declare: { w: 170, h: 52 },
        assign: { w: 170, h: 52 },
        input: { w: 170, h: 52 },
        output: { w: 170, h: 52 },
        if: { w: 180, h: 78 },
        while: { w: 180, h: 70 },
        for: { w: 190, h: 70 },
        do: { w: 180, h: 70 },
        comment: { w: 170, h: 48 },
        breakpoint: { w: 56, h: 56 },
        call: { w: 170, h: 52 },
      },
    };

    const state = {
      functions: [],
      activeFn: "Main",
      nodes: [],
      edges: [],
      selectedId: null,
      linkFrom: null,
      pan: { x: 80, y: 28 },
      draggingNode: null,
      panning: false,
      panStart: null,
      running: false,
      waitingInput: null,
      stepMode: false,
      stepResolve: null,
      highlightId: null,
      vars: Object.create(null),
      idSeq: 1,
      pendingEdge: null,
    };

    const svg = document.getElementById("canvas");
    const inspector = document.getElementById("inspector");
    const consoleEl = document.getElementById("console");
    const varsEl = document.getElementById("vars");
    const stdin = document.getElementById("stdin");
    const btnSubmit = document.getElementById("btn-submit");
    const btnRun = document.getElementById("btn-run");
    const btnStop = document.getElementById("btn-stop");
    const btnStep = document.getElementById("btn-step");
    const fnSelect = document.getElementById("fn-select");
    const fnMeta = document.getElementById("fn-meta");
    const fnParams = document.getElementById("fn-params");

    function getFn(name) {
      return state.functions.find((f) => f.name === name);
    }

    function blankFunction(name, returnType = "None", parameters = []) {
      state.idSeq = 1;
      const s = makeNode("start", 260, 36);
      const e = makeNode("end", 260, 220, { expression: "" });
      return {
        name,
        returnType,
        parameters: parameters.slice(),
        nodes: [s, e],
        edges: [{ from: s.id, to: e.id, branch: "next" }],
        idSeq: state.idSeq,
        pan: { x: 80, y: 28 },
      };
    }

    function flushActive() {
      const f = getFn(state.activeFn);
      if (!f) return;
      f.nodes = state.nodes;
      f.edges = state.edges;
      f.idSeq = state.idSeq;
      f.pan = { x: state.pan.x, y: state.pan.y };
    }

    function loadActive() {
      const f = getFn(state.activeFn) || state.functions[0];
      if (!f) return;
      state.activeFn = f.name;
      state.nodes = f.nodes;
      state.edges = f.edges;
      state.idSeq = f.idSeq || 1;
      state.pan = f.pan ? { x: f.pan.x, y: f.pan.y } : { x: 80, y: 28 };
      state.selectedId = null;
      state.linkFrom = null;
    }

    function switchFunction(name) {
      if (!name || name === state.activeFn) return;
      flushActive();
      state.activeFn = name;
      loadActive();
      renderFnUi();
      render();
      renderInspector();
    }

    function renderFnUi() {
      fnSelect.innerHTML = state.functions.map((f) =>
        \`<option value="\${escapeAttr(f.name)}" \${f.name === state.activeFn ? "selected" : ""}>\${escapeAttr(f.name)}</option>\`
      ).join("");
      const f = getFn(state.activeFn);
      if (!f) {
        fnMeta.innerHTML = "";
        fnParams.textContent = "";
        return;
      }
      fnMeta.innerHTML =
        select("fnReturn", "Return type", f.returnType, ["None", "Integer", "Real", "String", "Boolean"]) +
        field("fnName", "Name", f.name) +
        field("fnParams", "Parameters", f.parameters.map((p) => \`\${p.typeName} \${p.name}\`).join(", "));
      fnParams.textContent = f.parameters.length
        ? "params: " + f.parameters.map((p) => \`\${p.typeName} \${p.name}\`).join(", ")
        : "no parameters";
      const nameEl = fnMeta.querySelector('[data-prop="fnName"]');
      const retEl = fnMeta.querySelector('[data-prop="fnReturn"]');
      const parEl = fnMeta.querySelector('[data-prop="fnParams"]');
      if (nameEl) {
        nameEl.addEventListener("change", () => renameActiveFunction(nameEl.value.trim()));
      }
      if (retEl) {
        retEl.addEventListener("change", () => {
          f.returnType = retEl.value;
          render();
        });
      }
      if (parEl) {
        parEl.addEventListener("change", () => {
          f.parameters = parseParamList(parEl.value);
          fnParams.textContent = f.parameters.length
            ? "params: " + f.parameters.map((p) => \`\${p.typeName} \${p.name}\`).join(", ")
            : "no parameters";
        });
      }
      document.getElementById("btn-fn-del").disabled = f.name === "Main" || state.functions.length < 2;
    }

    function parseParamList(text) {
      return String(text || "").split(",").map((part) => part.trim()).filter(Boolean).map((part) => {
        const bits = part.split(/\\s+/);
        if (bits.length >= 2) return { typeName: bits[0], name: bits[1] };
        return { typeName: "Integer", name: bits[0] };
      });
    }

    function renameActiveFunction(newName) {
      if (!newName || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(newName)) {
        log("Invalid function name.", "err");
        renderFnUi();
        return;
      }
      if (state.functions.some((f) => f.name === newName && f.name !== state.activeFn)) {
        log("Function name already exists.", "err");
        renderFnUi();
        return;
      }
      const old = state.activeFn;
      const f = getFn(old);
      f.name = newName;
      state.activeFn = newName;
      // update Call shapes across all functions
      state.functions.forEach((fn) => {
        fn.nodes.forEach((n) => {
          if (n.type === "call" && n.props.name === old) n.props.name = newName;
        });
      });
      renderFnUi();
      render();
    }

    function addFunction() {
      flushActive();
      let base = "Function";
      let i = 1;
      while (getFn(base + i)) i++;
      const name = base + i;
      const fn = blankFunction(name, "Integer", [{ name: "x", typeName: "Integer" }]);
      state.functions.push(fn);
      state.activeFn = name;
      loadActive();
      renderFnUi();
      render();
      renderInspector();
      log("Added function " + name, "sys");
    }

    function deleteFunction() {
      if (state.activeFn === "Main") return;
      const name = state.activeFn;
      flushActive();
      state.functions = state.functions.filter((f) => f.name !== name);
      state.activeFn = "Main";
      loadActive();
      renderFnUi();
      render();
      renderInspector();
      log("Deleted function " + name, "sys");
    }

    function parseArgList(text) {
      // split on commas not inside quotes
      const out = [];
      let cur = "";
      let q = null;
      for (let i = 0; i < String(text || "").length; i++) {
        const c = text[i];
        if (q) {
          cur += c;
          if (c === q) q = null;
          continue;
        }
        if (c === '"' || c === "'") { q = c; cur += c; continue; }
        if (c === ",") { out.push(cur.trim()); cur = ""; continue; }
        cur += c;
      }
      if (cur.trim()) out.push(cur.trim());
      return out;
    }

    function uid() {
      return "n" + (state.idSeq++);
    }

    function log(text, cls = "sys") {
      const span = document.createElement("span");
      span.className = cls;
      span.textContent = text + "\\n";
      consoleEl.appendChild(span);
      consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    function defaultProps(type) {
      switch (type) {
        case "declare": return { name: "x", typeName: "Integer", isArray: false, size: "" };
        case "input": return { variable: "x" };
        case "output": return { expression: '"Hello"' };
        case "assign": return { variable: "x", expression: "x + 1" };
        case "if": return { condition: "x > 0" };
        case "while": return { condition: "x < 10" };
        case "do": return { condition: "x < 10" };
        case "for": return { variable: "i", start: "1", end: "10", step: "1" };
        case "comment": return { text: "Comment" };
        case "breakpoint": return {};
        case "call": return { name: "Double", args: "n", result: "" };
        case "end": return { expression: "" };
        default: return {};
      }
    }

    function nodeLabel(n) {
      const p = n.props || {};
      switch (n.type) {
        case "start": return state.activeFn === "Main" ? "Start" : state.activeFn;
        case "end": {
          const fn = getFn(state.activeFn);
          if (fn && fn.returnType !== "None" && p.expression) return "Return " + p.expression;
          return "End";
        }
        case "declare": return p.isArray ? \`\${p.typeName} \${p.name}[\${p.size || "?"}]\` : \`\${p.typeName} \${p.name}\`;
        case "input": return \`Input \${p.variable}\`;
        case "output": return \`Output \${p.expression}\`;
        case "assign": return \`\${p.variable} = \${p.expression}\`;
        case "if": return p.condition;
        case "while": return \`While \${p.condition}\`;
        case "do": return \`Do \${p.condition}\`;
        case "for": return \`For \${p.variable} = \${p.start} to \${p.end}\`;
        case "comment": return p.text || "Comment";
        case "breakpoint": return "●";
        case "call": {
          const call = \`\${p.name || "?"}(\${p.args || ""})\`;
          return p.result ? \`\${p.result} = \${call}\` : \`Call \${call}\`;
        }
        default: return n.type;
      }
    }

    function makeNode(type, x, y, props) {
      const sz = STYLE.size[type] || { w: 170, h: 52 };
      return {
        id: uid(),
        type,
        x,
        y,
        w: sz.w,
        h: sz.h,
        props: props || defaultProps(type),
      };
    }

    function addNode(type, x = 220 + state.nodes.length * 8, y = 60 + state.nodes.length * 70) {
      if ((type === "start" || type === "end") && state.nodes.some((n) => n.type === type)) {
        log(\`Only one \${type} shape is allowed.\`, "err");
        return;
      }
      const node = makeNode(type, x, y);
      state.nodes.push(node);
      state.selectedId = node.id;
      render();
      renderInspector();
    }

    function findNode(id) {
      return state.nodes.find((n) => n.id === id);
    }

    function deleteSelected() {
      if (!state.selectedId) return;
      const id = state.selectedId;
      state.nodes = state.nodes.filter((n) => n.id !== id);
      state.edges = state.edges.filter((e) => e.from !== id && e.to !== id);
      if (state.linkFrom === id) state.linkFrom = null;
      state.selectedId = null;
      render();
      renderInspector();
    }

    function connect(fromId, toId) {
      if (fromId === toId) return;
      const from = findNode(fromId);
      const to = findNode(toId);
      if (!from || !to) return;

      let branch = "next";
      if (from.type === "if" || from.type === "while" || from.type === "for" || from.type === "do") {
        // Flowgorithm convention: True on the left, False on the right
        const fromCx = from.x + from.w / 2;
        const toCx = to.x + to.w / 2;
        branch = toCx <= fromCx ? "true" : "false";
      }

      if (from.type === "if" || from.type === "while" || from.type === "for" || from.type === "do") {
        state.edges = state.edges.filter((e) => !(e.from === fromId && e.branch === branch));
      } else {
        state.edges = state.edges.filter((e) => e.from !== fromId);
      }
      state.edges.push({ from: fromId, to: toId, branch });
      state.linkFrom = null;
      log(\`Linked → \${branch === "next" ? "next" : branch}\`, "sys");
      render();
    }

    function shapePath(type, w, h) {
      // Classic flowchart geometry (Flowgorithm-style)
      if (type === "start" || type === "end") {
        const r = h / 2;
        return \`M \${r},0 H \${w - r} A \${r},\${r} 0 0 1 \${w - r},\${h} H \${r} A \${r},\${r} 0 0 1 \${r},0 Z\`;
      }
      if (type === "input" || type === "output") {
        const skew = Math.min(22, w * 0.14);
        return \`M \${skew},0 H \${w} L \${w - skew},\${h} H 0 Z\`;
      }
      if (type === "if") {
        return \`M \${w / 2},0 L \${w},\${h / 2} L \${w / 2},\${h} L 0,\${h / 2} Z\`;
      }
      if (type === "while" || type === "for" || type === "do") {
        const r = Math.min(18, h / 2);
        return \`M \${r},0 H \${w - r} Q \${w},0 \${w},\${r} V \${h - r} Q \${w},\${h} \${w - r},\${h} H \${r} Q 0,\${h} 0,\${h - r} V \${r} Q 0,0 \${r},0 Z\`;
      }
      if (type === "breakpoint") {
        const s = Math.min(w, h);
        const cx = w / 2, cy = h / 2, r = s / 2 - 1;
        // octagon
        const pts = [];
        for (let i = 0; i < 8; i++) {
          const a = (Math.PI / 8) + i * (Math.PI / 4);
          pts.push(\`\${cx + r * Math.cos(a)},\${cy + r * Math.sin(a)}\`);
        }
        return \`M \${pts[0]} L \${pts.slice(1).join(" L ")} Z\`;
      }
      if (type === "comment") {
        return \`M 0,0 H \${w} V \${h} H 0 Z\`;
      }
      if (type === "call") {
        return \`M 0,0 H \${w} V \${h} H 0 Z\`;
      }
      // declare / assign rectangle
      return \`M 0,0 H \${w} V \${h} H 0 Z\`;
    }

    function anchorPoint(node, which) {
      const cx = node.x + node.w / 2;
      const cy = node.y + node.h / 2;
      if (which === "top") return { x: cx, y: node.y };
      if (which === "bottom") return { x: cx, y: node.y + node.h };
      if (which === "left") return { x: node.x, y: cy };
      if (which === "right") return { x: node.x + node.w, y: cy };
      return { x: cx, y: cy };
    }

    function elbowPath(x1, y1, x2, y2, branch) {
      // Orthogonal connectors like Flowgorithm
      if (branch === "true") {
        const midX = Math.min(x1, x2) - 18;
        const drop = y1 + Math.max(18, (y2 - y1) * 0.35);
        return \`M \${x1} \${y1} L \${midX} \${y1} L \${midX} \${drop} L \${x2} \${drop} L \${x2} \${y2}\`;
      }
      if (branch === "false") {
        const midX = Math.max(x1, x2) + 18;
        const drop = y1 + Math.max(18, (y2 - y1) * 0.35);
        return \`M \${x1} \${y1} L \${midX} \${y1} L \${midX} \${drop} L \${x2} \${drop} L \${x2} \${y2}\`;
      }
      const midY = y1 + Math.max(24, (y2 - y1) / 2);
      return \`M \${x1} \${y1} L \${x1} \${midY} L \${x2} \${midY} L \${x2} \${y2}\`;
    }

    const addMenu = document.getElementById("add-menu");
    const addBackdrop = document.getElementById("add-backdrop");

    function openAddMenu(ev, edge) {
      state.pendingEdge = { from: edge.from, to: edge.to, branch: edge.branch };
      addMenu.hidden = false;
      addBackdrop.hidden = false;
      addMenu.classList.add("open");
      addBackdrop.classList.add("open");
      const pad = 12;
      const menuW = Math.min(560, window.innerWidth - 24);
      const menuH = Math.min(520, window.innerHeight - 24);
      let left = ev.clientX + 8;
      let top = ev.clientY + 8;
      if (left + menuW > window.innerWidth - pad) left = window.innerWidth - menuW - pad;
      if (top + menuH > window.innerHeight - pad) top = window.innerHeight - menuH - pad;
      if (left < pad) left = pad;
      if (top < pad) top = pad;
      addMenu.style.left = left + "px";
      addMenu.style.top = top + "px";
    }

    function closeAddMenu() {
      state.pendingEdge = null;
      addMenu.classList.remove("open");
      addBackdrop.classList.remove("open");
      addMenu.hidden = true;
      addBackdrop.hidden = true;
    }

    function insertOnEdge(type) {
      const edge = state.pendingEdge;
      if (!edge) return;
      const from = findNode(edge.from);
      const to = findNode(edge.to);
      if (!from || !to) {
        closeAddMenu();
        return;
      }

      const sz = STYLE.size[type] || { w: 170, h: 52 };
      const midX = (from.x + from.w / 2 + to.x + to.w / 2) / 2 - sz.w / 2;
      const midY = (from.y + from.h + to.y) / 2 - sz.h / 2;
      const node = makeNode(type, Math.round(midX), Math.round(midY));
      state.nodes.push(node);

      // Push nodes below the insert point down a bit for readability
      const insertY = node.y;
      state.nodes.forEach((n) => {
        if (n.id !== node.id && n.y >= insertY - 8 && n.id !== from.id) {
          n.y += sz.h + 36;
        }
      });

      state.edges = state.edges.filter(
        (e) => !(e.from === edge.from && e.to === edge.to && e.branch === edge.branch)
      );
      state.edges.push({ from: edge.from, to: node.id, branch: edge.branch });

      if (type === "if" || type === "while" || type === "for" || type === "do") {
        state.edges.push({ from: node.id, to: edge.to, branch: "true" });
      } else {
        state.edges.push({ from: node.id, to: edge.to, branch: "next" });
      }

      state.selectedId = node.id;
      closeAddMenu();
      render();
      renderInspector();
      log(\`Inserted \${type} on connector.\`, "sys");
    }

    addBackdrop.addEventListener("click", closeAddMenu);
    addMenu.addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-add]");
      if (!btn || btn.disabled) return;
      insertOnEdge(btn.getAttribute("data-add"));
    });
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeAddMenu();
    });

    function render() {
      const ns = "http://www.w3.org/2000/svg";
      while (svg.firstChild) svg.removeChild(svg.firstChild);

      const root = document.createElementNS(ns, "g");
      root.setAttribute("transform", \`translate(\${state.pan.x},\${state.pan.y})\`);
      svg.appendChild(root);

      const defs = document.createElementNS(ns, "defs");
      defs.innerHTML = \`
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="\${STYLE.line}"></path>
        </marker>
        <marker id="arrow-true" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="\${STYLE.trueStroke}"></path>
        </marker>
        <marker id="arrow-false" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="\${STYLE.falseStroke}"></path>
        </marker>
        <filter id="shape-shadow" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="1" stdDeviation="1.2" flood-color="#000" flood-opacity="0.18"/>
        </filter>
      \`;
      root.appendChild(defs);

      // edges first (under shapes)
      for (const e of state.edges) {
        const a = findNode(e.from);
        const b = findNode(e.to);
        if (!a || !b) continue;

        let start;
        let end = anchorPoint(b, "top");
        let stroke = STYLE.line;
        let marker = "url(#arrow)";

        if (e.branch === "true") {
          start = anchorPoint(a, "left");
          stroke = STYLE.trueStroke;
          marker = "url(#arrow-true)";
        } else if (e.branch === "false") {
          start = anchorPoint(a, "right");
          stroke = STYLE.falseStroke;
          marker = "url(#arrow-false)";
        } else {
          start = anchorPoint(a, "bottom");
        }

        const d = elbowPath(start.x, start.y, end.x, end.y, e.branch);

        const path = document.createElementNS(ns, "path");
        path.setAttribute("d", d);
        path.setAttribute("fill", "none");
        path.setAttribute("stroke", stroke);
        path.setAttribute("stroke-width", "2");
        path.setAttribute("stroke-linejoin", "round");
        path.setAttribute("marker-end", marker);
        path.style.pointerEvents = "none";

        // Invisible wide hit target — click arrow to add a shape (Flowgorithm)
        const hit = document.createElementNS(ns, "path");
        hit.setAttribute("d", d);
        hit.setAttribute("fill", "none");
        hit.setAttribute("stroke", "transparent");
        hit.setAttribute("stroke-width", "18");
        hit.style.cursor = "pointer";
        hit.addEventListener("pointerdown", (ev) => {
          ev.stopPropagation();
          openAddMenu(ev, e);
        });
        hit.addEventListener("mouseenter", () => path.setAttribute("stroke-width", "3.2"));
        hit.addEventListener("mouseleave", () => path.setAttribute("stroke-width", "2"));
        root.appendChild(hit);
        root.appendChild(path);

        if (e.branch === "true" || e.branch === "false") {
          const label = document.createElementNS(ns, "text");
          const lx = e.branch === "true" ? start.x - 28 : start.x + 10;
          const ly = start.y - 6;
          label.setAttribute("x", lx);
          label.setAttribute("y", ly);
          label.setAttribute("fill", stroke);
          label.setAttribute("font-size", "12");
          label.setAttribute("font-weight", "700");
          label.setAttribute("font-family", "Figtree, sans-serif");
          label.textContent = e.branch === "true" ? "True" : "False";
          root.appendChild(label);
        }
      }

      for (const n of state.nodes) {
        const g = document.createElementNS(ns, "g");
        g.setAttribute("transform", \`translate(\${n.x},\${n.y})\`);
        g.style.cursor = "pointer";
        g.dataset.id = n.id;

        const path = document.createElementNS(ns, "path");
        path.setAttribute("d", shapePath(n.type, n.w, n.h));
        path.setAttribute("fill", STYLE.fill[n.type] || "#fff");
        path.setAttribute("stroke", n.id === state.highlightId
          ? STYLE.exec
          : n.id === state.linkFrom
            ? STYLE.link
            : n.id === state.selectedId
              ? STYLE.selected
              : STYLE.stroke);
        path.setAttribute("stroke-width", n.id === state.selectedId || n.id === state.highlightId || n.id === state.linkFrom ? "2.6" : "1.7");
        path.setAttribute("filter", "url(#shape-shadow)");
        if (n.type === "comment") path.setAttribute("stroke-dasharray", "5 4");
        if (n.type === "declare" || n.type === "call") {
          // double side bars like Flowgorithm declare/call
          const bar = document.createElementNS(ns, "path");
          if (n.type === "declare") {
            bar.setAttribute("d", \`M 6,0 V \${n.h} M 10,0 V \${n.h}\`);
          } else {
            bar.setAttribute("d", \`M 6,0 V \${n.h} M \${n.w - 6},0 V \${n.h}\`);
          }
          bar.setAttribute("fill", "none");
          bar.setAttribute("stroke", STYLE.stroke);
          bar.setAttribute("stroke-width", "1.5");
          g.appendChild(path);
          g.appendChild(bar);
        } else {
          g.appendChild(path);
        }

        // multiline-ish label
        const text = document.createElementNS(ns, "text");
        text.setAttribute("x", n.w / 2);
        text.setAttribute("y", n.h / 2 + 4);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("fill", STYLE.text);
        text.setAttribute("font-size", n.type === "if" || n.type === "while" || n.type === "for" || n.type === "do" ? "12" : "13");
        text.setAttribute("font-weight", "700");
        text.setAttribute("font-family", "Figtree, sans-serif");
        const label = nodeLabel(n);
        text.textContent = label.length > 24 ? label.slice(0, 23) + "…" : label;
        if (n.type === "breakpoint") {
          text.setAttribute("fill", "#ffffff");
          text.textContent = "BP";
        }
        g.appendChild(text);

        g.addEventListener("pointerdown", onNodePointerDown);
        g.addEventListener("dblclick", () => {
          state.selectedId = n.id;
          renderInspector();
          render();
        });
        root.appendChild(g);
      }
    }

    function onNodePointerDown(ev) {
      ev.stopPropagation();
      const id = ev.currentTarget.dataset.id;
      if (ev.shiftKey || state.linkFrom) {
        if (!state.linkFrom) {
          state.linkFrom = id;
          state.selectedId = id;
          log("Click another shape to link. For If/While/For: left = True, right = False.", "sys");
        } else {
          connect(state.linkFrom, id);
        }
        render();
        renderInspector();
        return;
      }
      state.selectedId = id;
      state.draggingNode = { id, ox: ev.clientX, oy: ev.clientY, nx: findNode(id).x, ny: findNode(id).y };
      svg.setPointerCapture(ev.pointerId);
      render();
      renderInspector();
    }

    svg.addEventListener("pointerdown", (ev) => {
      if (ev.target === svg) {
        state.selectedId = null;
        state.panning = true;
        state.panStart = { x: ev.clientX, y: ev.clientY, px: state.pan.x, py: state.pan.y };
        svg.classList.add("dragging");
        renderInspector();
        render();
      }
    });

    svg.addEventListener("pointermove", (ev) => {
      if (state.draggingNode) {
        const n = findNode(state.draggingNode.id);
        if (!n) return;
        n.x = state.draggingNode.nx + (ev.clientX - state.draggingNode.ox);
        n.y = state.draggingNode.ny + (ev.clientY - state.draggingNode.oy);
        render();
      } else if (state.panning && state.panStart) {
        state.pan.x = state.panStart.px + (ev.clientX - state.panStart.x);
        state.pan.y = state.panStart.py + (ev.clientY - state.panStart.y);
        render();
      }
    });

    svg.addEventListener("pointerup", () => {
      state.draggingNode = null;
      state.panning = false;
      state.panStart = null;
      svg.classList.remove("dragging");
    });

    function renderInspector() {
      const n = findNode(state.selectedId);
      if (!n) {
        inspector.innerHTML = '<p class="empty-state">Select a shape to edit its properties.</p>';
        return;
      }
      const p = n.props;
      let fields = \`<div style="margin-bottom:0.35rem;color:var(--muted);font-size:0.8rem">\${n.type.toUpperCase()}</div>\`;
      if (n.type === "declare") {
        fields += field("name", "Name", p.name);
        fields += select("typeName", "Type", p.typeName, ["Integer", "Real", "String", "Boolean"]);
        fields += check("isArray", "Array", p.isArray);
        fields += field("size", "Size", p.size || "");
      } else if (n.type === "input") {
        fields += field("variable", "Variable", p.variable);
      } else if (n.type === "output") {
        fields += field("expression", "Expression", p.expression);
      } else if (n.type === "assign") {
        fields += field("variable", "Variable", p.variable);
        fields += field("expression", "Expression", p.expression);
      } else if (n.type === "if" || n.type === "while" || n.type === "do") {
        fields += field("condition", "Condition", p.condition);
      } else if (n.type === "for") {
        fields += field("variable", "Variable", p.variable);
        fields += field("start", "Start", p.start);
        fields += field("end", "End", p.end);
        fields += field("step", "Step", p.step);
      } else if (n.type === "comment") {
        fields += field("text", "Text", p.text || "");
      } else if (n.type === "breakpoint") {
        fields += '<p class="empty-state">Pauses Run until you Step/Run again.</p>';
      } else if (n.type === "call") {
        const names = state.functions.map((f) => f.name).filter((n) => n !== "Main");
        if (!names.length) names.push("Double");
        fields += select("name", "Function", p.name || names[0], names);
        fields += field("args", "Arguments", p.args || "");
        fields += field("result", "Store result in", p.result || "");
      } else if (n.type === "end") {
        const fn = getFn(state.activeFn);
        if (fn && fn.returnType !== "None") {
          fields += field("expression", "Return expression", p.expression || "");
        } else {
          fields += '<p class="empty-state">End of function.</p>';
        }
      } else if (n.type === "start") {
        fields += '<p class="empty-state">Function entry. Edit details in Functions panel.</p>';
      } else {
        fields += '<p class="empty-state">No editable properties.</p>';
      }
      fields += '<p class="hint" style="margin-top:0.75rem">Tip: click a connector to insert shapes.</p>';
      inspector.innerHTML = fields;
      inspector.querySelectorAll("[data-prop]").forEach((el) => {
        el.addEventListener("change", () => {
          const key = el.dataset.prop;
          n.props[key] = el.type === "checkbox" ? el.checked : el.value;
          render();
        });
        el.addEventListener("input", () => {
          if (el.type === "checkbox") return;
          n.props[el.dataset.prop] = el.value;
          render();
        });
      });
    }

    function field(key, label, value) {
      return \`<label>\${label}<input data-prop="\${key}" value="\${escapeAttr(value)}" /></label>\`;
    }
    function select(key, label, value, options) {
      return \`<label>\${label}<select data-prop="\${key}">\${options.map((o) => \`<option \${o === value ? "selected" : ""}>\${o}</option>\`).join("")}</select></label>\`;
    }
    function check(key, label, value) {
      return \`<label style="display:flex;gap:0.45rem;align-items:center;margin-top:0.7rem"><input type="checkbox" data-prop="\${key}" \${value ? "checked" : ""} /> \${label}</label>\`;
    }
    function escapeAttr(s) {
      return String(s ?? "").replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
    }

    function showVars() {
      const keys = Object.keys(state.vars);
      if (!keys.length) {
        varsEl.textContent = "(none)";
        return;
      }
      varsEl.textContent = keys.map((k) => {
        const v = state.vars[k];
        return Array.isArray(v) ? \`\${k} = [\${v.join(", ")}]\` : \`\${k} = \${JSON.stringify(v)}\`;
      }).join("\\n");
    }

    // ---- expression evaluator (safe-ish subset) ----
    const TYPE_ALIASES = {
      integer: "Integer", int: "Integer", long: "Integer",
      real: "Real", float: "Real", double: "Real", number: "Real",
      string: "String", str: "String", text: "String",
      boolean: "Boolean", bool: "Boolean",
    };
    function normalizeType(t) {
      const raw = String(t || "").trim();
      if (!raw) return "Integer";
      if (["Integer", "Real", "String", "Boolean"].includes(raw)) return raw;
      return TYPE_ALIASES[raw.toLowerCase()] || raw;
    }
    function isTypeKeyword(name) {
      return Object.prototype.hasOwnProperty.call(TYPE_ALIASES, String(name || "").toLowerCase());
    }
    function parseTypedName(name, fallbackType) {
      const bits = String(name || "").trim().split(/\\s+/).filter(Boolean);
      if (bits.length >= 2 && isTypeKeyword(bits[0])) {
        return { typeName: normalizeType(bits[0]), name: bits.slice(1).join("_") };
      }
      // "hours: Real" / "minutes:Integer" style labels
      const colon = String(name || "").trim().match(/^([A-Za-z_][A-Za-z0-9_]*)\\s*:\\s*([A-Za-z_]+)$/);
      if (colon && isTypeKeyword(colon[2])) {
        return { typeName: normalizeType(colon[2]), name: colon[1] };
      }
      return { typeName: normalizeType(fallbackType || "Integer"), name: bits[0] || "x" };
    }
    function callBuiltin(name, args) {
      const n = String(name || "");
      const key = n.toLowerCase();
      const a0 = args[0];
      if (["tointeger", "integer", "int"].includes(key)) return parseInt(a0, 10);
      if (["toreal", "real", "float", "double"].includes(key)) return parseFloat(a0);
      if (["tostring", "string", "str"].includes(key)) return String(a0);
      if (["toboolean", "boolean", "bool"].includes(key)) {
        if (typeof a0 === "boolean") return a0;
        const s = String(a0).toLowerCase();
        if (s === "true" || s === "1") return true;
        if (s === "false" || s === "0") return false;
        return Boolean(a0);
      }
      if (key === "abs") return Math.abs(Number(a0));
      if (key === "sqrt") return Math.sqrt(Number(a0));
      if (key === "floor") return Math.floor(Number(a0));
      if (key === "ceiling" || key === "ceil") return Math.ceil(Number(a0));
      if (key === "round") return Math.round(Number(a0));
      if (key === "length" || key === "size") {
        if (Array.isArray(a0) || typeof a0 === "string") return a0.length;
        return String(a0).length;
      }
      if (key === "random") {
        if (args.length >= 2) {
          const lo = Number(args[0]), hi = Number(args[1]);
          return lo + Math.floor(Math.random() * (hi - lo + 1));
        }
        return Math.random();
      }
      throw new Error("Unknown function: " + n);
    }

    function tokenize(expr) {
      const tokens = [];
      let i = 0;
      const s = String(expr);
      while (i < s.length) {
        const c = s[i];
        if (/\\s/.test(c)) { i++; continue; }
        if ('"+\\''.includes(c)) {
          const q = c;
          let j = i + 1, out = "";
          while (j < s.length && s[j] !== q) {
            if (s[j] === "\\\\") { out += s[j + 1]; j += 2; }
            else { out += s[j++]; }
          }
          tokens.push({ t: "str", v: out });
          i = j + 1;
          continue;
        }
        if (/[0-9.]/.test(c)) {
          let j = i;
          while (j < s.length && /[0-9.]/.test(s[j])) j++;
          tokens.push({ t: "num", v: Number(s.slice(i, j)) });
          i = j;
          continue;
        }
        if (/[A-Za-z_]/.test(c)) {
          let j = i;
          while (j < s.length && /[A-Za-z0-9_]/.test(s[j])) j++;
          const name = s.slice(i, j);
          if (name === "true" || name === "false") tokens.push({ t: "bool", v: name === "true" });
          else tokens.push({ t: "id", v: name });
          i = j;
          continue;
        }
        const two = s.slice(i, i + 2);
        if (["==", "!=", "<=", ">=", "&&", "||"].includes(two)) {
          tokens.push({ t: "op", v: two });
          i += 2;
          continue;
        }
        if ("+-*/%<>=!()[],".includes(c)) {
          tokens.push({ t: "op", v: c });
          i++;
          continue;
        }
        throw new Error("Unexpected character: " + c);
      }
      return tokens;
    }

    function evalExpr(expr, env) {
      const tokens = tokenize(expr);
      let pos = 0;
      function peek() { return tokens[pos]; }
      function take() { return tokens[pos++]; }
      function parsePrimary() {
        const tok = take();
        if (!tok) throw new Error("Unexpected end of expression");
        if (tok.t === "num" || tok.t === "str" || tok.t === "bool") return tok.v;
        if (tok.t === "id") {
          // Function call: ToReal(x), Integer(x), Real(x), Length(s), ...
          if (peek() && peek().v === "(") {
            take();
            const args = [];
            if (peek() && peek().v !== ")") {
              args.push(parseExpr());
              while (peek() && peek().v === ",") {
                take();
                args.push(parseExpr());
              }
            }
            if (!peek() || peek().v !== ")") throw new Error("Expected )");
            take();
            return callBuiltin(tok.v, args);
          }
          // Bare cast: Real Minutes / 60  →  ToReal(Minutes) / 60
          if (isTypeKeyword(tok.v) && peek() && (peek().t === "id" || peek().t === "num" || peek().t === "str" || peek().t === "bool" || peek().v === "(" || peek().v === "-")) {
            return callBuiltin(tok.v, [parsePrimary()]);
          }
          if (!(tok.v in env)) {
            if (isTypeKeyword(tok.v)) {
              throw new Error(
                "Type name '" + tok.v + "' is not a variable. Declare a name (e.g. minutes) and set Type to " +
                normalizeType(tok.v) + ", or convert with " + normalizeType(tok.v) + "(value)."
              );
            }
            throw new Error("Unknown variable: " + tok.v);
          }
          let val = env[tok.v];
          if (peek() && peek().v === "[") {
            take();
            const idx = parseExpr();
            if (!peek() || peek().v !== "]") throw new Error("Expected ]");
            take();
            return val[idx];
          }
          return val;
        }
        if (tok.v === "(") {
          const v = parseExpr();
          if (!peek() || peek().v !== ")") throw new Error("Expected )");
          take();
          return v;
        }
        if (tok.v === "-") return -parsePrimary();
        if (tok.v === "!") return !parsePrimary();
        throw new Error("Unexpected token: " + tok.v);
      }
      function parseMul() {
        let left = parsePrimary();
        while (peek() && "*/%".includes(peek().v)) {
          const op = take().v;
          const right = parsePrimary();
          if (op === "*") left *= right;
          else if (op === "/") left /= right;
          else left %= right;
        }
        return left;
      }
      function parseAdd() {
        let left = parseMul();
        while (peek() && (peek().v === "+" || peek().v === "-")) {
          const op = take().v;
          const right = parseMul();
          left = op === "+" ? left + right : left - right;
        }
        return left;
      }
      function parseCmp() {
        let left = parseAdd();
        while (peek() && ["<", ">", "<=", ">=", "==", "!="].includes(peek().v)) {
          const op = take().v;
          const right = parseAdd();
          if (op === "<") left = left < right;
          else if (op === ">") left = left > right;
          else if (op === "<=") left = left <= right;
          else if (op === ">=") left = left >= right;
          else if (op === "==") left = left == right;
          else left = left != right;
        }
        return left;
      }
      function parseAnd() {
        let left = parseCmp();
        while (peek() && peek().v === "&&") {
          take();
          left = left && parseCmp();
        }
        return left;
      }
      function parseExpr() {
        let left = parseAnd();
        while (peek() && peek().v === "||") {
          take();
          left = left || parseAnd();
        }
        return left;
      }
      const value = parseExpr();
      if (pos < tokens.length) throw new Error("Unexpected trailing tokens");
      return value;
    }

    function coerce(typeName, raw) {
      const t = normalizeType(typeName);
      if (t === "Integer") return parseInt(raw, 10);
      if (t === "Real") return parseFloat(raw);
      if (t === "Boolean") {
        const s = String(raw).toLowerCase();
        if (s === "true" || s === "1") return true;
        if (s === "false" || s === "0") return false;
        throw new Error("Expected Boolean");
      }
      return String(raw);
    }

    function nextEdge(nodeId, branch = "next") {
      return state.edges.find((e) => e.from === nodeId && e.branch === branch)
        || (branch === "next" ? state.edges.find((e) => e.from === nodeId) : null);
    }

    function sleep(ms) {
      return new Promise((r) => setTimeout(r, ms));
    }

    async function waitStep() {
      if (!state.stepMode) {
        await sleep(220);
        return;
      }
      return new Promise((resolve) => { state.stepResolve = resolve; });
    }

    function askInput(promptText) {
      return new Promise((resolve) => {
        state.waitingInput = resolve;
        stdin.disabled = false;
        btnSubmit.disabled = false;
        stdin.value = "";
        stdin.focus();
        log(promptText, "sys");
      });
    }

    function submitInput() {
      if (!state.waitingInput) return;
      const v = stdin.value;
      log("> " + v, "out");
      const resolve = state.waitingInput;
      state.waitingInput = null;
      stdin.disabled = true;
      btnSubmit.disabled = true;
      resolve(v);
    }

    async function runProgram(stepMode = false) {
      if (state.running) return;
      flushActive();
      const main = getFn("Main");
      if (!main || !main.nodes.some((n) => n.type === "start")) {
        log("Main function needs a Start shape.", "err");
        return;
      }

      const viewFn = state.activeFn;
      state.running = true;
      state.stepMode = stepMode;
      btnRun.disabled = true;
      btnStop.disabled = false;
      log("— Run started —", "sys");

      const chartStack = [];

      function enterFnChart(fnDef) {
        chartStack.push({
          nodes: state.nodes,
          edges: state.edges,
          activeFn: state.activeFn,
          pan: { x: state.pan.x, y: state.pan.y },
        });
        state.nodes = fnDef.nodes;
        state.edges = fnDef.edges;
        state.activeFn = fnDef.name;
        state.pan = fnDef.pan ? { x: fnDef.pan.x, y: fnDef.pan.y } : state.pan;
        renderFnUi();
      }

      function leaveFnChart() {
        const prev = chartStack.pop();
        if (!prev) return;
        state.nodes = prev.nodes;
        state.edges = prev.edges;
        state.activeFn = prev.activeFn;
        state.pan = prev.pan;
        renderFnUi();
      }

      async function executeFn(fnName, argText, callerVars) {
        const fnDef = getFn(fnName);
        if (!fnDef) throw new Error("Unknown function: " + fnName);

        const argExprs = parseArgList(argText);
        if (argExprs.length !== fnDef.parameters.length) {
          throw new Error(
            fnName + " expects " + fnDef.parameters.length + " argument(s), got " + argExprs.length
          );
        }
        const argVals = argExprs.map((ex) => evalExpr(ex, callerVars));

        const localVars = Object.create(null);
        const declared = Object.create(null);
        fnDef.parameters.forEach((p, i) => {
          declared[p.name] = p.typeName;
          localVars[p.name] = argVals[i];
        });

        enterFnChart(fnDef);
        const prevVars = state.vars;
        state.vars = localVars;
        showVars();

        let current = fnDef.nodes.find((n) => n.type === "start");
        const loopStack = [];
        let steps = 0;
        let returnValue;

        try {
          while (current && state.running) {
            if (++steps > 10000) throw new Error("Too many steps (possible infinite loop)");
            state.highlightId = current.id;
            render();
            await waitStep();
            if (!state.running) break;

            const n = current;
            let branch = "next";

            if (n.type === "start") {
              // fall through
            } else if (n.type === "end") {
              if (fnDef.returnType !== "None") {
                returnValue = n.props.expression
                  ? evalExpr(n.props.expression, state.vars)
                  : 0;
              }
              break;
            } else if (n.type === "declare") {
              const parsed = parseTypedName(n.props.name, n.props.typeName);
              const name = parsed.name;
              const typeName = parsed.typeName;
              const isArray = n.props.isArray;
              const size = n.props.size;
              declared[name] = typeName;
              if (isArray) {
                const len = Number(evalExpr(size || "0", state.vars));
                state.vars[name] = Array.from({ length: len }, () =>
                  typeName === "String" ? "" : typeName === "Boolean" ? false : 0
                );
              } else {
                state.vars[name] = typeName === "String" ? "" : typeName === "Boolean" ? false : 0;
              }
            } else if (n.type === "assign") {
              let variable = String(n.props.variable || "").trim();
              let expression = String(n.props.expression || "").trim();
              // Whole assignment pasted into Variable: "hours = minutes / 60"
              if ((!expression || expression === "=") && variable.includes("=")) {
                const split = variable.match(/^([^=]+?)=(.*)$/);
                if (split) {
                  variable = split[1].trim();
                  expression = split[2].trim();
                }
              }
              // Allow "hours = minutes / 60" pasted into Expression.
              const assignMatch = expression.match(
                /^([A-Za-z_][A-Za-z0-9_]*(?:\\s+[A-Za-z_][A-Za-z0-9_]*)?)\\s*=\\s*(.+)$/
              );
              if (
                assignMatch &&
                !expression.includes("==") &&
                !expression.includes("!=") &&
                !expression.includes("<=") &&
                !expression.includes(">=")
              ) {
                if (!variable || variable === "x") variable = assignMatch[1].trim();
                expression = assignMatch[2].trim();
              }
              // Leading equals leftover: "= minutes / 60"
              if (expression.startsWith("=")) expression = expression.replace(/^=+\\s*/, "");
              // Allow "Real hours" / "string name" / "INT minutes" in Variable field.
              const typed = parseTypedName(variable, declared[variable] || "Integer");
              variable = typed.name;
              if (!(variable in declared)) declared[variable] = typed.typeName;
              state.vars[variable] = coerce(declared[variable], evalExpr(expression, state.vars));
            } else if (n.type === "output") {
              const val = evalExpr(n.props.expression, state.vars);
              log(String(val), "out");
            } else if (n.type === "input") {
              let variable = String(n.props.variable || "").trim();
              const typed = parseTypedName(variable, declared[variable] || "String");
              variable = typed.name;
              const raw = await askInput("Enter " + variable + ":");
              if (!state.running) break;
              const t = declared[variable] || typed.typeName || "String";
              declared[variable] = normalizeType(t);
              state.vars[variable] = coerce(t, raw);
            } else if (n.type === "comment") {
              // skip
            } else if (n.type === "breakpoint") {
              log("Breakpoint hit — click Step or Run to continue.", "sys");
              state.stepMode = true;
              await waitStep();
              if (!state.running) break;
            } else if (n.type === "call") {
              const ret = await executeFn(n.props.name, n.props.args || "", state.vars);
              if (n.props.result) {
                state.vars[n.props.result] = ret;
                declared[n.props.result] = declared[n.props.result] || "Integer";
              }
            } else if (n.type === "if") {
              branch = evalExpr(n.props.condition, state.vars) ? "true" : "false";
            } else if (n.type === "while" || n.type === "do") {
              const ok = !!evalExpr(n.props.condition, state.vars);
              if (ok) {
                loopStack.push({ type: n.type, nodeId: n.id });
                branch = "true";
              } else {
                branch = "false";
              }
            } else if (n.type === "for") {
              const { variable, start: st, end, step } = n.props;
              if (!n._forInit) {
                state.vars[variable] = evalExpr(st, state.vars);
                n._forInit = true;
              }
              const i = state.vars[variable];
              const endV = evalExpr(end, state.vars);
              const stepV = evalExpr(step || "1", state.vars);
              const cont = stepV >= 0 ? i <= endV : i >= endV;
              if (cont) {
                loopStack.push({ type: "for", nodeId: n.id, stepV });
                branch = "true";
              } else {
                n._forInit = false;
                branch = "false";
              }
            }

            showVars();

            if (n.type !== "while" && n.type !== "do" && n.type !== "for" && n.type !== "if") {
              const edge = nextEdge(n.id, "next");
              if (!edge && loopStack.length) {
                const frame = loopStack.pop();
                const header = findNode(frame.nodeId);
                if (frame.type === "for") {
                  state.vars[header.props.variable] =
                    Number(state.vars[header.props.variable]) + Number(frame.stepV);
                }
                current = header;
                continue;
              }
              current = edge ? findNode(edge.to) : null;
            } else if (n.type === "if") {
              const edge = nextEdge(n.id, branch);
              current = edge ? findNode(edge.to) : null;
            } else {
              const edge = nextEdge(n.id, branch);
              current = edge ? findNode(edge.to) : null;
              if (branch === "true" && !current) throw new Error(n.type + " has no true/body branch");
            }
          }
        } finally {
          fnDef.nodes.forEach((n) => { delete n._forInit; });
          state.vars = prevVars;
          leaveFnChart();
          showVars();
        }

        return returnValue;
      }

      try {
        state.vars = Object.create(null);
        await executeFn("Main", "", state.vars);
        log("— Run finished —", "sys");
      } catch (err) {
        log("Error: " + err.message, "err");
      } finally {
        state.running = false;
        state.highlightId = null;
        state.stepResolve = null;
        state.waitingInput = null;
        stdin.disabled = true;
        btnSubmit.disabled = true;
        btnRun.disabled = false;
        btnStop.disabled = true;
        state.activeFn = viewFn;
        loadActive();
        renderFnUi();
        render();
        showVars();
      }
    }

    function stopProgram() {
      state.running = false;
      if (state.stepResolve) state.stepResolve();
      if (state.waitingInput) {
        state.waitingInput("");
        state.waitingInput = null;
      }
      log("— Stopped —", "sys");
    }

    function newProgram() {
      state.functions = [blankFunction("Main")];
      state.activeFn = "Main";
      loadActive();
      renderFnUi();
      render();
      renderInspector();
      log("New program.", "sys");
    }

    function loadExample() {
      // Main: input n, call Double(n) -> r, output r
      state.idSeq = 1;
      const mainStart = makeNode("start", 260, 24);
      const dN = makeNode("declare", 250, 100, { name: "n", typeName: "Integer", isArray: false, size: "" });
      const dR = makeNode("declare", 250, 180, { name: "r", typeName: "Integer", isArray: false, size: "" });
      const inp = makeNode("input", 250, 260, { variable: "n" });
      const call = makeNode("call", 250, 340, { name: "Double", args: "n", result: "r" });
      const out = makeNode("output", 250, 420, { expression: "r" });
      const mainEnd = makeNode("end", 260, 500, { expression: "" });
      const main = {
        name: "Main",
        returnType: "None",
        parameters: [],
        nodes: [mainStart, dN, dR, inp, call, out, mainEnd],
        edges: [
          { from: mainStart.id, to: dN.id, branch: "next" },
          { from: dN.id, to: dR.id, branch: "next" },
          { from: dR.id, to: inp.id, branch: "next" },
          { from: inp.id, to: call.id, branch: "next" },
          { from: call.id, to: out.id, branch: "next" },
          { from: out.id, to: mainEnd.id, branch: "next" },
        ],
        idSeq: state.idSeq,
        pan: { x: 40, y: 16 },
      };

      state.idSeq = 1;
      const dStart = makeNode("start", 260, 24);
      const dEnd = makeNode("end", 250, 160, { expression: "x * 2" });
      const dbl = {
        name: "Double",
        returnType: "Integer",
        parameters: [{ name: "x", typeName: "Integer" }],
        nodes: [dStart, dEnd],
        edges: [{ from: dStart.id, to: dEnd.id, branch: "next" }],
        idSeq: state.idSeq,
        pan: { x: 80, y: 28 },
      };

      state.functions = [main, dbl];
      state.activeFn = "Main";
      loadActive();
      renderFnUi();
      render();
      renderInspector();
      log("Loaded function example: Main calls Double(n).", "sys");
    }

    function saveProgram() {
      flushActive();
      const data = {
        format: "flowgorithm-web",
        version: 2,
        activeFn: state.activeFn,
        functions: state.functions.map((f) => ({
          name: f.name,
          returnType: f.returnType,
          parameters: f.parameters,
          nodes: f.nodes.map(({ id, type, x, y, w, h, props }) => ({ id, type, x, y, w, h, props })),
          edges: f.edges,
          idSeq: f.idSeq,
          pan: f.pan,
        })),
      };
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "program.flow.json";
      a.click();
      URL.revokeObjectURL(a.href);
    }

    function openProgram(file) {
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const text = String(reader.result);
          if (text.trim().startsWith("<")) {
            importFprg(text);
          } else {
            const data = JSON.parse(text);
            if (data.functions && Array.isArray(data.functions)) {
              state.functions = data.functions;
              state.activeFn = data.activeFn || "Main";
            } else {
              // legacy single-chart files
              state.functions = [{
                name: "Main",
                returnType: "None",
                parameters: [],
                nodes: data.nodes || [],
                edges: data.edges || [],
                idSeq: data.idSeq || 1,
                pan: { x: 40, y: 16 },
              }];
              state.activeFn = "Main";
            }
            loadActive();
            renderFnUi();
            render();
            renderInspector();
            log("Opened " + file.name, "sys");
          }
        } catch (err) {
          log("Open failed: " + err.message, "err");
        }
      };
      reader.readAsText(file);
    }

    function importFprg(xmlText) {
      const doc = new DOMParser().parseFromString(xmlText, "application/xml");
      const fn = doc.querySelector("function[name='Main'], function");
      if (!fn) throw new Error("No Main function in .fprg");
      const body = [...fn.querySelector("body").children];
      state.nodes = [];
      state.edges = [];
      state.idSeq = 1;
      const start = makeNode("start", 260, 24);
      state.nodes.push(start);
      let y = 100;
      let prev = start;
      const link = (from, to, branch = "next") => state.edges.push({ from: from.id, to: to.id, branch });

      function addFromEl(el) {
        const tag = el.tagName.toLowerCase();
        let node = null;
        if (tag === "declare") {
          node = makeNode("declare", 250, y, {
            name: el.getAttribute("name") || "x",
            typeName: normalizeType(el.getAttribute("type") || el.getAttribute("Type") || "Integer"),
            isArray: (el.getAttribute("array") || "False").toLowerCase() === "true",
            size: el.getAttribute("size") || "",
          });
          // If name was written as "Real minutes", split it.
          const parsed = parseTypedName(node.props.name, node.props.typeName);
          node.props.name = parsed.name;
          node.props.typeName = parsed.typeName;
        } else if (tag === "input") {
          node = makeNode("input", 250, y, { variable: el.getAttribute("variable") || "x" });
        } else if (tag === "output") {
          node = makeNode("output", 250, y, { expression: el.getAttribute("expression") || '""' });
        } else if (tag === "assign") {
          node = makeNode("assign", 250, y, {
            variable: el.getAttribute("variable") || "x",
            expression: el.getAttribute("expression") || "0",
          });
        } else if (tag === "if") {
          node = makeNode("if", 245, y, {
            condition: el.getAttribute("expression") || el.getAttribute("condition") || "true",
          });
        } else if (tag === "while") {
          node = makeNode("while", 245, y, {
            condition: el.getAttribute("expression") || el.getAttribute("condition") || "true",
          });
        } else if (tag === "for") {
          node = makeNode("for", 240, y, {
            variable: el.getAttribute("variable") || "i",
            start: el.getAttribute("start") || "1",
            end: el.getAttribute("end") || "10",
            step: el.getAttribute("step") || "1",
          });
        }
        if (node) {
          state.nodes.push(node);
          link(prev, node);
          prev = node;
          y += 90;
        }
      }

      body.forEach(addFromEl);
      const end = makeNode("end", 260, y, { expression: "" });
      state.nodes.push(end);
      link(prev, end);
      state.functions = [{
        name: "Main",
        returnType: "None",
        parameters: [],
        nodes: state.nodes,
        edges: state.edges,
        idSeq: state.idSeq,
        pan: { x: 40, y: 16 },
      }];
      state.activeFn = "Main";
      renderFnUi();
      render();
      renderInspector();
      log("Imported .fprg (linear Main body).", "sys");
    }

    fnSelect.addEventListener("change", () => switchFunction(fnSelect.value));
    document.getElementById("btn-fn-add").addEventListener("click", addFunction);
    document.getElementById("btn-fn-del").addEventListener("click", deleteFunction);

    // palette removed — insert shapes by clicking connector arrows (+)

    btnRun.addEventListener("click", () => runProgram(false));
    btnStep.addEventListener("click", () => {
      if (state.running && state.stepResolve) state.stepResolve();
      else runProgram(true);
    });
    btnStop.addEventListener("click", stopProgram);
    document.getElementById("btn-new").addEventListener("click", newProgram);
    document.getElementById("btn-example").addEventListener("click", loadExample);
    document.getElementById("btn-save").addEventListener("click", saveProgram);
    document.getElementById("btn-delete").addEventListener("click", deleteSelected);
    document.getElementById("btn-clear-console").addEventListener("click", () => { consoleEl.textContent = ""; });
    document.getElementById("file-open").addEventListener("change", (e) => {
      const f = e.target.files && e.target.files[0];
      if (f) openProgram(f);
      e.target.value = "";
    });
    btnSubmit.addEventListener("click", submitInput);
    stdin.addEventListener("keydown", (e) => { if (e.key === "Enter") submitInput(); });
    window.addEventListener("keydown", (e) => {
      if ((e.key === "Delete" || e.key === "Backspace") && !/input|textarea|select/i.test(e.target.tagName)) {
        deleteSelected();
      }
    });

    loadExample();
    log("Flowgorithm web ready. Run the even/odd example or build your own.", "sys");
  })();
  </script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(HTML);
    return;
  }

  if (req.method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, app: "flowgorithm" }));
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`Flowgorithm running at http://localhost:${PORT}`);
});

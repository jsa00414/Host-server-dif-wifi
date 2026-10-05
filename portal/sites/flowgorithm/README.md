# Flowgorithm

Educational flowchart programming in the browser — a web take on [Flowgorithm](http://www.flowgorithm.org/), served from a single Node.js file.

## Run

```bash
node server.js
```

Then open [http://localhost:3000](http://localhost:3000).

## Features

- Flowchart shapes: Start, End, Declare, Input, Output, Assign, If, While, For
- Drag shapes, pan the canvas, Shift-click to connect (True/False branches for decisions)
- Run / Step / Stop with a console for input & output
- Variable inspector
- Save/open JSON programs; basic `.fprg` Main-body import
- Example: even/odd checker

No npm dependencies — only Node’s built-in `http` module.

You need Node.js and Python 3.

You can convert PHP into a JSON AST by doing
```sh
cd slice-to-ast/
npm install
npm run parser -- path/to/php/code >where/you/want/to/save/it
```

There's a script that converts text files in `proj-slices/` to JSON.

Then run `analyzer.py` in the project root directory. Example:
```sh
./analyzer.py proj-slices/xss_01.json
```

Currently it only spits out a GraphViz file, for visualization.
```sh
./analyzer.py proj-slices/xss_01.json | dot -Tpng -o xss_01.png
```

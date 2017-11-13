You need Node.js and Python 3.

You can convert PHP into a JSON AST by doing
```sh
cd slice-to-ast/
npm install
npm run parser -- path/to/php/code >where/you/want/to/save/it
```

Then run `analyzer.py` in the project root directory. Example:
```sh
./analyzer.py slices/sqli_01.json
```

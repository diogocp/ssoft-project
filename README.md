You need Node.js and Python 3.

You can convert PHP into a JSON AST by doing
```sh
cd slice-to-ast/
npm install
npm run parser -- ../slices/slice1.php > ../slices/slice1.json
```

Then run `analyzer.py` in the project root directory. Example:
```sh
./analyzer.py slices/slice1.json
```

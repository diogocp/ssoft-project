Discovering vulnerabilities in PHP web applications
===================================================

The aim of this project is to study how vulnerabilities in PHP code can be
detected statically by means of taint and input validation analysis.


Running the analysis tool
-------------------------
Run `analyzer.py` in the project root directory. The name of the file to
analyze may be passed in as an argument. If no argument is specified, the
program will read from stdin.

 Example:
```sh
./analyzer.py slices/slice1.json
```

To run the tests:
```sh
./run_tests
```


Parsing PHP code
----------------
If you have Node.js installed, you can convert PHP into a JSON AST by doing
```sh
cd php-parser
npm install
npm run parser -- slice.php
```
This will create a file `slice.json` with the AST.

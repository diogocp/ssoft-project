First generate the parser:
```sh
cd grammar/
./gradlew generateGrammarSource
```

Then run `analyzer.py` in the project root directory. Example:
```sh
./analyzer.py proj-slices/xss_01.txt
```

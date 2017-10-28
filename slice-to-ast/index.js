// initialize the php parser factory class
var fs = require('fs');
var replaceExt = require('replace-ext');
var path = require('path');
var process = require('process');
var engine = require('php-parser');

// initialize a new parser instance
var parser = new engine({
  // some options :
  parser: {
    extractDoc: false,
    suppressErrors: false,
    debug: false
  }
});

if (process.argv.length < 3) return;

var fileName = process.argv[2];
var outFileName = replaceExt(fileName, '.json');

// Load a static file (Note: this file should exist on your computer)
var phpFile = fs.readFileSync(fileName, 'utf-8');

var ast = '';
try {
  ast = parser.parseEval(phpFile);
} catch (err) {
  try {
    ast = parser.parseCode(phpFile, fileName);
  } catch (err2) {
    console.log("wtf do I do");
    return;
  }
}

ast = JSON.stringify(ast, null, 2);

// Log out results
fs.writeFileSync(outFileName, ast);

// Orivoclass server (loader).
// The server code is split into small files (server-part-1.js ... server-part-8.js) so every file is easy to upload to GitHub.
// This file joins them in order and runs them as one program. It also checks that no part was cut off during upload.
const fs = require("fs");
const path = require("path");
const PARTS = 10;
let code = "";
for (let i = 1; i <= PARTS; i++) {
  const name = "server-part-" + i + ".js";
  let text;
  try { text = fs.readFileSync(path.join(__dirname, name), "utf8"); }
  catch (e) { console.error("MISSING FILE: " + name + ". Upload it into the same folder as server.js."); process.exit(1); }
  if (!text.trimEnd().endsWith("// END OF PART " + i)) {
    console.error("INCOMPLETE FILE: " + name + " looks cut off (its last line is missing). Upload that file again.");
    process.exit(1);
  }
  code += text + "\n";
}
new Function("require", "module", "exports", "__dirname", code + "\n//# sourceURL=orivoclass-server.js")(require, module, exports, __dirname);

// Hilfsskript: prüft die <script>-Blöcke der HTML-Dateien auf Syntaxfehler
const fs = require('fs');
const vm = require('vm');
let fail = 0;
for (const file of ['public/index.html', 'public/admin.html']) {
  const html = fs.readFileSync(file, 'utf8');
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  blocks.forEach((m, i) => {
    try {
      new vm.Script(m[1], { filename: `${file}#script${i + 1}` });
      console.log(`OK   ${file} script #${i + 1}`);
    } catch (e) {
      fail = 1;
      console.error(`FAIL ${file} script #${i + 1}: ${e.message}`);
      const line = (e.stack.split('\n')[0].match(/:(\d+)/) || [])[1];
      if (line) console.error('  near line', line, ':', m[1].split('\n')[line - 1]);
    }
  });
}
process.exit(fail);

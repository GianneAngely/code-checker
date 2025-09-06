<?php
// index.php — PHP Code Vulnerability Checker (static analysis)

function analyze_code($code) {
    $lines = preg_split("/\r\n|\n|\r/", $code);
    $findings = [];
    $push = function($type, $severity, $message, $lineNo, $snippet) use (&$findings) {
        $findings[] = [
            'type'     => $type,
            'severity' => $severity,
            'message'  => $message,
            'line'     => $lineNo,
            'snippet'  => trim($snippet),
        ];
    };

    foreach ($lines as $i => $line) {
        $ln = $i + 1;

        // RCE
        if (preg_match('/\b(eval|assert)\s*\(/i', $line)) $push('RCE', 'high', 'Penggunaan eval/assert terdeteksi.', $ln, $line);
        if (preg_match('/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i', $line)) $push('RCE', 'high', 'Pemanggilan perintah sistem terdeteksi.', $ln, $line);
        if (preg_match('/preg_replace\s*\(.*\/e.*\)/i', $line)) $push('RCE', 'high', 'preg_replace dengan /e modifier terdeteksi.', $ln, $line);

        // LFI/RFI
        if (preg_match('/\b(include|include_once|require|require_once)\s*\(\s*\$[\w\[\]\'"\-\>]+\s*\)/i', $line))
            $push('LFI/RFI', 'high', 'Include/require menggunakan input variabel.', $ln, $line);

        // SQLi
        $userInput = '(\\$_(GET|POST|REQUEST|COOKIE|SERVER)\\s*(\\[[^\\]]+\\])*)';
        $hasSQL = preg_match('/(SELECT|INSERT|UPDATE|DELETE)\b/i', $line)
               || preg_match('/(mysql_query|mysqli_query|->query|->exec|DB::select|DB::statement)/i', $line);

        if ($hasSQL && preg_match("/$userInput/i", $line)) {
            if (preg_match('/\.\s*' . $userInput . '/i', $line) || preg_match('/".*\$.*"/', $line)) {
                $push('SQLi', 'high', 'Query SQL berpotensi injeksi (menggunakan input user).', $ln, $line);
            }
        }

        // XSS
        if (preg_match('/\b(echo|print|<\?=)\b/i', $line)
            && preg_match("/$userInput/i", $line)
            && !preg_match('/htmlspecialchars|htmlentities|strip_tags/i', $line)) {
            $push('XSS', 'high', 'Output langsung dari input user tanpa encoding aman.', $ln, $line);
        }

        // Upload / file ops
        if (preg_match('/\bmove_uploaded_file\s*\(/i', $line)
            && !preg_match('/(mime|finfo|pathinfo|extension|allowlist|whitelist)/i', $line))
            $push('Upload', 'medium', 'move_uploaded_file tanpa validasi tipe/ekstensi.', $ln, $line);

        if (preg_match('/\b(file_put_contents|fopen|unlink|rename)\s*\(\s*\$[\w\[\]\'"\-\\>]+/i', $line))
            $push('File', 'medium', 'Operasi file menggunakan nama/path dari variabel.', $ln, $line);

        // Weak crypto
        if (preg_match('/\b(md5|sha1)\s*\(/i', $line))
            $push('Crypto', 'medium', 'Hash lemah (md5/sha1) terdeteksi.', $ln, $line);

        // CSRF
        if (preg_match('/\$_(POST|REQUEST)\s*\[/i', $line)
            && preg_match('/(if\s*\(|isset\s*\()/', $line)
            && !preg_match('/csrf|token/i', $line))
            $push('CSRF', 'low', 'Proses form terdeteksi—perlindungan CSRF tidak terlihat.', $ln, $line);

        // Info leak
        if (preg_match('/\b(var_dump|print_r|phpinfo)\s*\(/i', $line))
            $push('Info', 'low', 'Fungsi debug yang dapat bocorkan informasi terdeteksi.', $ln, $line);
    }

    return $findings;
}

$submitted = ($_SERVER['REQUEST_METHOD'] === 'POST');
$code = $submitted ? ($_POST['code'] ?? '') : '';
$results = $submitted ? analyze_code($code) : [];
?>
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>PHP Code Vulnerability Checker</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <!-- Tailwind -->
  <script src="https://cdn.tailwindcss.com"></script>

  <!-- CodeMirror -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.15/codemirror.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.15/theme/material-darker.min.css">

  <style>
    .editor-card {
      border-radius: .75rem;
      overflow: hidden;
      background: #1e1e1e;
    }
    .editor-header {
      background: #1f2937;
      color: #f3f4f6;
      padding: .7rem 1rem; /* lebih tinggi */
      display: flex; align-items: center; gap: .7rem;
      font-size: 1rem; /* lebih besar */
      font-weight: 500;
    }
    .editor-header svg {
      width: 22px; /* icon lebih besar */
      height: 22px;
      opacity: 0.9;
    }
    .editor-header .chip {
      background: #2563eb;
      color: #fff;
      font-weight: 600;
      padding: .25rem .9rem; /* lebih besar */
      border-radius: .6rem;
      font-size: .9rem;
    }
    .CodeMirror {
      border: none !important;
      height: 400px;
      font-size: 15px;
      font-family: Menlo, Monaco, Consolas, "Courier New", monospace;
      background-color: #1e1e1e;
      color: #e5e7eb;
    }
    .cm-s-material-darker .CodeMirror-gutters {
      background: #1e1e1e;
      border-right: none;
      color: #6b7280;
    }
    .cm-s-material-darker .CodeMirror-linenumber {
      color: #6b7280;
      font-size: 13px;
    }
    .cm-s-material-darker .CodeMirror-cursor {
      border-left: 1px solid #fff;
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <div class="max-w-5xl mx-auto p-6">
    <div class="bg-white rounded-xl shadow-md border border-gray-200">
      <div class="p-6">
        <h1 class="text-xl sm:text-2xl font-bold text-gray-800">PHP Code Vulnerability Checker</h1>
        <p class="mt-1 text-sm text-gray-600">
          Website ini dibuat khusus untuk mengecek kerentanan yang ada di kode <strong>PHP</strong>.
        </p>
      </div>

      <div class="px-6 pb-6">
        <form method="post" class="space-y-4">
          <div class="editor-card">
            <div class="editor-header">
              <!-- icon </> -->
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="16 18 22 12 16 6"></polyline>
                <polyline points="8 6 2 12 8 18"></polyline>
              </svg>
              <span>Code</span>
              <span class="chip">PHP</span>
            </div>
            <textarea id="code" name="code" class="hidden"></textarea>
            <div id="code-editor-wrapper"></div>
          </div>

          <div class="mt-4 flex flex-col sm:flex-row items-center sm:justify-end gap-3">
            <button type="button" id="btn-clear"
              class="w-full sm:w-auto border border-gray-300 hover:bg-gray-50 text-gray-700 font-semibold py-2.5 px-5 rounded-lg">
              Clear
            </button>
            <button type="submit"
              class="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white font-bold py-2.5 px-6 rounded-lg">
              Submit Solution
            </button>
          </div>
        </form>

        <!-- Hasil -->
        <div class="mt-6">
          <?php if ($submitted): ?>
            <?php if (trim($code) === ''): ?>
              <div class="rounded-md border border-gray-200 bg-gray-50 p-4">
                <p class="text-gray-700">Tidak ada kode untuk dianalisis.</p>
              </div>
            <?php elseif (empty($results)): ?>
              <div class="rounded-md border border-green-200 bg-green-50 p-4">
                <p class="font-semibold text-green-800">Tidak ada kerentanan yang terdeteksi.</p>
              </div>
            <?php else: ?>
              <div class="rounded-lg border border-amber-200 bg-amber-50 p-4">
                <p class="font-semibold text-amber-800">Potensi kerentanan terdeteksi:</p>
                <ul class="mt-2 space-y-2">
                  <?php foreach ($results as $f): ?>
                    <?php
                      $sevClass = [
                        'high'   => 'bg-red-600',
                        'medium' => 'bg-orange-500',
                        'low'    => 'bg-yellow-500',
                      ][strtolower($f['severity'])] ?? 'bg-gray-500';
                    ?>
                    <li class="bg-white border rounded-lg p-3">
                      <div class="flex items-center gap-2">
                        <span class="text-xs text-white px-2 py-0.5 rounded <?= $sevClass ?>">
                          <?= strtoupper($f['severity']) ?>
                        </span>
                        <span class="text-sm font-semibold text-gray-800"><?= htmlspecialchars($f['type']) ?></span>
                        <span class="text-xs text-gray-500">Baris <?= (int)$f['line'] ?></span>
                      </div>
                      <div class="mt-1 text-sm text-gray-700"><?= htmlspecialchars($f['message']) ?></div>
                      <pre class="mt-2 text-xs bg-gray-50 border rounded p-2 overflow-x-auto"><code><?= htmlspecialchars($f['snippet']) ?></code></pre>
                    </li>
                  <?php endforeach; ?>
                </ul>
              </div>
            <?php endif; ?>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <p class="text-center text-xs text-gray-400 mt-4">
      &copy; <?= date('Y') ?> PHP Code Vulnerability Checker
    </p>
  </div>

  <!-- CodeMirror -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.15/codemirror.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.15/mode/php/php.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.15/mode/clike/clike.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.15/mode/xml/xml.min.js"></script>
  <script>
    const hidden = document.getElementById('code');
    const wrapper = document.getElementById('code-editor-wrapper');

    const editor = CodeMirror(wrapper, {
      value: hidden.value,
      mode: 'php',
      theme: 'material-darker',
      lineNumbers: true,
      lineWrapping: true,
      indentUnit: 4,
      matchBrackets: true,
      autoCloseBrackets: true,
    });

    editor.on('change', () => hidden.value = editor.getValue());
    setTimeout(() => editor.refresh(), 1);

    document.getElementById('btn-clear').addEventListener('click', () => {
      editor.setValue('');
    });
  </script>
</body>
</html>

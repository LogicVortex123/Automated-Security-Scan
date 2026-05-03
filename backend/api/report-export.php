<?php
declare(strict_types=1);

@ini_set('display_errors', '0');

require_once dirname(__DIR__) . '/ReportXslt.php';
require_once dirname(__DIR__) . '/ReportHtmlFallback.php';
require_once dirname(__DIR__) . '/scan_store.php';

$module = isset($_GET['module']) ? trim((string) $_GET['module']) : '';
if ($module === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Missing module';
    return;
}

try {
    $row = scan_store_select_latest($module);
} catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Storage error';
    return;
}

if ($row === null) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'No scan history for this module. Run a scan first.';
    return;
}

$vulns = json_decode((string) $row['vulnerabilities_json'], true);
if (!is_array($vulns)) {
    $vulns = [];
}

$payload = [
    'module' => $module,
    'vulnerabilities' => $vulns,
    'overall_score' => (float) $row['overall_score'],
    'generated_at' => (string) $row['created_at'],
];

$html = null;
if (class_exists(XSLTProcessor::class)) {
    try {
        $xml = ReportXslt::scanToXml($payload);
        $html = ReportXslt::transform($xml);
    } catch (Throwable) {
        $html = null;
    }
}
if ($html === null || $html === '') {
    $html = ReportHtmlFallback::render($payload);
}

$safe = preg_replace('/[^a-zA-Z0-9_-]+/', '_', $module);
$filename = 'security_report_' . $safe . '.html';

header('Content-Type: text/html; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
echo $html;

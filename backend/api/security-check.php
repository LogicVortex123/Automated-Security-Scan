<?php
declare(strict_types=1);

@ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');

require_once dirname(__DIR__) . '/SecurityScanner.php';
require_once dirname(__DIR__) . '/scan_store.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    return;
}

$raw = file_get_contents('php://input');
$data = is_string($raw) ? json_decode($raw, true) : null;
$module = '';
if (is_array($data) && isset($data['module'])) {
    $module = trim((string) $data['module']);
}
if ($module === '' && isset($_POST['module'])) {
    $module = trim((string) $_POST['module']);
}

if ($module === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Missing module name. Send JSON: {"module":"Patient Registration"}']);
    return;
}

try {
    $result = SecurityScanner::scan($module);
} catch (InvalidArgumentException $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
    return;
}

$overall = SecurityScanner::overallScore($result['vulnerabilities']);

try {
    scan_store_insert($result['module'], $result['vulnerabilities'], $overall);
} catch (Throwable $e) {
    http_response_code(200);
    echo json_encode(
        [
            'module' => $result['module'],
            'vulnerabilities' => $result['vulnerabilities'],
            'warning' => 'Scan ran but could not be saved: ' . $e->getMessage(),
        ],
        JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
    );
    return;
}

$out = [
    'module' => $result['module'],
    'vulnerabilities' => $result['vulnerabilities'],
];

echo json_encode($out, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

<?php
declare(strict_types=1);

@ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');

require_once dirname(__DIR__) . '/scan_store.php';

$module = isset($_GET['module']) ? trim((string) $_GET['module']) : '';
if ($module === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Missing module']);
    return;
}

try {
    $rows = scan_store_select_history($module, 25);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(
        ['error' => 'Storage error: ' . $e->getMessage(), 'module' => $module, 'history' => []],
        JSON_UNESCAPED_UNICODE
    );
    return;
}

$history = [];
foreach ($rows as $r) {
    $decoded = json_decode((string) $r['vulnerabilities_json'], true);
    if (!is_array($decoded)) {
        $decoded = [];
    }
    $history[] = [
        'id' => (int) $r['id'],
        'module' => $r['module_name'],
        'vulnerabilities' => $decoded,
        'overall_score' => (float) $r['overall_score'],
        'timestamp' => $r['created_at'],
    ];
}

echo json_encode(
    [
        'module' => $module,
        'history' => $history,
    ],
    JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
);

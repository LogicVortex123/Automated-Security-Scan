<?php
declare(strict_types=1);

@ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');

require_once dirname(__DIR__) . '/scan_store.php';

try {
    $driver = scan_store_driver();
    $messages = [
        'mysql' => 'Using MySQL.',
        'sqlite' => 'Using local SQLite file (backend/data/security_scans.sqlite).',
        'jsonfile' => 'Using JSON file storage (backend/data/scans.json) — no PDO drivers required.',
    ];
    echo json_encode(
        [
            'ok' => true,
            'db_driver' => $driver,
            'message' => $messages[$driver] ?? 'OK',
        ],
        JSON_UNESCAPED_UNICODE
    );
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(
        [
            'ok' => false,
            'error' => $e->getMessage(),
        ],
        JSON_UNESCAPED_UNICODE
    );
}

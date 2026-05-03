<?php
/**
 * Local development defaults. Override with environment variables if needed.
 * Set DB_SQLITE_ONLY=1 to skip MySQL and use only backend/data/security_scans.sqlite.
 */
declare(strict_types=1);

return [
    'mysql_first' => getenv('DB_SQLITE_ONLY') !== '1',
    'db' => [
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => (int) (getenv('DB_PORT') ?: '3306'),
        'name' => getenv('DB_NAME') ?: 'lh_ehr_security',
        'user' => getenv('DB_USER') ?: 'root',
        'pass' => getenv('DB_PASS') !== false ? getenv('DB_PASS') : '',
        'charset' => 'utf8mb4',
    ],
];

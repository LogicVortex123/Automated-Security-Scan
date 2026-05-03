<?php
declare(strict_types=1);

/**
 * Try MySQL then SQLite. Returns null if no PDO driver is available (e.g. pdo_sqlite / pdo_mysql disabled).
 *
 * @return PDO|null
 */
function db_try_pdo(): ?PDO
{
    static $cached = null;
    static $done = false;

    if ($done) {
        return $cached;
    }
    $done = true;

    $cfg = require __DIR__ . '/config.php';
    $d = $cfg['db'];
    $mysqlFirst = ($cfg['mysql_first'] ?? true) === true;

    if ($mysqlFirst) {
        try {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $d['host'],
                $d['port'],
                $d['name'],
                $d['charset']
            );
            $mysql = new PDO($dsn, $d['user'], $d['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            $mysql->query('SELECT 1');
            $cached = $mysql;
            return $cached;
        } catch (Throwable) {
            // MySQL unavailable or pdo_mysql missing.
        }
    }

    $dataDir = __DIR__ . '/data';
    if (!is_dir($dataDir) && !@mkdir($dataDir, 0755, true) && !is_dir($dataDir)) {
        $cached = null;
        return null;
    }

    try {
        $sqlitePath = $dataDir . DIRECTORY_SEPARATOR . 'security_scans.sqlite';
        $sqlite = new PDO('sqlite:' . $sqlitePath, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        $sqlite->exec(
            'CREATE TABLE IF NOT EXISTS security_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT NOT NULL,
                vulnerabilities_json TEXT NOT NULL,
                overall_score REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
            )'
        );
        $sqlite->exec(
            'CREATE INDEX IF NOT EXISTS idx_module_created ON security_scans (module_name, created_at)'
        );

        $cached = $sqlite;
        return $cached;
    } catch (Throwable) {
        $cached = null;
        return null;
    }
}

/**
 * @throws RuntimeException when no PDO backend is available (use file fallback instead).
 */
function db_connect(): PDO
{
    $pdo = db_try_pdo();
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    throw new RuntimeException('No PDO driver available. Enable pdo_sqlite or pdo_mysql in php.ini, or the app will use JSON file storage.');
}

/** @return 'mysql'|'sqlite' */
function db_driver(PDO $pdo): string
{
    $n = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    return $n === 'mysql' ? 'mysql' : 'sqlite';
}

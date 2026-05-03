<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

/**
 * Unified scan persistence: PDO (MySQL/SQLite) or JSON file if no drivers.
 */

function scan_store_data_dir(): string
{
    $dir = __DIR__ . '/data';
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create data directory: ' . $dir);
    }
    return $dir;
}

function scan_store_json_path(): string
{
    return scan_store_data_dir() . DIRECTORY_SEPARATOR . 'scans.json';
}

/** @return 'mysql'|'sqlite'|'jsonfile' */
function scan_store_driver(): string
{
    $pdo = db_try_pdo();
    if ($pdo instanceof PDO) {
        return db_driver($pdo);
    }
    return 'jsonfile';
}

function scan_store_insert(string $module, array $vulnerabilities, float $overall): void
{
    $pdo = db_try_pdo();
    if ($pdo instanceof PDO) {
        $stmt = $pdo->prepare(
            'INSERT INTO security_scans (module_name, vulnerabilities_json, overall_score) VALUES (?, ?, ?)'
        );
        $stmt->execute([
            $module,
            json_encode($vulnerabilities, JSON_UNESCAPED_UNICODE),
            $overall,
        ]);
        return;
    }

    $path = scan_store_json_path();
    $lockPath = $path . '.lock';
    $fp = fopen($lockPath, 'c+');
    if ($fp === false) {
        throw new RuntimeException('Cannot lock JSON store');
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        throw new RuntimeException('Cannot acquire lock for JSON store');
    }
    try {
        $data = ['scans' => []];
        if (is_file($path)) {
            $raw = file_get_contents($path);
            if ($raw !== false && $raw !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded) && isset($decoded['scans']) && is_array($decoded['scans'])) {
                    $data = $decoded;
                }
            }
        }
        $nextId = 1;
        foreach ($data['scans'] as $row) {
            $nextId = max($nextId, (int) ($row['id'] ?? 0) + 1);
        }
        $data['scans'][] = [
            'id' => $nextId,
            'module_name' => $module,
            'vulnerabilities_json' => json_encode($vulnerabilities, JSON_UNESCAPED_UNICODE),
            'overall_score' => $overall,
            'created_at' => date('Y-m-d H:i:s'),
        ];
        if (file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) === false) {
            throw new RuntimeException('Cannot write JSON store');
        }
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

/**
 * @return list<array{id:int,module_name:string,vulnerabilities_json:string,overall_score:float,created_at:string}>
 */
function scan_store_select_history(string $module, int $limit = 25): array
{
    $pdo = db_try_pdo();
    if ($pdo instanceof PDO) {
        $stmt = $pdo->prepare(
            'SELECT id, module_name, vulnerabilities_json, overall_score, created_at
             FROM security_scans
             WHERE module_name = ?
             ORDER BY created_at DESC
             LIMIT ?'
        );
        $stmt->bindValue(1, $module, PDO::PARAM_STR);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    $path = scan_store_json_path();
    if (!is_file($path)) {
        return [];
    }
    $raw = file_get_contents($path);
    if ($raw === false || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || !isset($decoded['scans']) || !is_array($decoded['scans'])) {
        return [];
    }
    $rows = [];
    foreach ($decoded['scans'] as $row) {
        if (!is_array($row)) {
            continue;
        }
        if (($row['module_name'] ?? '') !== $module) {
            continue;
        }
        $rows[] = $row;
    }
    usort($rows, static function (array $a, array $b): int {
        return strcmp((string) ($b['created_at'] ?? ''), (string) ($a['created_at'] ?? ''));
    });
    return array_slice($rows, 0, $limit);
}

/** @return array{id:int,module_name:string,vulnerabilities_json:string,overall_score:float,created_at:string}|null */
function scan_store_select_latest(string $module): ?array
{
    $rows = scan_store_select_history($module, 1);
    return $rows[0] ?? null;
}

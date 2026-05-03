<?php
declare(strict_types=1);

/**
 * Router for PHP built-in server:
 *   php -S localhost:8000 index.php
 *
 * APIs (exact paths per spec):
 *   POST /security-check
 *   GET  /report/{module}
 *   GET  /report-export/{module}  — downloadable HTML (XSLT), latest scan for module
 */

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

if ($uri === false || $uri === null) {
    $uri = '/';
}

/** Local dev: allow browser tools / Live Server to call APIs on this PHP server (cross-origin). */
$isApiPath =
    $uri === '/health'
    || $uri === '/security-check'
    || ($uri !== '' && str_starts_with($uri, '/report/'))
    || ($uri !== '' && str_starts_with($uri, '/report-export/'));

if ($isApiPath) {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Accept');
}

if ($method === 'OPTIONS' && $isApiPath) {
    http_response_code(204);
    return true;
}

/**
 * Safe "file is inside directory" check (Windows drive letter / slash variants).
 */
$path_is_inside = static function (string $dir, string $file): bool {
    $dirReal = realpath($dir);
    $fileReal = realpath($file);
    if ($dirReal === false || $fileReal === false || !is_file($fileReal)) {
        return false;
    }
    $dirNorm = rtrim(str_replace('\\', '/', $dirReal), '/');
    $fileNorm = str_replace('\\', '/', $fileReal);
    return $fileNorm === $dirNorm || str_starts_with($fileNorm, $dirNorm . '/');
};

// --- API: GET /health
if ($uri === '/health' && $method === 'GET') {
    require __DIR__ . '/backend/api/health.php';
    return true;
}

// --- API: POST /security-check
if ($uri === '/security-check' && $method === 'POST') {
    require __DIR__ . '/backend/api/security-check.php';
    return true;
}

// --- API: GET /report/{module}
if ($method === 'GET' && preg_match('#^/report/(.+)$#u', $uri, $m)) {
    $_GET['module'] = rawurldecode($m[1]);
    require __DIR__ . '/backend/api/report.php';
    return true;
}

// --- Download HTML report: GET /report-export/{module}
if ($method === 'GET' && preg_match('#^/report-export/(.+)$#u', $uri, $m)) {
    $_GET['module'] = rawurldecode($m[1]);
    require __DIR__ . '/backend/api/report-export.php';
    return true;
}

// --- Static frontend
$frontendBase = realpath(__DIR__ . '/frontend');
if ($frontendBase === false) {
    http_response_code(500);
    echo 'Frontend directory missing';
    return true;
}

if ($uri === '/' || $uri === '') {
    header('Content-Type: text/html; charset=utf-8');
    readfile($frontendBase . DIRECTORY_SEPARATOR . 'index.html');
    return true;
}

$rel = ltrim($uri, '/');
$candidatePath = $frontendBase . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
$candidate = realpath($candidatePath);
if ($candidate !== false && $path_is_inside($frontendBase, $candidate)) {
    $ext = strtolower(pathinfo($candidate, PATHINFO_EXTENSION));
    $types = [
        'html' => 'text/html; charset=utf-8',
        'css' => 'text/css; charset=utf-8',
        'js' => 'application/javascript; charset=utf-8',
        'png' => 'image/png',
        'ico' => 'image/x-icon',
        'svg' => 'image/svg+xml',
    ];
    if (isset($types[$ext])) {
        header('Content-Type: ' . $types[$ext]);
    }
    readfile($candidate);
    return true;
}

http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
echo 'Not Found';
return true;

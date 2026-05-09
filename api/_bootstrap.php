<?php
// Shared bootstrap for every API endpoint: CORS, JSON helpers, domain validation, DB.

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

function spectr_config(): array {
    static $cfg = null;
    if ($cfg === null) {
        $cfg = require __DIR__ . '/../config/config.php';
    }
    return $cfg;
}

function spectr_respond(array $payload, int $status = 200): void {
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function spectr_ok(array $data, ?string $domain = null): void {
    spectr_respond([
        'success' => true,
        'domain'  => $domain,
        'data'    => $data,
    ]);
}

function spectr_error(string $message, int $status = 400, array $extra = []): void {
    spectr_respond(array_merge([
        'success' => false,
        'error'   => $message,
    ], $extra), $status);
}

function spectr_input_domain(): string {
    $raw = $_GET['domain'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $json = json_decode($body, true);
            $raw = is_array($json) ? ($json['domain'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['domain'] ?? null);
    }
    if (!is_string($raw) || $raw === '') {
        spectr_error('Missing "domain" parameter.', 422);
    }
    return spectr_normalize_domain($raw);
}

function spectr_normalize_domain(string $input): string {
    $d = trim($input);
    $d = preg_replace('#^https?://#i', '', $d);
    $d = preg_replace('#/.*$#', '', $d);
    $d = strtolower($d);

    if (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $d)) {
        spectr_error('Invalid domain name.', 422);
    }
    return $d;
}

function spectr_db(): ?PDO {
    static $pdo = null;
    static $tried = false;
    if ($tried) {
        return $pdo;
    }
    $tried = true;

    $cfg = spectr_config()['db'];
    $dsn = sprintf('pgsql:host=%s;port=%s;dbname=%s', $cfg['host'], $cfg['port'], $cfg['name']);
    try {
        $pdo = new PDO($dsn, $cfg['user'], $cfg['password'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    } catch (Throwable $e) {
        $pdo = null;
    }
    return $pdo;
}

function spectr_log_scan(string $domain, string $module, bool $success, array $result): void {
    $pdo = spectr_db();
    if ($pdo === null) {
        return;
    }
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO scans (domain, module, success, result) VALUES (:domain, :module, :success, :result::jsonb)'
        );
        $stmt->execute([
            ':domain'  => $domain,
            ':module'  => $module,
            ':success' => $success ? 't' : 'f',
            ':result'  => json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ]);
    } catch (Throwable $e) {
        // Logging failures must never break the response.
    }
}

function spectr_http_get(string $url, array $headers = []): array {
    $cfg = spectr_config()['http'];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => $cfg['timeout'],
        CURLOPT_USERAGENT      => $cfg['user_agent'],
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $body   = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err    = curl_error($ch);
    curl_close($ch);
    return ['status' => (int)$status, 'body' => $body, 'error' => $err];
}

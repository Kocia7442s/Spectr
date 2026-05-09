<?php
// /api/wayback.php — Internet Archive / Wayback Machine snapshot lookup.

require __DIR__ . '/_bootstrap.php';

function wayback_input(): string {
    $raw = $_GET['url'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['url'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['url'] ?? null);
    }
    if (!is_string($raw) || trim($raw) === '') {
        spectr_error('Missing "url" parameter.', 422);
    }
    $u = trim($raw);
    if (!preg_match('#^https?://#i', $u)) {
        $u = 'http://' . $u;
    }
    if (!filter_var($u, FILTER_VALIDATE_URL)) {
        spectr_error('Invalid URL.', 422);
    }
    return $u;
}

function wayback_http_get(string $url, int $timeout): array {
    // archive.org severely throttles unfamiliar User-Agents — use a browser-style UA.
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $body   = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err    = curl_error($ch);
    curl_close($ch);
    return ['status' => $status, 'body' => $body, 'error' => $err];
}

function wayback_human_date(string $ts): ?string {
    // Wayback timestamps are YYYYMMDDhhmmss (14 chars), sometimes truncated to YYYYMMDD or shorter.
    $ts = preg_replace('/\D/', '', $ts);
    if (strlen($ts) < 8) return null;
    $padded = str_pad(substr($ts, 0, 14), 14, '0');
    $dt = DateTime::createFromFormat('YmdHis', $padded);
    if ($dt === false) return null;
    return $dt->format('Y-m-d H:i:s') . ' UTC';
}

$url = wayback_input();

// 1. Availability API — closest snapshot. Returns {} for many URLs even when CDX has results,
//    so treat this as informational only — CDX is the source of truth for is_archived.
$avail = wayback_http_get('https://archive.org/wayback/available?url=' . urlencode($url), 15);
$closest = null;
$availError = null;
if ($avail['status'] !== 200) {
    $availError = 'Availability HTTP ' . $avail['status'] . ($avail['error'] ? ' — ' . $avail['error'] : '');
}
if ($avail['status'] === 200 && $avail['body']) {
    $j = json_decode($avail['body'], true);
    if (is_array($j) && !empty($j['archived_snapshots']['closest'])) {
        $c = $j['archived_snapshots']['closest'];
        $closest = [
            'url'        => $c['url']        ?? null,
            'timestamp'  => $c['timestamp']  ?? null,
            'date_human' => isset($c['timestamp']) ? wayback_human_date((string)$c['timestamp']) : null,
            'status'     => $c['status']     ?? null,
            'available'  => $c['available']  ?? null,
        ];
    }
}

// 2. CDX API — last 20 snapshots, collapsed by month-precision (timestamp:6).
$cdxUrl = 'https://web.archive.org/cdx/search/cdx?url=' . urlencode($url)
        . '&output=json&limit=20&fl=timestamp,statuscode,mimetype,length&collapse=timestamp:6';
$cdx = wayback_http_get($cdxUrl, 45);  // CDX is slow — needs a generous timeout.

$snapshots = [];
$cdxError  = null;
if ($cdx['status'] === 200 && $cdx['body']) {
    $rows = json_decode($cdx['body'], true);
    if (is_array($rows) && !empty($rows)) {
        // First row is the field list ("header"); skip it.
        $header = array_shift($rows);
        $idx    = array_flip($header);
        foreach ($rows as $row) {
            if (!is_array($row)) continue;
            $ts = (string)($row[$idx['timestamp']] ?? '');
            $snapshots[] = [
                'timestamp'   => $ts,
                'date_human'  => wayback_human_date($ts),
                'status_code' => isset($idx['statuscode']) ? ($row[$idx['statuscode']] ?? null) : null,
                'mimetype'    => isset($idx['mimetype'])   ? ($row[$idx['mimetype']]   ?? null) : null,
                'length'      => isset($idx['length'])     ? (int)($row[$idx['length']] ?? 0) : null,
                'wayback_url' => $ts !== '' ? 'https://web.archive.org/web/' . $ts . '/' . $url : null,
            ];
        }
    }
} elseif ($cdx['status'] !== 200) {
    $cdxError = 'CDX HTTP ' . $cdx['status'] . ($cdx['error'] ? ' — ' . $cdx['error'] : '');
}

$isArchived = $closest !== null || !empty($snapshots);
// CDX is the source of truth for snapshot history. If it failed and we have nothing else,
// we genuinely don't know whether the URL has been archived.
$lookupStatus = $isArchived
    ? 'archived'
    : ($cdxError !== null ? 'unknown' : 'not_archived');

$payload = [
    'url'                => $url,
    'is_archived'        => $isArchived,
    'lookup_status'      => $lookupStatus,
    'closest_snapshot'   => $closest,
    'snapshots'          => $snapshots,
    'snapshot_count'     => count($snapshots),
    'availability_error' => $availError,
    'cdx_error'          => $cdxError,
    'search_urls'        => [
        'full_history' => 'https://web.archive.org/web/*/' . $url,
        'calendar'     => 'https://web.archive.org/web/20*/' . $url,
    ],
    'source' => 'archive.org',
];

spectr_log_scan($url, 'wayback', $isArchived, $payload);
spectr_ok($payload, $url);

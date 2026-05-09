<?php
// /api/subdomains.php — Subdomain discovery via crt.sh certificate transparency logs.

require __DIR__ . '/_bootstrap.php';

$domain = spectr_input_domain();

$url = 'https://crt.sh/?q=' . urlencode('%.' . $domain) . '&output=json';
$res = spectr_http_get($url, ['Accept: application/json']);

if ($res['status'] !== 200 || !$res['body']) {
    spectr_error('crt.sh request failed.', 502, [
        'http_status' => $res['status'],
        'curl_error'  => $res['error'],
    ]);
}

$entries = json_decode($res['body'], true);
if (!is_array($entries)) {
    spectr_error('crt.sh returned non-JSON payload.', 502);
}

$set = [];
$wildcards = [];
foreach ($entries as $row) {
    $names = isset($row['name_value']) ? explode("\n", (string)$row['name_value']) : [];
    if (isset($row['common_name'])) {
        $names[] = (string)$row['common_name'];
    }
    foreach ($names as $name) {
        $name = strtolower(trim($name));
        if ($name === '' || $name === $domain) continue;
        if (!str_ends_with($name, '.' . $domain)) continue;
        if (str_starts_with($name, '*.')) {
            $wildcards[$name] = true;
            continue;
        }
        $set[$name] = true;
    }
}

$subdomains = array_keys($set);
sort($subdomains, SORT_STRING);
$wildcardList = array_keys($wildcards);
sort($wildcardList, SORT_STRING);

// Group by depth (label count) for a quick overview in the UI.
$byDepth = [];
foreach ($subdomains as $s) {
    $depth = substr_count($s, '.') + 1;
    $byDepth[$depth] = ($byDepth[$depth] ?? 0) + 1;
}
ksort($byDepth);

$payload = [
    'subdomains'    => $subdomains,
    'wildcards'     => $wildcardList,
    'count'         => count($subdomains),
    'wildcard_count'=> count($wildcardList),
    'depth_breakdown' => $byDepth,
    'source'        => 'crt.sh',
    'raw_entries'   => count($entries),
];

spectr_log_scan($domain, 'subdomains', $payload['count'] > 0, $payload);
spectr_ok($payload, $domain);

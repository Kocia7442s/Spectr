<?php
// /api/geoip.php — IP geolocation via ipinfo.io (free tier, no key needed).

require __DIR__ . '/_bootstrap.php';

$domain = spectr_input_domain();

set_error_handler(static function () { /* swallow dns warnings */ });
$aRecords = dns_get_record($domain, DNS_A);
restore_error_handler();

$ips = [];
if (is_array($aRecords)) {
    foreach ($aRecords as $r) {
        if (!empty($r['ip'])) $ips[$r['ip']] = true;
    }
}
$ips = array_keys($ips);

if (!$ips) {
    spectr_error('No A records found for ' . $domain . ' — nothing to geolocate.', 404);
}

function geoip_parse_loc(?string $loc): array {
    if (!$loc || strpos($loc, ',') === false) {
        return ['lat' => null, 'lng' => null];
    }
    [$lat, $lng] = array_map('trim', explode(',', $loc, 2));
    return [
        'lat' => is_numeric($lat) ? (float)$lat : null,
        'lng' => is_numeric($lng) ? (float)$lng : null,
    ];
}

function geoip_parse_org(?string $org): array {
    // ipinfo's org field is typically "AS12345 Organisation Name".
    if (!$org) return ['asn' => null, 'org_name' => null];
    if (preg_match('/^(AS\d+)\s+(.+)$/', $org, $m)) {
        return ['asn' => $m[1], 'org_name' => trim($m[2])];
    }
    return ['asn' => null, 'org_name' => $org];
}

$hosts      = [];
$ipErrors   = [];

foreach ($ips as $ip) {
    $res = spectr_http_get('https://ipinfo.io/' . urlencode($ip) . '/json', ['Accept: application/json']);

    if ($res['status'] !== 200 || !$res['body']) {
        $ipErrors[$ip] = 'HTTP ' . $res['status'] . ($res['error'] ? ' — ' . $res['error'] : '');
        continue;
    }

    $j = json_decode($res['body'], true);
    if (!is_array($j)) {
        $ipErrors[$ip] = 'Invalid JSON from ipinfo.io';
        continue;
    }
    if (!empty($j['error'])) {
        $msg = is_array($j['error']) ? ($j['error']['message'] ?? json_encode($j['error'])) : (string)$j['error'];
        $ipErrors[$ip] = $msg;
        continue;
    }

    $loc = geoip_parse_loc($j['loc'] ?? null);
    $org = geoip_parse_org($j['org'] ?? null);

    $hosts[] = [
        'ip'       => $j['ip']       ?? $ip,
        'hostname' => $j['hostname'] ?? null,
        'city'     => $j['city']     ?? null,
        'region'   => $j['region']   ?? null,
        'country'  => $j['country']  ?? null,
        'loc'      => $j['loc']      ?? null,
        'lat'      => $loc['lat'],
        'lng'      => $loc['lng'],
        'org'      => $j['org']      ?? null,
        'asn'      => $org['asn'],
        'org_name' => $org['org_name'],
        'postal'   => $j['postal']   ?? null,
        'timezone' => $j['timezone'] ?? null,
    ];
}

$payload = [
    'ips'        => $ips,
    'ip_count'   => count($ips),
    'hosts'      => $hosts,
    'errors'     => $ipErrors,
    'source'     => 'ipinfo.io',
];

spectr_log_scan($domain, 'geoip', !empty($hosts), $payload);
spectr_ok($payload, $domain);

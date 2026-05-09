<?php
// /api/shodan.php — Shodan host lookup for every A record on the domain.

require __DIR__ . '/_bootstrap.php';

$domain = spectr_input_domain();

$apiKey = spectr_config()['shodan_api_key'] ?? '';
if ($apiKey === '') {
    spectr_error('Shodan API key not configured (set shodan_api_key in config/config.php or SPECTR_SHODAN_KEY).', 503);
}

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
    spectr_error('No A records found for ' . $domain . ' — nothing to query Shodan with.', 404);
}

function shodan_summarize_host(array $h): array {
    $ports = [];
    foreach ($h['data'] ?? [] as $svc) {
        $ports[] = [
            'port'      => $svc['port']      ?? null,
            'transport' => $svc['transport'] ?? 'tcp',
            'service'   => $svc['_shodan']['module'] ?? ($svc['product'] ?? null),
            'product'   => $svc['product']   ?? null,
            'version'   => $svc['version']   ?? null,
            'banner'    => isset($svc['data']) ? mb_substr((string)$svc['data'], 0, 600) : null,
            'timestamp' => $svc['timestamp'] ?? null,
        ];
    }
    usort($ports, static fn($a, $b) => ($a['port'] ?? 0) <=> ($b['port'] ?? 0));

    $vulns = [];
    foreach (($h['vulns'] ?? []) as $cve => $meta) {
        if (is_int($cve) && is_string($meta)) {
            // older API shape: vulns is a flat list of strings
            $vulns[] = ['cve' => $meta];
        } else {
            $vulns[] = [
                'cve'       => $cve,
                'cvss'      => $meta['cvss']      ?? null,
                'summary'   => isset($meta['summary']) ? mb_substr((string)$meta['summary'], 0, 400) : null,
                'verified'  => $meta['verified']  ?? null,
            ];
        }
    }
    // Per-service vuln dictionaries that some Shodan records carry.
    foreach ($h['data'] ?? [] as $svc) {
        foreach (($svc['vulns'] ?? []) as $cve => $meta) {
            $vulns[] = is_array($meta)
                ? ['cve' => is_string($cve) ? $cve : ($meta['cve'] ?? null), 'cvss' => $meta['cvss'] ?? null, 'summary' => isset($meta['summary']) ? mb_substr((string)$meta['summary'], 0, 400) : null]
                : ['cve' => is_string($meta) ? $meta : (string)$cve];
        }
    }
    // Dedupe by CVE id.
    $seen = []; $vulns = array_values(array_filter($vulns, function ($v) use (&$seen) {
        $k = $v['cve'] ?? null; if (!$k || isset($seen[$k])) return false; $seen[$k] = true; return true;
    }));

    return [
        'ip'          => $h['ip_str']       ?? null,
        'hostnames'   => $h['hostnames']    ?? [],
        'os'          => $h['os']           ?? null,
        'org'         => $h['org']          ?? null,
        'isp'         => $h['isp']          ?? null,
        'asn'         => $h['asn']          ?? null,
        'country'     => $h['country_name'] ?? null,
        'country_code'=> $h['country_code'] ?? null,
        'city'        => $h['city']         ?? null,
        'last_update' => $h['last_update']  ?? null,
        'tags'        => $h['tags']         ?? [],
        'ports'       => $ports,
        'port_count'  => count($ports),
        'vulns'       => $vulns,
        'vuln_count'  => count($vulns),
    ];
}

$results   = [];
$rateLimited = false;
$apiErrors = [];

foreach ($ips as $ip) {
    $url = 'https://api.shodan.io/shodan/host/' . urlencode($ip) . '?key=' . urlencode($apiKey);
    $res = spectr_http_get($url, ['Accept: application/json']);
    $status = $res['status'];

    if ($status === 200 && $res['body']) {
        $h = json_decode($res['body'], true);
        if (is_array($h)) {
            $results[] = shodan_summarize_host($h);
            continue;
        }
        $apiErrors[$ip] = 'Invalid JSON from Shodan';
        continue;
    }

    if ($status === 404) {
        // Shodan returns 404 with {"error":"No information available for that IP."} — that's a valid empty result.
        $results[] = [
            'ip'        => $ip,
            'not_found' => true,
            'message'   => 'No Shodan data for this IP.',
            'ports'     => [], 'port_count' => 0, 'vulns' => [], 'vuln_count' => 0,
        ];
        continue;
    }

    if ($status === 401) {
        spectr_error('Shodan rejected the API key (401). Check shodan_api_key in config.', 401);
    }
    if ($status === 402 || $status === 429) {
        $rateLimited = true;
        $apiErrors[$ip] = $status === 402
            ? 'Shodan plan limit reached (402) — upgrade or wait for reset.'
            : 'Shodan rate limit hit (429) — slow down or wait for reset.';
        // Don't keep hammering once we've been rate-limited.
        break;
    }

    $msg = 'HTTP ' . $status;
    if ($res['body']) {
        $j = json_decode($res['body'], true);
        if (is_array($j) && isset($j['error'])) $msg .= ' — ' . $j['error'];
    }
    $apiErrors[$ip] = $msg;
}

$totalPorts = array_sum(array_map(static fn($r) => $r['port_count'] ?? 0, $results));
$totalVulns = array_sum(array_map(static fn($r) => $r['vuln_count'] ?? 0, $results));

$payload = [
    'ips'           => $ips,
    'ip_count'      => count($ips),
    'hosts'         => $results,
    'total_ports'   => $totalPorts,
    'total_vulns'   => $totalVulns,
    'rate_limited'  => $rateLimited,
    'api_errors'    => $apiErrors,
];

spectr_log_scan($domain, 'shodan', !empty($results), $payload);
spectr_ok($payload, $domain);

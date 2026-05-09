<?php
// /api/whois.php — Socket-based WHOIS lookup with referral chase + parsed fields.

require __DIR__ . '/_bootstrap.php';

$domain = spectr_input_domain();

function whois_query(string $server, string $query, int $timeout = 8): ?string {
    $errno = 0; $errstr = '';
    $fp = @fsockopen($server, 43, $errno, $errstr, $timeout);
    if (!$fp) {
        return null;
    }
    stream_set_timeout($fp, $timeout);
    fwrite($fp, $query . "\r\n");
    $response = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 4096);
        if ($chunk === false) break;
        $response .= $chunk;
        $info = stream_get_meta_data($fp);
        if ($info['timed_out']) break;
    }
    fclose($fp);
    return $response !== '' ? $response : null;
}

function whois_extract_referral(string $raw): ?string {
    if (preg_match('/(?:whois|refer):\s*([a-z0-9.\-]+)/i', $raw, $m)) {
        return strtolower($m[1]);
    }
    return null;
}

function whois_parse(string $raw): array {
    $fields = [
        'registrar'      => '/Registrar:\s*(.+)/i',
        'registrar_url'  => '/Registrar URL:\s*(.+)/i',
        'creation_date'  => '/(?:Creation Date|Created On|registered on):\s*(.+)/i',
        'updated_date'   => '/(?:Updated Date|Last Updated On|last-update):\s*(.+)/i',
        'expiry_date'    => '/(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date):\s*(.+)/i',
        'registrant_org' => '/Registrant Organization:\s*(.+)/i',
        'registrant_country' => '/Registrant Country:\s*(.+)/i',
        'dnssec'         => '/DNSSEC:\s*(.+)/i',
    ];
    $out = [];
    foreach ($fields as $key => $rx) {
        if (preg_match($rx, $raw, $m)) {
            $out[$key] = trim($m[1]);
        }
    }
    if (preg_match_all('/Name Server:\s*([^\s]+)/i', $raw, $m)) {
        $out['name_servers'] = array_values(array_unique(array_map('strtolower', $m[1])));
    }
    if (preg_match_all('/Domain Status:\s*([^\r\n]+)/i', $raw, $m)) {
        $out['status'] = array_values(array_unique(array_map('trim', $m[1])));
    }
    return $out;
}

$chain = [];

// Step 1: ask IANA which registry handles the TLD.
$tld = substr(strrchr($domain, '.'), 1);
$ianaResp = whois_query('whois.iana.org', $tld);
if ($ianaResp === null) {
    spectr_error('WHOIS connection to whois.iana.org failed.', 502);
}
$chain[] = ['server' => 'whois.iana.org', 'query' => $tld, 'length' => strlen($ianaResp)];
$registry = whois_extract_referral($ianaResp);

// Step 2: query the registry's WHOIS server with the full domain.
$final_raw = $ianaResp;
if ($registry !== null) {
    $registryResp = whois_query($registry, $domain);
    if ($registryResp !== null && $registryResp !== '') {
        $final_raw = $registryResp;
        $chain[] = ['server' => $registry, 'query' => $domain, 'length' => strlen($registryResp)];

        // Step 3: thin registries (e.g. .com) point at a registrar's WHOIS — chase one hop.
        $registrarServer = whois_extract_referral($registryResp);
        if ($registrarServer !== null && $registrarServer !== $registry) {
            $registrarResp = whois_query($registrarServer, $domain);
            if ($registrarResp !== null && $registrarResp !== '') {
                $final_raw = $registrarResp;
                $chain[] = ['server' => $registrarServer, 'query' => $domain, 'length' => strlen($registrarResp)];
            }
        }
    }
}

$parsed = whois_parse($final_raw);

$payload = [
    'parsed'  => $parsed,
    'servers' => $chain,
    'raw'     => $final_raw,
];

spectr_log_scan($domain, 'whois', !empty($parsed), $payload);
spectr_ok($payload, $domain);

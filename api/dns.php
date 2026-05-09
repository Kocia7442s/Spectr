<?php
// /api/dns.php — DNS records enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA).

require __DIR__ . '/_bootstrap.php';

$domain = spectr_input_domain();

$types = [
    'A'     => DNS_A,
    'AAAA'  => DNS_AAAA,
    'MX'    => DNS_MX,
    'TXT'   => DNS_TXT,
    'NS'    => DNS_NS,
    'CNAME' => DNS_CNAME,
    'SOA'   => DNS_SOA,
];

$records = [];
$errors  = [];

foreach ($types as $label => $flag) {
    set_error_handler(static function () { /* swallow dns_get_record warnings */ });
    $result = dns_get_record($domain, $flag);
    restore_error_handler();

    if ($result === false) {
        $errors[$label] = 'Lookup failed';
        $records[$label] = [];
        continue;
    }

    $records[$label] = array_map(static function (array $r) use ($label) {
        // Normalize: keep only fields relevant to each type.
        $base = ['host' => $r['host'] ?? null, 'ttl' => $r['ttl'] ?? null];
        switch ($label) {
            case 'A':     return $base + ['ip'       => $r['ip']     ?? null];
            case 'AAAA':  return $base + ['ipv6'     => $r['ipv6']   ?? null];
            case 'MX':    return $base + ['target'   => $r['target'] ?? null, 'pri' => $r['pri'] ?? null];
            case 'TXT':   return $base + ['txt'      => $r['txt']    ?? (isset($r['entries']) ? implode('', $r['entries']) : null)];
            case 'NS':    return $base + ['target'   => $r['target'] ?? null];
            case 'CNAME': return $base + ['target'   => $r['target'] ?? null];
            case 'SOA':   return $base + [
                'mname'   => $r['mname']   ?? null,
                'rname'   => $r['rname']   ?? null,
                'serial'  => $r['serial']  ?? null,
                'refresh' => $r['refresh'] ?? null,
                'retry'   => $r['retry']   ?? null,
                'expire'  => $r['expire']  ?? null,
                'minimum-ttl' => $r['minimum-ttl'] ?? null,
            ];
        }
        return $base;
    }, $result);
}

$total = array_sum(array_map('count', $records));
$payload = [
    'records' => $records,
    'counts'  => array_map('count', $records),
    'total'   => $total,
    'errors'  => $errors,
];

spectr_log_scan($domain, 'dns', $total > 0, $payload);
spectr_ok($payload, $domain);

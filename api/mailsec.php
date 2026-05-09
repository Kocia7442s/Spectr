<?php
// /api/mailsec.php — SPF / DKIM / DMARC / MTA-STS / BIMI audit on an email domain.

require __DIR__ . '/_bootstrap.php';

function mailsec_input(): string {
    $raw = $_GET['domain'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['domain'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['domain'] ?? null);
    }
    if (!is_string($raw) || trim($raw) === '') {
        spectr_error('Missing "domain" parameter.', 422);
    }
    $d = trim($raw);
    if (strpos($d, '@') !== false) {
        $d = substr($d, strrpos($d, '@') + 1);
    }
    // Reuse domain validation rules from bootstrap.
    return spectr_normalize_domain($d);
}

function mailsec_txt(string $host): array {
    set_error_handler(static function () {});
    $records = dns_get_record($host, DNS_TXT);
    restore_error_handler();
    if (!is_array($records)) return [];
    $out = [];
    foreach ($records as $r) {
        if (isset($r['txt'])) {
            $out[] = (string)$r['txt'];
        } elseif (isset($r['entries']) && is_array($r['entries'])) {
            $out[] = implode('', $r['entries']);
        }
    }
    return $out;
}

// ---- SPF ----
function mailsec_spf(string $domain): array {
    $records = mailsec_txt($domain);
    $spf = null;
    foreach ($records as $r) {
        if (stripos($r, 'v=spf1') === 0) { $spf = $r; break; }
    }
    if ($spf === null) {
        return [
            'present' => false, 'record' => null, 'mechanisms' => [],
            'qualifier_all' => null, 'risk' => 'missing', 'raw' => $records,
        ];
    }

    $tokens = preg_split('/\s+/', trim($spf));
    array_shift($tokens); // drop "v=spf1"
    $mechanisms   = [];
    $qualifierAll = null;
    foreach ($tokens as $t) {
        if ($t === '') continue;
        $first = $t[0];
        $qualifier = '+';
        $name = $t;
        if (in_array($first, ['+', '-', '~', '?'], true)) {
            $qualifier = $first;
            $name = substr($t, 1);
        }
        if (strcasecmp($name, 'all') === 0) {
            $qualifierAll = $qualifier;
            $mechanisms[] = ['type' => 'all', 'qualifier' => $qualifier, 'value' => null];
            continue;
        }
        $type = $name; $value = null;
        if (strpos($name, ':') !== false) {
            [$type, $value] = explode(':', $name, 2);
        } elseif (strpos($name, '=') !== false) {
            [$type, $value] = explode('=', $name, 2);
        }
        $mechanisms[] = ['type' => strtolower($type), 'qualifier' => $qualifier, 'value' => $value];
    }

    $risk = match ($qualifierAll) {
        '-'     => 'strict',
        '~'     => 'soft',
        '?'     => 'neutral',
        '+'     => 'critical',     // "+all" lets anyone send as your domain
        default => 'no_all',
    };

    return [
        'present'       => true,
        'record'        => $spf,
        'mechanisms'    => $mechanisms,
        'qualifier_all' => $qualifierAll,
        'risk'          => $risk,
        'raw'           => $records,
    ];
}

// ---- DKIM (probe common selectors) ----
function mailsec_dkim(string $domain): array {
    $selectors = [
        'google', 'mail', 'default', 'dkim', 'k1',
        'selector1', 'selector2', 'smtp', 'email',
        'mimecast', 'mailjet', 'sendgrid', 'amazonses',
        'protonmail', 'zoho', 'mailchimp',
    ];
    $found = [];
    foreach ($selectors as $sel) {
        $records = mailsec_txt($sel . '._domainkey.' . $domain);
        foreach ($records as $r) {
            // DKIM TXT typically contains "v=DKIM1" and a "p=" tag with the public key.
            if (stripos($r, 'p=') === false) continue;
            $kv = mailsec_kv_parse($r);
            $p  = $kv['p'] ?? '';
            $found[] = [
                'selector'         => $sel,
                'host'             => $sel . '._domainkey.' . $domain,
                'record_truncated' => mb_substr($r, 0, 200),
                'v'                => $kv['v'] ?? null,
                'k'                => $kv['k'] ?? null,
                's'                => $kv['s'] ?? null,
                'p_preview'        => $p === '' ? null : (mb_substr($p, 0, 40) . (mb_strlen($p) > 40 ? '…' : '')),
                'p_length'         => mb_strlen($p),
            ];
            break;   // one record per selector is enough
        }
    }
    return ['selectors_found' => $found, 'selectors_checked' => $selectors];
}

function mailsec_kv_parse(string $record): array {
    $out = [];
    foreach (preg_split('/;\s*/', $record) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) continue;
        [$k, $v] = explode('=', $part, 2);
        $out[strtolower(trim($k))] = trim($v);
    }
    return $out;
}

// ---- DMARC ----
function mailsec_dmarc(string $domain): array {
    $records = mailsec_txt('_dmarc.' . $domain);
    $rec = null;
    foreach ($records as $r) {
        if (stripos($r, 'v=DMARC1') === 0) { $rec = $r; break; }
    }
    if ($rec === null) {
        return [
            'present' => false, 'record' => null, 'policy' => null,
            'rua' => null, 'ruf' => null, 'subdomain_policy' => null,
            'pct' => null, 'adkim' => null, 'aspf' => null,
            'strength' => 'none', 'raw' => $records,
        ];
    }
    $kv = mailsec_kv_parse($rec);
    $policy = strtolower($kv['p'] ?? '');
    $strength = match ($policy) {
        'reject'     => 'strong',
        'quarantine' => 'medium',
        'none'       => 'weak',
        default      => 'unknown',
    };
    return [
        'present'          => true,
        'record'           => $rec,
        'policy'           => $policy ?: null,
        'rua'              => $kv['rua'] ?? null,
        'ruf'              => $kv['ruf'] ?? null,
        'subdomain_policy' => $kv['sp']  ?? null,
        'pct'              => isset($kv['pct']) ? (int)$kv['pct'] : null,
        'adkim'            => $kv['adkim'] ?? null,
        'aspf'             => $kv['aspf']  ?? null,
        'strength'         => $strength,
        'raw'              => $records,
    ];
}

// ---- MTA-STS / BIMI (presence-only) ----
function mailsec_mtasts(string $domain): array {
    $records = mailsec_txt('_mta-sts.' . $domain);
    $present = false;
    foreach ($records as $r) {
        if (stripos($r, 'v=STSv1') !== false) { $present = true; break; }
    }
    if (!$present && !empty($records)) $present = true; // any TXT under _mta-sts is the policy id record
    return ['present' => $present, 'raw' => $records];
}

function mailsec_bimi(string $domain): array {
    $records = mailsec_txt('default._bimi.' . $domain);
    if (empty($records)) {
        $records = mailsec_txt('_bimi.' . $domain);  // some publishers omit the selector
    }
    $present = false;
    foreach ($records as $r) {
        if (stripos($r, 'v=BIMI1') !== false) { $present = true; break; }
    }
    return ['present' => $present, 'raw' => $records];
}

$domain = mailsec_input();
$spf    = mailsec_spf($domain);
$dkim   = mailsec_dkim($domain);
$dmarc  = mailsec_dmarc($domain);
$mtasts = mailsec_mtasts($domain);
$bimi   = mailsec_bimi($domain);

// ---- Score ----
$score = 0;
if ($spf['present'] && in_array($spf['qualifier_all'], ['-', '~'], true)) $score += 25;
if ($dmarc['present'])                                                   $score += 25;
if ($dmarc['present'] && in_array($dmarc['policy'], ['quarantine', 'reject'], true)) $score += 20;
if (!empty($dkim['selectors_found']))                                    $score += 20;
if ($mtasts['present'])                                                  $score += 10;

$label = $score >= 80 ? 'Excellent'
       : ($score >= 60 ? 'Bon'
       : ($score >= 40 ? 'Moyen' : 'Faible'));

$payload = [
    'domain'      => $domain,
    'spf'         => $spf,
    'dkim'        => $dkim,
    'dmarc'       => $dmarc,
    'mta_sts'     => $mtasts,
    'bimi'        => $bimi,
    'score'       => $score,
    'score_label' => $label,
];

spectr_log_scan($domain, 'mailsec', $score > 0, $payload);
spectr_ok($payload, $domain);

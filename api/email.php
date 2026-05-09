<?php
// /api/email.php — Email OSINT: provider hint + MX check + HIBP breach/paste lookup.

require __DIR__ . '/_bootstrap.php';

function email_input(): string {
    $raw = $_GET['email'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['email'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['email'] ?? null);
    }
    if (!is_string($raw) || $raw === '') {
        spectr_error('Missing "email" parameter.', 422);
    }
    $e = strtolower(trim($raw));
    if (!filter_var($e, FILTER_VALIDATE_EMAIL)) {
        spectr_error('Invalid email address.', 422);
    }
    return $e;
}

function email_provider_hint(string $domain): array {
    $free = [
        'gmail.com'      => 'Gmail',
        'googlemail.com' => 'Gmail',
        'outlook.com'    => 'Outlook',
        'hotmail.com'    => 'Outlook (Hotmail)',
        'live.com'       => 'Outlook (Live)',
        'msn.com'        => 'Outlook (MSN)',
        'yahoo.com'      => 'Yahoo',
        'yahoo.fr'       => 'Yahoo FR',
        'ymail.com'      => 'Yahoo',
        'aol.com'        => 'AOL',
        'icloud.com'     => 'iCloud',
        'me.com'         => 'iCloud (me)',
        'mac.com'        => 'iCloud (mac)',
        'protonmail.com' => 'Proton Mail',
        'proton.me'      => 'Proton Mail',
        'pm.me'          => 'Proton Mail',
        'tutanota.com'   => 'Tutanota',
        'tuta.io'        => 'Tutanota',
        'gmx.com'        => 'GMX',
        'gmx.net'        => 'GMX',
        'gmx.de'         => 'GMX',
        'mail.com'       => 'Mail.com',
        'zoho.com'       => 'Zoho',
        'fastmail.com'   => 'Fastmail',
        'orange.fr'      => 'Orange',
        'wanadoo.fr'     => 'Orange (Wanadoo)',
        'free.fr'        => 'Free.fr',
        'sfr.fr'         => 'SFR',
        'laposte.net'    => 'La Poste',
    ];
    if (isset($free[$domain])) {
        return ['provider' => $free[$domain], 'is_free_provider' => true];
    }
    return ['provider' => null, 'is_free_provider' => false];
}

function email_mx(string $domain): array {
    set_error_handler(static function () {});
    $records = dns_get_record($domain, DNS_MX);
    restore_error_handler();
    if (!is_array($records)) return [];
    $out = [];
    foreach ($records as $r) {
        if (!empty($r['target'])) {
            $out[] = ['target' => $r['target'], 'pri' => $r['pri'] ?? null];
        }
    }
    usort($out, static fn($a, $b) => ($a['pri'] ?? 0) <=> ($b['pri'] ?? 0));
    return $out;
}

function hibp_get(string $url, string $apiKey): array {
    $cfg = spectr_config()['http'];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $cfg['timeout'],
        CURLOPT_USERAGENT      => $cfg['user_agent'],
        CURLOPT_HTTPHEADER     => [
            'Accept: application/json',
            'hibp-api-key: ' . $apiKey,
        ],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $body   = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err    = curl_error($ch);
    curl_close($ch);
    return ['status' => $status, 'body' => $body, 'error' => $err];
}

$email = email_input();
[$local, $domain] = explode('@', $email, 2);

$providerInfo = email_provider_hint($domain);
$mx           = email_mx($domain);

$payload = [
    'email'            => $email,
    'local'            => $local,
    'domain'           => $domain,
    'provider'         => $providerInfo['provider'],
    'is_free_provider' => $providerInfo['is_free_provider'],
    'mx_records'       => $mx,
    'has_mx'           => !empty($mx),
    'breaches'         => [],
    'pastes'           => [],
    'breach_count'     => 0,
    'paste_count'      => 0,
    'is_compromised'   => false,
    'hibp_skipped'     => false,
    'hibp_warning'     => null,
];

$apiKey = spectr_config()['hibp_api_key'] ?? '';

if ($apiKey === '') {
    $payload['hibp_skipped'] = true;
    $payload['hibp_warning'] = 'No HIBP API key configured — breach lookup skipped. Set hibp_api_key in config.';
    spectr_log_scan($domain, 'email', true, $payload);
    spectr_ok($payload, $domain);
}

// Breachedaccount: ?truncateResponse=false returns full breach objects.
$breachUrl = 'https://haveibeenpwned.com/api/v3/breachedaccount/' . rawurlencode($email) . '?truncateResponse=false';
$br        = hibp_get($breachUrl, $apiKey);

if ($br['status'] === 401) {
    spectr_error('HIBP rejected the API key (401). Check hibp_api_key in config.', 401);
}
if ($br['status'] === 429) {
    spectr_error('HIBP rate limit hit (429). Slow down or wait for reset.', 429);
}
if ($br['status'] !== 200 && $br['status'] !== 404) {
    spectr_error('HIBP request failed.', 502, ['http_status' => $br['status'], 'curl_error' => $br['error']]);
}

if ($br['status'] === 200 && $br['body']) {
    $items = json_decode($br['body'], true);
    if (is_array($items)) {
        foreach ($items as $b) {
            $payload['breaches'][] = [
                'name'         => $b['Name']         ?? null,
                'title'        => $b['Title']        ?? null,
                'date'         => $b['BreachDate']   ?? null,
                'pwn_count'    => $b['PwnCount']     ?? null,
                'data_classes' => $b['DataClasses']  ?? [],
                'is_verified'  => $b['IsVerified']   ?? null,
                'is_fabricated'=> $b['IsFabricated'] ?? null,
                'is_sensitive' => $b['IsSensitive']  ?? null,
                'description'  => isset($b['Description']) ? strip_tags((string)$b['Description']) : null,
            ];
        }
        usort($payload['breaches'], static fn($a, $b) => strcmp((string)($b['date'] ?? ''), (string)($a['date'] ?? '')));
    }
}

$pasteUrl = 'https://haveibeenpwned.com/api/v3/pasteaccount/' . rawurlencode($email);
$pa       = hibp_get($pasteUrl, $apiKey);

if ($pa['status'] === 200 && $pa['body']) {
    $items = json_decode($pa['body'], true);
    if (is_array($items)) {
        foreach ($items as $p) {
            $payload['pastes'][] = [
                'source'     => $p['Source']     ?? null,
                'id'         => $p['Id']         ?? null,
                'title'      => $p['Title']      ?? null,
                'date'       => $p['Date']       ?? null,
                'email_count'=> $p['EmailCount'] ?? null,
            ];
        }
    }
}
// 404 on either endpoint just means no exposure — leave the empty arrays in place.

$payload['breach_count']   = count($payload['breaches']);
$payload['paste_count']    = count($payload['pastes']);
$payload['is_compromised'] = $payload['breach_count'] > 0 || $payload['paste_count'] > 0;

spectr_log_scan($domain, 'email', true, $payload);
spectr_ok($payload, $domain);

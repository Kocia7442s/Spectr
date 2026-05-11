<?php
// /api/emailrep.php — Email reputation aggregator (no external dependency on EmailRep).
// Synthesizes a reputation profile from MX + SPF + DMARC + DKIM + HIBP + Gravatar.

require __DIR__ . '/_bootstrap.php';

function emailrep_input(): string {
    $raw = $_GET['email'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['email'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['email'] ?? null);
    }
    if (!is_string($raw) || $raw === '') spectr_error('Missing "email" parameter.', 422);
    $e = strtolower(trim($raw));
    if (!filter_var($e, FILTER_VALIDATE_EMAIL)) spectr_error('Invalid email address.', 422);
    return $e;
}

// ---- Static lists ----

function emailrep_disposable(): array {
    // Common disposable email domains. Not exhaustive — extend as needed.
    return array_flip([
        '10minutemail.com', '10minutemail.net', '20minutemail.com',
        'mailinator.com', 'mailinator.net', 'mailinator.org',
        'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz',
        'sharklasers.com', 'grr.la',
        'tempmail.com', 'tempmail.net', 'tempmailo.com', 'tmpeml.com', 'tempemails.com',
        'temp-mail.org', 'temp-mail.io',
        'yopmail.com', 'yopmail.net',
        'throwaway.email', 'throwawaymail.com', 'trashmail.com', 'trashmail.de', 'trbvm.com',
        'dispostable.com', 'getnada.com', 'maildrop.cc', 'mailcatch.com', 'mailnesia.com',
        'fakeinbox.com', 'fakemail.net', 'emailondeck.com', 'emailfake.com',
        'mintemail.com', 'mohmal.com', 'harakirimail.com', 'einrot.com', 'anonbox.net',
        'spamgourmet.com', 'spambog.com', 'jetable.org', 'deadaddress.com', 'no-spam.ws',
        'mailsac.com', 'dropmail.me', 'tempr.email', 'getmymail.com', 'smailpro.com',
        'vusra.com', 'gufum.com', 'fexbox.org', 'wegwerfemail.de', 'inboxbear.com',
        'mail-temp.com', 'tempinbox.com', 'getairmail.com', 'tmail.com', 'mfsa.ru',
    ]);
}

function emailrep_free_providers(): array {
    return array_flip([
        'gmail.com', 'googlemail.com',
        'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.fr',
        'yahoo.com', 'yahoo.fr', 'ymail.com',
        'aol.com', 'icloud.com', 'me.com', 'mac.com',
        'protonmail.com', 'proton.me', 'pm.me',
        'tutanota.com', 'tuta.io', 'gmx.com', 'gmx.net', 'gmx.de', 'mail.com',
        'zoho.com', 'fastmail.com',
        'orange.fr', 'wanadoo.fr', 'free.fr', 'sfr.fr', 'laposte.net',
    ]);
}

// ---- DNS helpers ----

function emailrep_dns(string $host, int $type): array {
    set_error_handler(static function () {});
    $r = dns_get_record($host, $type);
    restore_error_handler();
    return is_array($r) ? $r : [];
}

function emailrep_txt(string $host): array {
    $out = [];
    foreach (emailrep_dns($host, DNS_TXT) as $r) {
        if (isset($r['txt'])) $out[] = (string)$r['txt'];
        elseif (isset($r['entries']) && is_array($r['entries'])) $out[] = implode('', $r['entries']);
    }
    return $out;
}

// ---- SPF / DMARC / DKIM ----

function emailrep_spf(string $domain): array {
    $records = emailrep_txt($domain);
    foreach ($records as $r) {
        if (stripos($r, 'v=spf1') !== 0) continue;
        $rt = trim($r);
        $strict   = (bool)preg_match('/(?:^|\s)-all\b/i', $rt);
        $soft     = (bool)preg_match('/(?:^|\s)~all\b/i', $rt);
        $critical = (bool)preg_match('/(?:^|\s)\+all\b/i', $rt);
        return [
            'present'  => true,
            'strict'   => $strict,
            'soft'     => $soft,
            'critical' => $critical,    // +all = anyone can send as you
            'record'   => $rt,
        ];
    }
    return ['present' => false, 'strict' => false, 'soft' => false, 'critical' => false, 'record' => null];
}

function emailrep_dmarc(string $domain): array {
    foreach (emailrep_txt('_dmarc.' . $domain) as $r) {
        if (stripos($r, 'v=DMARC1') !== 0) continue;
        $kv = [];
        foreach (preg_split('/;\s*/', $r) as $part) {
            if (strpos($part, '=') === false) continue;
            [$k, $v] = explode('=', $part, 2);
            $kv[strtolower(trim($k))] = trim($v);
        }
        $policy = strtolower($kv['p'] ?? '');
        return [
            'present'  => true,
            'policy'   => $policy ?: null,
            'enforced' => in_array($policy, ['quarantine', 'reject'], true),
            'record'   => $r,
        ];
    }
    return ['present' => false, 'policy' => null, 'enforced' => false, 'record' => null];
}

function emailrep_dkim(string $domain): array {
    $selectors = ['google', 'mail', 'default', 'dkim', 'k1', 'selector1', 'selector2', 'smtp'];
    foreach ($selectors as $sel) {
        foreach (emailrep_txt($sel . '._domainkey.' . $domain) as $r) {
            if (stripos($r, 'p=') !== false) {
                return ['found' => true, 'selector' => $sel];
            }
        }
    }
    return ['found' => false, 'selector' => null];
}

// ---- HIBP (reuse same approach as email.php) ----

function emailrep_hibp(string $email, string $apiKey): array {
    if ($apiKey === '') return ['skipped' => true, 'reason' => 'no_key'];
    $cfg = spectr_config()['http'];
    $ch = curl_init('https://haveibeenpwned.com/api/v3/breachedaccount/' . rawurlencode($email) . '?truncateResponse=true');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $cfg['timeout'],
        CURLOPT_USERAGENT      => $cfg['user_agent'],
        CURLOPT_HTTPHEADER     => ['Accept: application/json', 'hibp-api-key: ' . $apiKey],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code === 401) return ['skipped' => true, 'reason' => 'bad_key'];
    if ($code === 429) return ['skipped' => true, 'reason' => 'rate_limited'];
    if ($code === 404) return ['breach_count' => 0, 'breaches' => []];
    if ($code !== 200 || !$body) return ['skipped' => true, 'reason' => 'http_' . $code];

    $items = json_decode($body, true);
    if (!is_array($items)) return ['skipped' => true, 'reason' => 'bad_json'];
    $names = array_map(static fn($b) => $b['Name'] ?? null, $items);
    $names = array_values(array_filter($names));
    return ['breach_count' => count($names), 'breaches' => $names];
}

// ---- Gravatar — produces the "profiles" payload with real usernames ----

function emailrep_gravatar(string $email): array {
    $hash = md5(strtolower(trim($email)));
    $res  = spectr_http_get('https://www.gravatar.com/' . $hash . '.json', ['Accept: application/json']);
    if ($res['status'] !== 200 || !$res['body']) {
        return ['has_account' => false, 'profiles' => [], 'name' => null, 'username' => null, 'hash' => $hash];
    }
    $j = json_decode($res['body'], true);
    if (!is_array($j) || empty($j['entry'][0])) {
        return ['has_account' => false, 'profiles' => [], 'name' => null, 'username' => null, 'hash' => $hash];
    }
    $entry = $j['entry'][0];
    $profiles = [];
    foreach (($entry['accounts'] ?? []) as $a) {
        $platform = $a['shortname'] ?? ($a['domain'] ?? null);
        if (!$platform) continue;
        $profiles[] = [
            'platform' => $platform,
            'username' => $a['username'] ?? null,
            'url'      => $a['url']      ?? null,
            'verified' => $a['verified'] ?? null,
        ];
    }
    return [
        'has_account' => true,
        'profiles'    => $profiles,
        'name'        => $entry['displayName']       ?? null,
        'username'    => $entry['preferredUsername'] ?? null,
        'profile_url' => $entry['profileUrl']        ?? null,
        'hash'        => $hash,
    ];
}

// ---- Main ----

$email           = emailrep_input();
[$local, $domain] = explode('@', $email, 2);

$mxRecords    = emailrep_dns($domain, DNS_MX);
$validMx      = !empty($mxRecords);
$primaryMx    = $validMx ? ($mxRecords[0]['target'] ?? null) : null;

$disposable     = emailrep_disposable();
$freeProviders  = emailrep_free_providers();
$isDisposable   = isset($disposable[$domain]);
$isFreeProvider = isset($freeProviders[$domain]);

$spf      = emailrep_spf($domain);
$dmarc    = emailrep_dmarc($domain);
$dkim     = emailrep_dkim($domain);

$spoofable = !$spf['strict'] || !$dmarc['enforced'];

$hibpKey  = spectr_config()['hibp_api_key'] ?? '';
$hibp     = emailrep_hibp($email, $hibpKey);
$breached = isset($hibp['breach_count']) && $hibp['breach_count'] > 0;

$gravatar = emailrep_gravatar($email);

// ---- Score (0-100) ----
$score = 0;
if ($validMx)                    $score += 15;
if (!$isDisposable)              $score += 15;
if ($spf['strict'])              $score += 15;
elseif ($spf['soft'])            $score += 8;
if ($dmarc['enforced'])          $score += 15;
elseif ($dmarc['present'])       $score += 5;
if ($dkim['found'])              $score += 10;
if (isset($hibp['breach_count']) && $hibp['breach_count'] === 0) $score += 20;
if ($gravatar['has_account'])    $score += 10;
// Penalties
if ($spf['critical'])            $score -= 30;     // +all is dangerous
if ($isDisposable)               $score -= 30;
if ($breached)                   $score -= max(5, min(20, ($hibp['breach_count'] ?? 0) * 2));
$score = max(0, min(100, $score));

$reputation = $score >= 80 ? 'high' : ($score >= 60 ? 'medium' : ($score >= 40 ? 'low' : 'none'));
$suspicious = $isDisposable || $spf['critical'] || !$validMx;

$payload = [
    'email'            => $email,
    'domain'           => $domain,
    'reputation'       => $reputation,
    'reputation_score' => $score,
    'suspicious'       => $suspicious,
    'references'       => null,                  // not derivable natively

    'flags' => [
        'data_breach'         => $breached,
        'credentials_leaked'  => $breached,       // same source as data_breach (HIBP) — kept for renderer compat
        'malicious_activity'  => null,
        'malicious_recent'    => null,
        'blacklisted'         => null,
        'spam'                => null,
        'disposable'          => $isDisposable,
        'free_provider'       => $isFreeProvider,
        'deliverable'         => $validMx,
        'accept_all'          => null,
        'spoofable'           => $spoofable,
        'valid_mx'            => $validMx,
        'spf_strict'          => $spf['strict'],
        'dmarc_enforced'      => $dmarc['enforced'],
    ],

    'timeline' => ['first_seen' => null, 'last_seen' => null],

    'domain_stats' => [
        'domain_exists'             => $validMx,
        'domain_reputation'         => null,
        'new_domain'                => null,
        'days_since_domain_creation'=> null,
        'suspicious_tld'            => null,
        'primary_mx'                => $primaryMx,
    ],

    // Upgraded shape: each profile has platform + url + username (when known).
    'profiles'       => $gravatar['profiles'],

    // Extra context the new aggregator can surface.
    'breaches'       => $hibp['breaches'] ?? [],
    'breach_count'   => $hibp['breach_count'] ?? null,
    'hibp_skipped'   => isset($hibp['skipped']) ? true : false,
    'hibp_reason'    => $hibp['reason'] ?? null,
    'gravatar_name'  => $gravatar['name'],
    'gravatar_username' => $gravatar['username'],

    'source' => 'spectr-native',
];

spectr_log_scan($domain, 'emailrep', !empty($reputation), $payload);
spectr_ok($payload, $domain);

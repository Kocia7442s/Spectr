<?php
// /api/gravatar.php — Gravatar profile + avatar lookup by email MD5.

require __DIR__ . '/_bootstrap.php';

function gravatar_input(): string {
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

function gravatar_head(string $url): int {
    $cfg = spectr_config()['http'];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY         => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_TIMEOUT        => $cfg['timeout'],
        CURLOPT_USERAGENT      => $cfg['user_agent'],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $code;
}

$email  = gravatar_input();
$domain = explode('@', $email, 2)[1];
$hash   = md5($email);

$avatarBase = 'https://www.gravatar.com/avatar/' . $hash;
$avatarUrls = [
    'small'  => $avatarBase . '?s=80&d=404',
    'medium' => $avatarBase . '?s=200&d=404',
    'large'  => $avatarBase . '?s=400&d=404',
];

// Profile lookup.
$profileRes = spectr_http_get('https://www.gravatar.com/' . $hash . '.json', ['Accept: application/json']);
$hasAccount = false;
$profile    = null;

if ($profileRes['status'] === 200 && $profileRes['body']) {
    $j = json_decode($profileRes['body'], true);
    if (is_array($j) && !empty($j['entry'][0])) {
        $hasAccount = true;
        $entry = $j['entry'][0];

        $emails = [];
        foreach (($entry['emails'] ?? []) as $row) {
            if (!empty($row['value'])) $emails[] = $row['value'];
        }
        $urls = [];
        foreach (($entry['urls'] ?? []) as $row) {
            $urls[] = ['title' => $row['title'] ?? null, 'value' => $row['value'] ?? null];
        }
        $accounts = [];
        foreach (($entry['accounts'] ?? []) as $row) {
            $accounts[] = [
                'domain'    => $row['domain']    ?? null,
                'shortname' => $row['shortname'] ?? null,
                'username'  => $row['username']  ?? null,
                'url'       => $row['url']       ?? null,
                'verified'  => $row['verified']  ?? null,
            ];
        }
        $photos = [];
        foreach (($entry['photos'] ?? []) as $row) {
            $photos[] = ['type' => $row['type'] ?? null, 'value' => $row['value'] ?? null];
        }

        $profile = [
            'displayName'       => $entry['displayName']       ?? null,
            'preferredUsername' => $entry['preferredUsername'] ?? null,
            'profileUrl'        => $entry['profileUrl']        ?? null,
            'aboutMe'           => $entry['aboutMe']           ?? null,
            'currentLocation'   => $entry['currentLocation']   ?? null,
            'jobTitle'          => $entry['job_title']         ?? ($entry['jobTitle'] ?? null),
            'company'           => $entry['company']           ?? null,
            'pronouns'          => $entry['pronouns']          ?? null,
            'emails'            => $emails,
            'urls'              => $urls,
            'accounts'          => $accounts,
            'photos'            => $photos,
        ];
    }
}

// Avatar existence (200 = exists, 404 = none because of d=404).
$avatarCode = gravatar_head($avatarUrls['medium']);
$hasAvatar  = $avatarCode === 200;

$payload = [
    'email'        => $email,
    'hash'         => $hash,
    'has_account'  => $hasAccount,
    'has_avatar'   => $hasAvatar,
    'avatar_http'  => $avatarCode,
    'avatar_urls'  => $avatarUrls,
    'profile'      => $profile,
    'profile_url'  => 'https://www.gravatar.com/' . $hash,
];

spectr_log_scan($domain, 'gravatar', $hasAccount, $payload);
spectr_ok($payload, $domain);

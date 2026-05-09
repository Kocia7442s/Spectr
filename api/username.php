<?php
// /api/username.php — Parallel username availability check across ~20 platforms.

require __DIR__ . '/_bootstrap.php';

function username_input(): string {
    $raw = $_GET['username'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['username'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['username'] ?? null);
    }
    if (!is_string($raw) || $raw === '') {
        spectr_error('Missing "username" parameter.', 422);
    }
    $u = trim($raw);
    if (!preg_match('/^[A-Za-z0-9._-]{3,30}$/', $u)) {
        spectr_error('Username must be 3-30 chars, alphanumeric plus . _ -.', 422);
    }
    return $u;
}

$username = username_input();

$platforms = [
    'GitHub'     => ['url' => 'https://github.com/{username}',                  'not_found' => 404],
    'GitLab'     => ['url' => 'https://gitlab.com/{username}',                  'not_found' => 404],
    'Twitter/X'  => ['url' => 'https://x.com/{username}',                       'not_found' => 404],
    'Instagram'  => ['url' => 'https://www.instagram.com/{username}/',           'not_found' => 404],
    'TikTok'     => ['url' => 'https://www.tiktok.com/@{username}',              'not_found' => 404],
    'Reddit'     => ['url' => 'https://www.reddit.com/user/{username}',          'not_found' => 404],
    'Pinterest'  => ['url' => 'https://www.pinterest.com/{username}/',           'not_found' => 404],
    'Twitch'     => ['url' => 'https://www.twitch.tv/{username}',                'not_found' => 404],
    'YouTube'    => ['url' => 'https://www.youtube.com/@{username}',             'not_found' => 404],
    'LinkedIn'   => ['url' => 'https://www.linkedin.com/in/{username}',          'not_found' => 404],
    'Snapchat'   => ['url' => 'https://www.snapchat.com/add/{username}',         'not_found' => 404],
    'Tumblr'     => ['url' => 'https://{username}.tumblr.com',                   'not_found' => 404],
    'Medium'     => ['url' => 'https://medium.com/@{username}',                  'not_found' => 404],
    'DevTo'      => ['url' => 'https://dev.to/{username}',                       'not_found' => 404],
    'HackerNews' => ['url' => 'https://news.ycombinator.com/user?id={username}', 'not_found' => 404],
    'Steam'      => ['url' => 'https://steamcommunity.com/id/{username}',        'not_found' => 404],
    'Keybase'    => ['url' => 'https://keybase.io/{username}',                   'not_found' => 404],
    'Pastebin'   => ['url' => 'https://pastebin.com/u/{username}',               'not_found' => 404],
    'Gravatar'   => ['url' => 'https://en.gravatar.com/{username}',              'not_found' => 404],
    'Flickr'     => ['url' => 'https://www.flickr.com/people/{username}',        'not_found' => 404],
];

$BROWSER_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36';

$multi   = curl_multi_init();
$handles = [];
$started = microtime(true);

foreach ($platforms as $name => $cfg) {
    $url = str_replace('{username}', urlencode($username), $cfg['url']);
    $ch  = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY         => true,           // HEAD first; some sites disallow it but many will reply with the right status
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 4,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_USERAGENT      => $BROWSER_UA,
        CURLOPT_SSL_VERIFYPEER => false,           // tolerant: some platforms have flaky chains
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_HTTPHEADER     => [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.5',
        ],
    ]);
    curl_multi_add_handle($multi, $ch);
    $handles[$name] = ['ch' => $ch, 'url' => $url, 'cfg' => $cfg];
}

// Run all transfers in parallel.
do {
    $status = curl_multi_exec($multi, $running);
    if ($running > 0) {
        curl_multi_select($multi, 1.0);
    }
} while ($running > 0 && $status === CURLM_OK);

$results = [];
foreach ($handles as $name => $h) {
    $ch    = $h['ch'];
    $code  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err   = curl_error($ch);
    $time  = (int)round(((float)curl_getinfo($ch, CURLINFO_TOTAL_TIME)) * 1000);

    $status = 'unknown';
    if ($err !== '' || $code === 0) {
        $status = 'error';
    } elseif ($code === 200) {
        $status = 'found';
    } elseif ($code === $h['cfg']['not_found']) {
        $status = 'not_found';
    } elseif ($code === 410 || $code === 451) {
        $status = 'not_found';
    }

    $results[] = [
        'platform'         => $name,
        'url'              => $h['url'],
        'http_code'        => $code,
        'status'           => $status,
        'response_time_ms' => $time,
        'error'            => $err !== '' ? $err : null,
    ];

    curl_multi_remove_handle($multi, $ch);
    curl_close($ch);
}
curl_multi_close($multi);

$duration_ms = (int)round((microtime(true) - $started) * 1000);

$bucket = ['found' => [], 'not_found' => [], 'unknown' => [], 'errors' => []];
foreach ($results as $r) {
    if ($r['status'] === 'found')        $bucket['found'][]      = ['platform' => $r['platform'], 'url' => $r['url'], 'http_code' => $r['http_code'], 'response_time_ms' => $r['response_time_ms']];
    elseif ($r['status'] === 'not_found') $bucket['not_found'][] = ['platform' => $r['platform'], 'http_code' => $r['http_code']];
    elseif ($r['status'] === 'error')     $bucket['errors'][]    = ['platform' => $r['platform'], 'error' => $r['error'], 'http_code' => $r['http_code']];
    else                                  $bucket['unknown'][]   = ['platform' => $r['platform'], 'url' => $r['url'], 'http_code' => $r['http_code']];
}

$payload = [
    'username'      => $username,
    'found'         => $bucket['found'],
    'unknown'       => $bucket['unknown'],
    'not_found'     => $bucket['not_found'],
    'errors'        => $bucket['errors'],
    'found_count'   => count($bucket['found']),
    'unknown_count' => count($bucket['unknown']),
    'not_found_count' => count($bucket['not_found']),
    'error_count'   => count($bucket['errors']),
    'total_checked' => count($results),
    'duration_ms'   => $duration_ms,
];

spectr_log_scan($username, 'username', true, $payload);
spectr_ok($payload, $username);

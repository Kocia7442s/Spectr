<?php
// /api/github.php — GitHub profile / repos / orgs / commit-email deep scan (unauthenticated, 60 req/h).

require __DIR__ . '/_bootstrap.php';

function github_input(): string {
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

// Custom GET that captures headers — spectr_http_get doesn't expose X-RateLimit-Remaining.
function github_get(string $url): array {
    $cfg = spectr_config()['http'];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_TIMEOUT        => $cfg['timeout'],
        CURLOPT_USERAGENT      => $cfg['user_agent'],
        CURLOPT_HTTPHEADER     => [
            'Accept: application/vnd.github.v3+json',
            'X-GitHub-Api-Version: 2022-11-28',
        ],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $raw     = curl_exec($ch);
    $info    = curl_getinfo($ch);
    $err     = curl_error($ch);
    $hdrSize = $info['header_size'] ?? 0;
    curl_close($ch);

    if ($raw === false) {
        return ['status' => 0, 'body' => null, 'error' => $err, 'headers' => []];
    }

    $headerBlob = substr($raw, 0, $hdrSize);
    $body       = substr($raw, $hdrSize);
    $sections   = preg_split("/\r?\n\r?\n/", trim($headerBlob));
    $finalSec   = end($sections);
    $headers = [];
    foreach (preg_split("/\r?\n/", $finalSec) as $line) {
        if (strpos($line, ':') === false) continue;
        [$k, $v] = explode(':', $line, 2);
        $headers[strtolower(trim($k))] = trim($v);
    }
    return [
        'status'  => (int)($info['http_code'] ?? 0),
        'body'    => $body,
        'error'   => $err,
        'headers' => $headers,
    ];
}

function github_check_rate_limit(array $res): void {
    if (in_array($res['status'], [403, 429], true)) {
        $remaining = $res['headers']['x-ratelimit-remaining'] ?? null;
        $reset     = $res['headers']['x-ratelimit-reset']     ?? null;
        $resetHum  = $reset !== null ? gmdate('Y-m-d H:i:s', (int)$reset) . ' UTC' : 'unknown';
        $msg = 'GitHub rate limit hit (HTTP ' . $res['status'] . ').';
        if ($remaining !== null) $msg .= ' Remaining: ' . $remaining . '.';
        $msg .= ' Resets at: ' . $resetHum . '.';
        spectr_error($msg, 429, [
            'x_ratelimit_remaining' => $remaining,
            'x_ratelimit_reset'     => $reset,
        ]);
    }
}

$username = github_input();

// 1. Profile
$res = github_get('https://api.github.com/users/' . urlencode($username));
github_check_rate_limit($res);
if ($res['status'] === 404) {
    spectr_error('GitHub user "' . $username . '" not found.', 404);
}
if ($res['status'] !== 200 || !$res['body']) {
    spectr_error('GitHub profile request failed (HTTP ' . $res['status'] . ').', 502);
}
$user = json_decode($res['body'], true);
if (!is_array($user)) {
    spectr_error('GitHub returned non-JSON payload.', 502);
}

$profile = [
    'login'            => $user['login']            ?? $username,
    'name'             => $user['name']             ?? null,
    'bio'              => $user['bio']              ?? null,
    'company'          => $user['company']          ?? null,
    'location'         => $user['location']         ?? null,
    'email'            => $user['email']            ?? null,
    'blog'             => $user['blog']             ?? null,
    'twitter_username' => $user['twitter_username'] ?? null,
    'public_repos'     => $user['public_repos']     ?? 0,
    'public_gists'     => $user['public_gists']     ?? 0,
    'followers'        => $user['followers']        ?? 0,
    'following'        => $user['following']        ?? 0,
    'created_at'       => $user['created_at']       ?? null,
    'updated_at'       => $user['updated_at']       ?? null,
    'avatar_url'       => $user['avatar_url']       ?? null,
    'html_url'         => $user['html_url']         ?? null,
    'hireable'         => $user['hireable']         ?? null,
];

// 2. Repos
$res = github_get('https://api.github.com/users/' . urlencode($username) . '/repos?sort=updated&per_page=30&type=public');
github_check_rate_limit($res);
$repos = [];
$languages = [];
if ($res['status'] === 200 && $res['body']) {
    $items = json_decode($res['body'], true);
    if (is_array($items)) {
        foreach ($items as $r) {
            $repos[] = [
                'name'             => $r['name']             ?? null,
                'full_name'        => $r['full_name']        ?? null,
                'description'      => $r['description']      ?? null,
                'language'         => $r['language']         ?? null,
                'stargazers_count' => $r['stargazers_count'] ?? 0,
                'forks_count'      => $r['forks_count']      ?? 0,
                'updated_at'       => $r['updated_at']       ?? null,
                'pushed_at'        => $r['pushed_at']        ?? null,
                'html_url'         => $r['html_url']         ?? null,
                'topics'           => $r['topics']           ?? [],
                'fork'             => $r['fork']             ?? false,
                'archived'         => $r['archived']         ?? false,
            ];
            if (!empty($r['language'])) {
                $lang = (string)$r['language'];
                $languages[$lang] = ($languages[$lang] ?? 0) + 1;
            }
        }
    }
}
arsort($languages, SORT_NUMERIC);

// 3. Orgs
$res = github_get('https://api.github.com/users/' . urlencode($username) . '/orgs');
github_check_rate_limit($res);
$orgs = [];
if ($res['status'] === 200 && $res['body']) {
    $items = json_decode($res['body'], true);
    if (is_array($items)) {
        foreach ($items as $o) {
            $login = $o['login'] ?? null;
            if (!$login) continue;
            $orgs[] = [
                'login'        => $login,
                'description'  => $o['description'] ?? null,
                'avatar_url'   => $o['avatar_url']  ?? null,
                'html_url'     => 'https://github.com/' . $login,
            ];
        }
    }
}

// 4. Commit-email mining: top 5 most-recently-updated non-fork repos.
$commitEmails = [];
$seenEmails   = [];
$reposToScan  = [];
foreach ($repos as $r) {
    if (!empty($r['fork']) || empty($r['name'])) continue;
    $reposToScan[] = $r['name'];
    if (count($reposToScan) >= 5) break;
}

foreach ($reposToScan as $repoName) {
    $url = 'https://api.github.com/repos/' . urlencode($username) . '/' . urlencode($repoName) . '/commits?per_page=20';
    $cr  = github_get($url);
    if (in_array($cr['status'], [403, 429], true)) {
        // Don't kill the whole scan over rate limit on commits — surface it in the payload.
        $commitsRateLimited = true;
        break;
    }
    if ($cr['status'] !== 200 || !$cr['body']) continue;
    $commits = json_decode($cr['body'], true);
    if (!is_array($commits)) continue;
    foreach ($commits as $c) {
        foreach (['author', 'committer'] as $role) {
            $person = $c['commit'][$role] ?? null;
            if (!is_array($person)) continue;
            $email = $person['email'] ?? null;
            $name  = $person['name']  ?? null;
            if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) continue;
            $key = strtolower($email);
            if (isset($seenEmails[$key])) continue;
            $seenEmails[$key] = true;
            $isNoreply = (bool)preg_match('/@users\.noreply\.github\.com$/i', $email);
            $commitEmails[] = [
                'email'      => $email,
                'name'       => $name,
                'is_noreply' => $isNoreply,
                'first_repo' => $repoName,
            ];
        }
    }
}

$rateRemaining = isset($res['headers']['x-ratelimit-remaining'])
    ? (int)$res['headers']['x-ratelimit-remaining']
    : null;

$payload = [
    'profile'             => $profile,
    'repos'               => $repos,
    'repo_count_returned' => count($repos),
    'languages'           => $languages,                 // sorted by count desc
    'orgs'                => $orgs,
    'commit_emails'       => $commitEmails,
    'commit_email_count'  => count($commitEmails),
    'commits_scanned_repos' => $reposToScan,
    'commits_rate_limited'  => !empty($commitsRateLimited),
    'rate_limit_remaining'  => $rateRemaining,
    'source'              => 'api.github.com',
];

spectr_log_scan($username, 'github', !empty($profile), $payload);
spectr_ok($payload, $username);

<?php
// /api/headers.php — HTTP headers analysis: server, technology hints, security headers audit.

require __DIR__ . '/_bootstrap.php';

$domain = spectr_input_domain();

function fetch_headers(string $url): array {
    $cfg = spectr_config()['http'];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_NOBODY         => false,        // some servers return 405 for HEAD
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => $cfg['timeout'],
        CURLOPT_USERAGENT      => $cfg['user_agent'],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_RANGE          => '0-2047',     // small body sample for tech fingerprint
    ]);
    $raw     = curl_exec($ch);
    $info    = curl_getinfo($ch);
    $err     = curl_error($ch);
    $hdrSize = $info['header_size'] ?? 0;
    curl_close($ch);

    if ($raw === false) {
        return ['ok' => false, 'error' => $err ?: 'request failed'];
    }

    $headerBlob = substr($raw, 0, $hdrSize);
    $body       = substr($raw, $hdrSize);

    // The header blob may contain multiple sections (one per redirect). Keep the last.
    $sections = preg_split("/\r?\n\r?\n/", trim($headerBlob));
    $finalSection = end($sections);
    $lines = preg_split("/\r?\n/", $finalSection);
    $statusLine = array_shift($lines);

    $headers = [];
    foreach ($lines as $line) {
        if (strpos($line, ':') === false) continue;
        [$k, $v] = explode(':', $line, 2);
        $k = strtolower(trim($k));
        $v = trim($v);
        $headers[$k] = isset($headers[$k]) ? $headers[$k] . ', ' . $v : $v;
    }

    return [
        'ok'          => true,
        'status_line' => $statusLine,
        'http_code'   => (int)($info['http_code'] ?? 0),
        'final_url'   => $info['url']             ?? $url,
        'redirects'   => (int)($info['redirect_count'] ?? 0),
        'total_time'  => round((float)($info['total_time'] ?? 0), 3),
        'headers'     => $headers,
        'body_sample' => $body,
    ];
}

function detect_technologies(array $headers, string $body): array {
    $tech = [];

    if (!empty($headers['server']))           $tech[] = 'Server: ' . $headers['server'];
    if (!empty($headers['x-powered-by']))     $tech[] = 'Powered by: ' . $headers['x-powered-by'];
    if (!empty($headers['x-aspnet-version'])) $tech[] = 'ASP.NET ' . $headers['x-aspnet-version'];
    if (!empty($headers['x-generator']))      $tech[] = 'Generator: ' . $headers['x-generator'];
    if (!empty($headers['x-drupal-cache']))   $tech[] = 'Drupal';
    if (!empty($headers['cf-ray']))           $tech[] = 'Cloudflare';
    if (!empty($headers['x-amz-cf-id']))      $tech[] = 'AWS CloudFront';
    if (!empty($headers['x-vercel-id']))      $tech[] = 'Vercel';
    if (!empty($headers['x-fastly-request-id']) || (!empty($headers['via']) && stripos($headers['via'], 'varnish') !== false))
        $tech[] = 'Fastly/Varnish';
    if (!empty($headers['x-shopify-stage']))  $tech[] = 'Shopify';
    if (!empty($headers['x-github-request-id'])) $tech[] = 'GitHub Pages';

    if ($body !== '') {
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']/i', $body, $m)) {
            $tech[] = 'Generator (meta): ' . $m[1];
        }
        if (stripos($body, 'wp-content') !== false) $tech[] = 'WordPress (body hint)';
        if (stripos($body, '/_next/')   !== false) $tech[] = 'Next.js (body hint)';
        if (stripos($body, 'gatsby')    !== false) $tech[] = 'Gatsby (body hint)';
    }

    return array_values(array_unique($tech));
}

function audit_security_headers(array $headers): array {
    $checks = [
        'strict-transport-security' => ['label' => 'HSTS',                       'recommendation' => 'max-age=31536000; includeSubDomains'],
        'content-security-policy'   => ['label' => 'Content-Security-Policy',   'recommendation' => 'restrict default-src and script-src'],
        'x-frame-options'           => ['label' => 'X-Frame-Options',           'recommendation' => 'DENY or SAMEORIGIN'],
        'x-content-type-options'    => ['label' => 'X-Content-Type-Options',    'recommendation' => 'nosniff'],
        'referrer-policy'           => ['label' => 'Referrer-Policy',           'recommendation' => 'strict-origin-when-cross-origin'],
        'permissions-policy'        => ['label' => 'Permissions-Policy',        'recommendation' => 'restrict camera/mic/geolocation'],
        'cross-origin-opener-policy'=> ['label' => 'Cross-Origin-Opener-Policy','recommendation' => 'same-origin'],
        'cross-origin-resource-policy' => ['label' => 'Cross-Origin-Resource-Policy', 'recommendation' => 'same-origin'],
    ];

    $out = []; $score = 0; $max = count($checks);
    foreach ($checks as $key => $meta) {
        $present = isset($headers[$key]);
        if ($present) $score++;
        $out[] = [
            'header'         => $key,
            'label'          => $meta['label'],
            'present'        => $present,
            'value'          => $present ? $headers[$key] : null,
            'recommendation' => $meta['recommendation'],
        ];
    }
    return ['checks' => $out, 'score' => $score, 'max' => $max];
}

$attempts = [];
$final    = null;
foreach (['https://' . $domain, 'http://' . $domain] as $url) {
    $r = fetch_headers($url);
    $r['url'] = $url;
    $attempts[] = $r;
    if (!empty($r['ok']) && $r['http_code'] > 0) {
        $final = $r;
        break;
    }
}

if ($final === null) {
    $payload = ['attempts' => $attempts];
    spectr_log_scan($domain, 'headers', false, $payload);
    spectr_error('Could not reach the host over HTTP/HTTPS.', 502, ['attempts' => $attempts]);
}

$security = audit_security_headers($final['headers']);
$tech     = detect_technologies($final['headers'], $final['body_sample'] ?? '');

unset($final['body_sample']);

$payload = [
    'request'       => [
        'url'        => $final['url'],
        'final_url'  => $final['final_url'],
        'http_code'  => $final['http_code'],
        'status'     => $final['status_line'],
        'redirects'  => $final['redirects'],
        'total_time' => $final['total_time'],
    ],
    'headers'       => $final['headers'],
    'technologies'  => $tech,
    'security'      => $security,
];

spectr_log_scan($domain, 'headers', true, $payload);
spectr_ok($payload, $domain);

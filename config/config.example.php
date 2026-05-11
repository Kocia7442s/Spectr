<?php
// Spectr — example configuration. Copy to config.php and fill in your values,
// or set the environment variables listed below.

return [
    'db' => [
        'host'     => getenv('SPECTR_DB_HOST') ?: '127.0.0.1',
        'port'     => getenv('SPECTR_DB_PORT') ?: '5433',
        'name'     => getenv('SPECTR_DB_NAME') ?: 'spectr',
        'user'     => getenv('SPECTR_DB_USER') ?: 'spectr',
        'password' => getenv('SPECTR_DB_PASS') ?: 'spectr',
    ],
    'http' => [
        'user_agent' => 'Spectr-OSINT/1.0 (+research)',
        'timeout'    => 10,
    ],
    // Get one at https://account.shodan.io — free tier is rate-limited.
    'shodan_api_key' => getenv('SPECTR_SHODAN_KEY') ?: '',
    // HaveIBeenPwned API key — purchase at https://haveibeenpwned.com/API (~$4/month).
    // Without a key, /api/email.php skips breach lookup and returns a warning.
    'hibp_api_key'   => getenv('SPECTR_HIBP_KEY') ?: '',
    // numverify API key — register at https://numverify.com (free tier: 100 req/month).
    // Without a key, /api/phone.php returns local parsing only.
    'numverify_api_key' => getenv('SPECTR_NUMVERIFY_KEY') ?: '',
    // EmailRep.io key — register at https://emailrep.io for higher rate limits.
    // Without a key, /api/emailrep.php hits very tight throttling on most IPs.
    'emailrep_api_key'  => getenv('SPECTR_EMAILREP_KEY') ?: '',
];

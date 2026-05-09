<?php
// Spectr — central configuration. Override with environment variables in production.

return [
    'db' => [
        'host'     => getenv('SPECTR_DB_HOST') ?: '127.0.0.1',
        'port'     => getenv('SPECTR_DB_PORT') ?: '5432',
        'name'     => getenv('SPECTR_DB_NAME') ?: 'spectr',
        'user'     => getenv('SPECTR_DB_USER') ?: 'spectr',
        'password' => getenv('SPECTR_DB_PASS') ?: 'spectr',
    ],
    'http' => [
        'user_agent' => 'Spectr-OSINT/1.0 (+research)',
        'timeout'    => 10,
    ],
];

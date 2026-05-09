<?php
// /api/phone.php — Phone number OSINT: country/type detection + search/social links + optional numverify.

require __DIR__ . '/_bootstrap.php';

function phone_input(): array {
    $raw = $_GET['phone'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['phone'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['phone'] ?? null);
    }
    if (!is_string($raw) || trim($raw) === '') {
        spectr_error('Missing "phone" parameter.', 422);
    }

    // Strip everything that isn't a digit, except a single leading +.
    $hasPlus = (substr(ltrim((string)$raw), 0, 1) === '+');
    $digits  = preg_replace('/\D+/', '', $raw);
    if ($digits === '' || strlen($digits) < 7 || strlen($digits) > 15) {
        spectr_error('Phone must be 7-15 digits (E.164 format).', 422);
    }
    return [
        'digits' => $digits,
        'e164'   => '+' . $digits,        // we always normalize to E.164 with leading +
        'raw_had_plus' => $hasPlus,
    ];
}

// Country prefixes, longest-first so multi-digit codes (+352, +358, +420…) match before +1/+3/+4.
function phone_countries(): array {
    return [
        '380' => ['UA', 'Ukraine'],
        '358' => ['FI', 'Finland'],
        '352' => ['LU', 'Luxembourg'],
        '351' => ['PT', 'Portugal'],
        '420' => ['CZ', 'Czech Republic'],
        '254' => ['KE', 'Kenya'],
        '234' => ['NG', 'Nigeria'],
        '91'  => ['IN', 'India'],
        '86'  => ['CN', 'China'],
        '82'  => ['KR', 'South Korea'],
        '81'  => ['JP', 'Japan'],
        '64'  => ['NZ', 'New Zealand'],
        '61'  => ['AU', 'Australia'],
        '55'  => ['BR', 'Brazil'],
        '54'  => ['AR', 'Argentina'],
        '52'  => ['MX', 'Mexico'],
        '49'  => ['DE', 'Germany'],
        '48'  => ['PL', 'Poland'],
        '47'  => ['NO', 'Norway'],
        '46'  => ['SE', 'Sweden'],
        '45'  => ['DK', 'Denmark'],
        '44'  => ['GB', 'United Kingdom'],
        '41'  => ['CH', 'Switzerland'],
        '39'  => ['IT', 'Italy'],
        '36'  => ['HU', 'Hungary'],
        '34'  => ['ES', 'Spain'],
        '33'  => ['FR', 'France'],
        '32'  => ['BE', 'Belgium'],
        '31'  => ['NL', 'Netherlands'],
        '27'  => ['ZA', 'South Africa'],
        '20'  => ['EG', 'Egypt'],
        '7'   => ['RU', 'Russia / Kazakhstan'],
        '1'   => ['US', 'USA / Canada'],
    ];
}

function phone_match_country(string $digits): array {
    foreach (phone_countries() as $prefix => $info) {
        if (strpos($digits, $prefix) === 0) {
            return [
                'prefix'      => '+' . $prefix,
                'country_code'=> $info[0],
                'country_name'=> $info[1],
                'national'    => substr($digits, strlen($prefix)),
            ];
        }
    }
    return ['prefix' => null, 'country_code' => null, 'country_name' => null, 'national' => $digits];
}

function phone_format_local(string $cc, string $national): string {
    if ($national === '') return '';
    switch ($cc) {
        case 'FR':
            // French national starts after +33 — prepend the leading 0 then group by 2.
            $s = '0' . $national;
            return trim(chunk_split($s, 2, ' '));
        case 'US':
        case 'CA':
            if (strlen($national) === 10) {
                return '(' . substr($national, 0, 3) . ') ' . substr($national, 3, 3) . '-' . substr($national, 6);
            }
            return $national;
        case 'GB':
            // Loose: 0XXXX XXXXXX for mobile, 0XX XXXX XXXX-ish for landline. Keep it simple.
            $s = '0' . $national;
            if (strlen($s) >= 10) {
                return substr($s, 0, 5) . ' ' . substr($s, 5);
            }
            return $s;
        case 'BE':
        case 'NL':
        case 'CH':
        case 'DE':
        case 'IT':
        case 'ES':
        case 'PT':
        case 'LU':
            return trim(chunk_split('0' . $national, 3, ' '));
        default:
            // Generic: groups of 3, no leading zero (some numbering plans use it, some don't).
            return trim(chunk_split($national, 3, ' '));
    }
}

function phone_type_hint(string $cc, string $national): array {
    if ($national === '') return ['type' => 'unknown', 'confidence' => 'low'];
    $first  = $national[0];
    $first2 = substr($national, 0, 2);
    switch ($cc) {
        case 'FR':
            // After +33: 6,7 mobile / 1-5 landline / 8 special / 9 voip-ish
            if ($first === '6' || $first === '7') return ['type' => 'mobile',   'confidence' => 'medium'];
            if (in_array($first, ['1','2','3','4','5'], true)) return ['type' => 'landline', 'confidence' => 'medium'];
            if ($first === '8') return ['type' => 'special',  'confidence' => 'medium'];
            if ($first === '9') return ['type' => 'voip',     'confidence' => 'medium'];
            return ['type' => 'unknown', 'confidence' => 'low'];
        case 'GB':
            if ($first === '7') return ['type' => 'mobile',   'confidence' => 'medium'];
            if ($first === '1' || $first === '2') return ['type' => 'landline', 'confidence' => 'medium'];
            if ($first === '3') return ['type' => 'non-geographic', 'confidence' => 'medium'];
            if ($first === '8' || $first === '9') return ['type' => 'special', 'confidence' => 'medium'];
            return ['type' => 'unknown', 'confidence' => 'low'];
        case 'US':
        case 'CA':
            return ['type' => 'unknown', 'confidence' => 'low'];
        default:
            return ['type' => 'unknown', 'confidence' => 'low'];
    }
}

function phone_search_links(string $e164, string $digits, ?string $countryName, ?string $cc, string $localFormat): array {
    $links = [];
    $links[] = ['label' => 'Google (exact number)',         'url' => 'https://www.google.com/search?q=' . urlencode('"' . $e164 . '"')];
    if ($countryName) {
        $links[] = ['label' => 'Google (number + country)', 'url' => 'https://www.google.com/search?q=' . urlencode('"' . $e164 . '" ' . $countryName)];
    }
    if ($cc === 'FR' && $localFormat !== '') {
        $links[] = ['label' => 'PagesJaunes (FR reverse)',  'url' => 'https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui=' . urlencode($localFormat)];
    }
    $links[] = ['label' => 'ReversePhoneCheck',             'url' => 'https://www.reversephonecheck.com/'];
    $links[] = ['label' => 'Truecaller search',             'url' => 'https://www.truecaller.com/search/fr/' . urlencode($digits)];
    return $links;
}

function phone_social_links(string $digits): array {
    return [
        ['label' => 'WhatsApp', 'url' => 'https://wa.me/' . $digits,  'note' => 'Opens chat if the number has WhatsApp.'],
        ['label' => 'Telegram', 'url' => 'https://t.me/+' . $digits,  'note' => 'Works only if the user enabled phone-based discovery.'],
        ['label' => 'Signal',   'url' => null,                          'note' => 'No public lookup — Signal does not expose accounts by number.'],
    ];
}

function phone_call_numverify(string $e164, string $apiKey): array {
    // numverify free tier is HTTP-only.
    $url = 'http://apilayer.net/api/validate?access_key=' . urlencode($apiKey)
         . '&number=' . urlencode($e164) . '&format=1';
    $res = spectr_http_get($url, ['Accept: application/json']);
    if ($res['status'] !== 200 || !$res['body']) {
        return ['ok' => false, 'error' => 'HTTP ' . $res['status'] . ($res['error'] ? ' — ' . $res['error'] : '')];
    }
    $j = json_decode($res['body'], true);
    if (!is_array($j)) {
        return ['ok' => false, 'error' => 'Invalid JSON from numverify'];
    }
    if (!empty($j['error'])) {
        $msg = is_array($j['error']) ? ($j['error']['info'] ?? json_encode($j['error'])) : (string)$j['error'];
        return ['ok' => false, 'error' => $msg];
    }
    return [
        'ok' => true,
        'data' => [
            'valid'                => $j['valid']                 ?? null,
            'number'               => $j['number']                ?? null,
            'local_format'         => $j['local_format']          ?? null,
            'international_format' => $j['international_format']  ?? null,
            'country_prefix'       => $j['country_prefix']        ?? null,
            'country_code'         => $j['country_code']          ?? null,
            'country_name'         => $j['country_name']          ?? null,
            'location'             => $j['location']              ?? null,
            'carrier'              => $j['carrier']               ?? null,
            'line_type'            => $j['line_type']             ?? null,
        ],
    ];
}

$in       = phone_input();
$digits   = $in['digits'];
$e164     = $in['e164'];
$country  = phone_match_country($digits);
$local    = phone_format_local($country['country_code'] ?? '', $country['national']);
$typeHint = phone_type_hint($country['country_code'] ?? '', $country['national']);

$payload = [
    'phone_raw'           => $e164,
    'phone_e164'          => $e164,
    'digits_only'         => $digits,
    'country_code'        => $country['country_code'],
    'country_name'        => $country['country_name'],
    'country_prefix'      => $country['prefix'],
    'national_number'     => $country['national'],
    'local_format'        => $local,
    'type_hint'           => $typeHint['type'],
    'type_hint_confidence'=> $typeHint['confidence'],
    'search_links'        => phone_search_links($e164, $digits, $country['country_name'], $country['country_code'], $local),
    'social_links'        => phone_social_links($digits),
    'numverify'           => null,
    'numverify_skipped'   => false,
    'numverify_warning'   => null,
];

$apiKey = spectr_config()['numverify_api_key'] ?? '';
if ($apiKey === '') {
    $payload['numverify_skipped'] = true;
    $payload['numverify_warning'] = 'No numverify API key configured — carrier/line-type lookup skipped. Set numverify_api_key in config.';
} else {
    $nv = phone_call_numverify($e164, $apiKey);
    if ($nv['ok']) {
        $payload['numverify'] = $nv['data'];
    } else {
        $payload['numverify_skipped'] = true;
        $payload['numverify_warning'] = 'numverify error: ' . $nv['error'];
    }
}

spectr_log_scan($e164, 'phone', true, $payload);
spectr_ok($payload, $e164);

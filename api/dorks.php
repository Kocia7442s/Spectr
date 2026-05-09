<?php
// /api/dorks.php — Generate Google dork URLs for a query (name, email, username, etc.).

require __DIR__ . '/_bootstrap.php';

function dorks_input(): string {
    $raw = $_GET['query'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['query'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['query'] ?? null);
    }
    if (!is_string($raw) || trim($raw) === '') {
        spectr_error('Missing "query" parameter.', 422);
    }
    $q = trim($raw);
    // Strip control chars and a few characters that break Google search syntax.
    $q = preg_replace('/[\x00-\x1F\x7F]+/u', '', $q);
    $q = str_replace(['"', '\\', '<', '>'], ' ', $q);
    $q = preg_replace('/\s+/u', ' ', $q);
    if ($q === '' || mb_strlen($q) > 120) {
        spectr_error('Query must be 1-120 characters after sanitization.', 422);
    }
    return $q;
}

$query = dorks_input();

$dorks = [
    'Identity' => [
        ['label' => 'Exact name/email search',       'q' => '"{query}"'],
        ['label' => 'LinkedIn profile',              'q' => '"{query}" site:linkedin.com'],
        ['label' => 'Twitter/X mention',             'q' => '"{query}" site:x.com OR site:twitter.com'],
        ['label' => 'Facebook profile',              'q' => '"{query}" site:facebook.com'],
        ['label' => 'Instagram mention',             'q' => '"{query}" site:instagram.com'],
        ['label' => 'GitHub profile or mention',     'q' => '"{query}" site:github.com'],
        ['label' => 'Reddit mention',                'q' => '"{query}" site:reddit.com'],
    ],
    'Documents & Files' => [
        ['label' => 'PDF documents mentioning',      'q' => '"{query}" filetype:pdf'],
        ['label' => 'Word documents mentioning',     'q' => '"{query}" filetype:doc OR filetype:docx'],
        ['label' => 'Excel files mentioning',        'q' => '"{query}" filetype:xls OR filetype:xlsx'],
        ['label' => 'CV/Resume',                     'q' => '"{query}" filetype:pdf (CV OR resume OR curriculum)'],
    ],
    'Leaks & Exposure' => [
        ['label' => 'Pastebin exposure',             'q' => '"{query}" site:pastebin.com'],
        ['label' => 'Ghostbin/paste sites',          'q' => '"{query}" site:ghostbin.com OR site:paste.ee OR site:dpaste.com'],
        ['label' => 'Trello boards (public)',        'q' => '"{query}" site:trello.com'],
        ['label' => 'Exposed in Google Groups',      'q' => '"{query}" site:groups.google.com'],
        ['label' => 'Mentioned in forums',           'q' => '"{query}" (forum OR forums OR community OR discussion)'],
    ],
    'Technical' => [
        ['label' => 'Email in source code (GitHub)', 'q' => '"{query}" site:github.com (email OR contact OR mailto)'],
        ['label' => 'Config or env files',           'q' => '"{query}" (filetype:env OR filetype:cfg OR filetype:conf OR filetype:ini)'],
        ['label' => 'API keys or tokens mentioning', 'q' => '"{query}" (api_key OR token OR secret OR password)'],
        ['label' => 'Subdomains mentioning',         'q' => '"{query}" inurl:{query}'],
    ],
    'News & Web' => [
        ['label' => 'News articles',                 'q' => '"{query}" (site:reuters.com OR site:bbc.com OR site:lemonde.fr OR site:lefigaro.fr)'],
        ['label' => 'Blog posts',                    'q' => '"{query}" (inurl:blog OR inurl:post OR inurl:article)'],
        ['label' => 'Web archive (Wayback)',         'q' => 'site:web.archive.org "{query}"'],
    ],
];

function build_dork_url(string $template, string $query): array {
    $expanded = str_replace('{query}', $query, $template);
    return [
        'q'   => $expanded,
        'url' => 'https://www.google.com/search?q=' . urlencode($expanded),
    ];
}

$categories = [];
$total = 0;
foreach ($dorks as $name => $items) {
    $catDorks = [];
    foreach ($items as $d) {
        $built = build_dork_url($d['q'], $query);
        $catDorks[] = [
            'label' => $d['label'],
            'q'     => $built['q'],
            'url'   => $built['url'],
        ];
        $total++;
    }
    $categories[] = ['category_name' => $name, 'dorks' => $catDorks];
}

$payload = [
    'query'           => $query,
    'categories'      => $categories,
    'total_dorks'     => $total,
    'search_all_url'  => 'https://www.google.com/search?q=' . urlencode('"' . $query . '"'),
];

spectr_log_scan($query, 'dorks', true, $payload);
spectr_ok($payload, $query);

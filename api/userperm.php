<?php
// /api/userperm.php — Generate ranked username permutations from first/last + optional birth year.
// No external calls; the frontend pivots each variant into username.php as the user clicks.

require __DIR__ . '/_bootstrap.php';

function userperm_input(): array {
    $first = $_GET['first'] ?? null;
    $last  = $_GET['last']  ?? null;
    $year  = $_GET['year']  ?? null;
    $name  = $_GET['name']  ?? null;

    if ($first === null && $last === null && $name === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            if (is_array($j)) {
                $first = $j['first'] ?? $first;
                $last  = $j['last']  ?? $last;
                $year  = $j['year']  ?? $year;
                $name  = $j['name']  ?? $name;
            }
        }
    }

    // Allow a single "name" input that we split heuristically.
    if ((!$first || !$last) && is_string($name) && trim($name) !== '') {
        $parts = preg_split('/\s+/', trim($name));
        if (count($parts) >= 2) {
            $first = $first ?: $parts[0];
            $last  = $last  ?: end($parts);
        } elseif (count($parts) === 1) {
            $first = $first ?: $parts[0];
        }
    }

    if (!is_string($first) || trim($first) === '' || !is_string($last) || trim($last) === '') {
        spectr_error('Provide "first" and "last" (or "name" with at least two tokens).', 422);
    }

    $year = is_string($year) || is_int($year) ? (string)$year : null;
    if ($year !== null && !preg_match('/^\d{4}$/', $year)) {
        $year = null;   // silently drop bad year input
    }

    return [
        'first' => trim($first),
        'last'  => trim($last),
        'year'  => $year !== null ? (int)$year : null,
    ];
}

function userperm_clean(string $s): string {
    // Strip diacritics, drop everything that's not [a-z0-9].
    $tr = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $s);
    if ($tr === false) $tr = $s;
    $tr = strtolower($tr);
    $tr = preg_replace('/[^a-z0-9]/', '', $tr);
    return $tr ?? '';
}

function userperm_valid(string $v): bool {
    return strlen($v) >= 3 && strlen($v) <= 30;
}

function userperm_generate(string $first, string $last, ?int $year): array {
    $f  = userperm_clean($first);
    $l  = userperm_clean($last);
    if ($f === '' || $l === '') return [];
    $fi = $f[0];
    $li = $l[0];

    // [variant, base score, pattern label]
    $base = [
        [$f.$l,        100, 'firstlast'],
        [$fi.$l,        95, 'flast'],
        [$f.'.'.$l,     90, 'first.last'],
        [$fi.'.'.$l,    85, 'f.last'],
        [$f.'_'.$l,     75, 'first_last'],
        [$f.$li,        70, 'firstl'],
        [$fi.'_'.$l,    65, 'f_last'],
        [$f.'-'.$l,     60, 'first-last'],
        [$l.$f,         55, 'lastfirst'],
        [$l.$fi,        50, 'lastf'],
        [$l.'.'.$f,     45, 'last.first'],
        [$f,            40, 'first'],
        [$l,            35, 'last'],
        [$fi.$li,       20, 'fl'],
    ];

    $variants = [];
    foreach ($base as [$v, $score, $pattern]) {
        if (!userperm_valid($v)) continue;
        if (!isset($variants[$v]) || $variants[$v]['score'] < $score) {
            $variants[$v] = ['variant' => $v, 'score' => $score, 'pattern' => $pattern];
        }
    }

    // Year-suffixed variants — only worthwhile on the strongest base patterns.
    if ($year !== null) {
        $yyyy = (string)$year;
        $yy   = substr($yyyy, -2);
        $topPatterns = ['firstlast', 'flast', 'first.last', 'first', 'last'];
        foreach ($base as [$v, $score, $pattern]) {
            if (!in_array($pattern, $topPatterns, true)) continue;
            foreach ([[$yyyy, -15], [$yy, -22]] as [$suffix, $delta]) {
                $candidate = $v . $suffix;
                if (!userperm_valid($candidate)) continue;
                $cscore = max(1, $score + $delta);
                if (!isset($variants[$candidate]) || $variants[$candidate]['score'] < $cscore) {
                    $variants[$candidate] = [
                        'variant' => $candidate,
                        'score'   => $cscore,
                        'pattern' => $pattern . '+' . (strlen($suffix) === 4 ? 'yyyy' : 'yy'),
                    ];
                }
            }
        }
    }

    $list = array_values($variants);
    usort($list, static fn($a, $b) => $b['score'] <=> $a['score']);
    return $list;
}

$in = userperm_input();
$variants = userperm_generate($in['first'], $in['last'], $in['year']);

$payload = [
    'first'    => $in['first'],
    'last'     => $in['last'],
    'year'     => $in['year'],
    'variants' => $variants,
    'count'    => count($variants),
];

spectr_log_scan(strtolower($in['first']) . ' ' . strtolower($in['last']), 'userperm', !empty($variants), $payload);
spectr_ok($payload, $in['first'] . ' ' . $in['last']);

<?php
// /api/pappers.php — French company / person registry lookup via the free
// gouvernement API at recherche-entreprises.api.gouv.fr (no key required).
// Filename kept for compatibility with existing frontend routes.

require __DIR__ . '/_bootstrap.php';

function pappers_input(): string {
    $raw = $_GET['q'] ?? null;
    if ($raw === null && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $body = file_get_contents('php://input');
        if ($body) {
            $j = json_decode($body, true);
            $raw = is_array($j) ? ($j['q'] ?? null) : null;
        }
        $raw = $raw ?? ($_POST['q'] ?? null);
    }
    if (!is_string($raw) || trim($raw) === '') {
        spectr_error('Missing "q" parameter.', 422);
    }
    $q = trim($raw);
    if (mb_strlen($q) > 100) {
        spectr_error('Query too long (max 100 chars).', 422);
    }
    return $q;
}

function pappers_dirigeant_name(array $d): ?string {
    if (!empty($d['nom']) || !empty($d['prenoms']) || !empty($d['prenom'])) {
        return trim(implode(' ', array_filter([
            $d['prenoms'] ?? ($d['prenom'] ?? null),
            $d['nom']     ?? null,
        ]))) ?: null;
    }
    if (!empty($d['denomination'])) return (string)$d['denomination'];   // dirigeant = personne morale
    if (!empty($d['nom_complet']))  return (string)$d['nom_complet'];
    return null;
}

function pappers_summarize(array $c): array {
    $siege = $c['siege'] ?? [];
    $etat  = $c['etat_administratif'] ?? ($siege['etat_administratif'] ?? null);
    $statut = $etat === 'A' ? 'Actif' : ($etat === 'F' ? 'Fermé' : null);

    $dirigeants = [];
    foreach (($c['dirigeants'] ?? []) as $d) {
        $name = pappers_dirigeant_name($d);
        if ($name === null) continue;
        $dirigeants[] = [
            'name'        => $name,
            'role'        => $d['qualite']                  ?? null,
            'birth'       => $d['date_de_naissance_formate'] ?? ($d['date_de_naissance'] ?? null),
            'nationality' => $d['nationalite']              ?? null,
        ];
    }

    $extras = [];
    foreach (($c['matching_etablissements'] ?? []) as $e) {
        if (!empty($e['siret']) && ($e['siret'] !== ($siege['siret'] ?? null))) {
            $extras[] = [
                'siret'       => $e['siret'],
                'adresse'     => $e['adresse']     ?? null,
                'code_postal' => $e['code_postal'] ?? null,
                'commune'     => $e['commune']     ?? null,
                'is_siege'    => $e['est_siege']   ?? false,
                'etat'        => $e['etat_administratif'] ?? null,
            ];
        }
    }

    $siren = $c['siren'] ?? null;
    return [
        'siren'             => $siren,
        'siret_siege'       => $siege['siret']  ?? null,
        'nom_entreprise'    => $c['nom_complet']        ?? ($c['nom_raison_sociale'] ?? null),
        'sigle'             => $c['sigle']              ?? null,
        'forme_juridique'   => $c['nature_juridique']   ?? ($c['forme_juridique'] ?? null),
        'activite'          => $c['activite_principale']?? null,
        'date_creation'     => $c['date_creation']      ?? null,
        'date_fermeture'    => $c['date_fermeture']     ?? null,
        'statut'            => $statut,
        'is_active'         => $etat === 'A',
        'effectif_tranche'  => $c['tranche_effectif_salarie'] ?? null,
        'effectif_annee'    => $c['annee_tranche_effectif_salarie'] ?? null,
        'nb_etablissements' => $c['nombre_etablissements']         ?? null,
        'nb_etablissements_ouverts' => $c['nombre_etablissements_ouverts'] ?? null,
        'siege' => [
            'adresse'     => $siege['adresse']     ?? null,
            'code_postal' => $siege['code_postal'] ?? null,
            'commune'     => $siege['commune']     ?? null,
            'latitude'    => isset($siege['latitude'])  ? (float)$siege['latitude']  : null,
            'longitude'   => isset($siege['longitude']) ? (float)$siege['longitude'] : null,
        ],
        'dirigeants'           => $dirigeants,
        'autres_etablissements'=> $extras,
        'links' => $siren ? [
            'annuaire_entreprises' => 'https://annuaire-entreprises.data.gouv.fr/entreprise/' . $siren,
            'societe_com'          => 'https://www.societe.com/societe/' . $siren . '.html',
        ] : null,
    ];
}

$query = pappers_input();

$inputType = 'search';
if (preg_match('/^\d{9}$/',  $query)) $inputType = 'siren';
elseif (preg_match('/^\d{14}$/', $query)) $inputType = 'siret';

$perPage = ($inputType === 'siren' || $inputType === 'siret') ? 1 : 10;
$url = 'https://recherche-entreprises.api.gouv.fr/search?q=' . urlencode($query) . '&per_page=' . $perPage;

$res = spectr_http_get($url, ['Accept: application/json']);
if ($res['status'] !== 200 || !$res['body']) {
    if ($res['status'] === 429) spectr_error('gouv.fr rate limit hit (429).', 429);
    spectr_error('recherche-entreprises.api.gouv.fr request failed.', 502, [
        'http_status' => $res['status'], 'curl_error' => $res['error'],
    ]);
}

$j = json_decode($res['body'], true);
if (!is_array($j)) {
    spectr_error('gouv.fr returned non-JSON payload.', 502);
}

$companies = [];
foreach (($j['results'] ?? []) as $c) {
    $companies[] = pappers_summarize($c);
}

$payload = [
    'query'         => $query,
    'input_type'    => $inputType,
    'companies'     => $companies,
    'total_results' => (int)($j['total_results'] ?? count($companies)),
    'returned'      => count($companies),
    'page'          => (int)($j['page']      ?? 1),
    'per_page'      => (int)($j['per_page']  ?? $perPage),
    'source'        => 'recherche-entreprises.api.gouv.fr',
];

spectr_log_scan($query, 'pappers', !empty($companies), $payload);
spectr_ok($payload, $query);

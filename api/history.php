<?php
// /api/history.php — Recent scan log for the dashboard.

require __DIR__ . '/_bootstrap.php';

$pdo = spectr_db();
if ($pdo === null) {
    spectr_error('Database unavailable.', 503);
}

$limit  = isset($_GET['limit'])  ? max(1, min(200, (int)$_GET['limit'])) : 50;
$domain = isset($_GET['domain']) && $_GET['domain'] !== '' ? spectr_normalize_domain($_GET['domain']) : null;

if ($domain) {
    $stmt = $pdo->prepare(
        'SELECT id, domain, module, success, created_at FROM scans WHERE domain = :d ORDER BY created_at DESC LIMIT :lim'
    );
    $stmt->bindValue(':d', $domain);
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
} else {
    $stmt = $pdo->prepare(
        'SELECT id, domain, module, success, created_at FROM scans ORDER BY created_at DESC LIMIT :lim'
    );
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
}
$stmt->execute();
$rows = $stmt->fetchAll();

foreach ($rows as &$row) {
    $row['id']      = (int)$row['id'];
    $row['success'] = (bool)$row['success'];
}

spectr_ok(['scans' => $rows, 'limit' => $limit], $domain);

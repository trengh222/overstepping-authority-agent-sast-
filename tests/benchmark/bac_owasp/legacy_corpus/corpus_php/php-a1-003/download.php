<?php
// 文档下载：/download.php?id=8

session_start();

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit;
}

$id = $_GET['id'] ?? '';

$stmt = $pdo->prepare('SELECT id, user_id, stored_name, mime FROM documents WHERE id = ?');
$stmt->execute([$id]);
$doc = $stmt->fetch(PDO::FETCH_ASSOC);

if ($doc === false) {
    http_response_code(404);
    exit;
}

header('Content-Type: ' . $doc['mime']);
header('Content-Disposition: attachment; filename="' . basename($doc['stored_name']) . '"');
readfile(__DIR__ . '/storage/documents/' . $doc['stored_name']);

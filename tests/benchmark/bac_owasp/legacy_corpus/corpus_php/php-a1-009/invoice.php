<?php
// 单张发票详情：/invoice.php?id=5

session_start();

$uid = $_SESSION['user_id'] ?? null;
if ($uid === null) {
    http_response_code(401);
    exit;
}

$id = $_GET['id'] ?? '';

$stmt = $pdo->prepare(
    'SELECT id, number, amount, status FROM invoices WHERE id = ? AND user_id = ?'
);
$stmt->execute([$id, $uid]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if ($row === false) {
    http_response_code(404);
    exit;
}

header('Content-Type: application/json');
echo json_encode($row);

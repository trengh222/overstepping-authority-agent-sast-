<?php
// 发票列表：/invoices.php?user_id=12

session_start();

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit;
}

$userId = $_GET['user_id'] ?? '';

$stmt = $pdo->prepare(
    'SELECT id, number, amount, status, issued_at FROM invoices WHERE user_id = ?'
);
$stmt->execute([$userId]);

$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

header('Content-Type: application/json');
echo json_encode($rows);

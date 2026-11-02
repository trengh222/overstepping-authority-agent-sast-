<?php
// 工单状态更新：POST /ticket_update.php

session_start();

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit;
}

$payload = json_decode(file_get_contents('php://input'), true);

$ticketId = $payload['ticket_id'] ?? 0;
$status = $payload['status'] ?? 'open';

$stmt = $pdo->prepare('UPDATE tickets SET status = ?, updated_at = NOW() WHERE id = ?');
$stmt->execute([$status, $ticketId]);

http_response_code(204);

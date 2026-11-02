<?php
// 会员资料：/api/members/me.php

session_start();

$uid = $_SESSION['user_id'] ?? null;
if ($uid === null) {
    http_response_code(401);
    exit;
}

$stmt = $pdo->prepare('SELECT * FROM members WHERE user_id = ?');
$stmt->execute([$uid]);
$member = $stmt->fetch(PDO::FETCH_ASSOC);

header('Content-Type: application/json');
echo json_encode($member);

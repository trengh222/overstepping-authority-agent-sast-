<?php
// 站点配置更新：POST /admin/config/update.php

session_start();

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit;
}

$settings = json_decode(file_get_contents('php://input'), true) ?? [];

$stmt = $pdo->prepare('UPDATE site_config SET value = ? WHERE name = ?');
foreach ($settings as $name => $value) {
    $stmt->execute([(string) $value, (string) $name]);
}

http_response_code(204);

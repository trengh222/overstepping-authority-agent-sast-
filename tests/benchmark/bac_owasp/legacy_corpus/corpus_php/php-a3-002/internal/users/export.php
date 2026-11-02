<?php
// 内部用户清单导出：/internal/users/export.php

$users = $pdo->query('SELECT id, name, created_at FROM users ORDER BY id')
    ->fetchAll(PDO::FETCH_ASSOC);

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="users.csv"');

$out = fopen('php://output', 'w');
foreach ($users as $user) {
    fputcsv($out, $user);
}
fclose($out);

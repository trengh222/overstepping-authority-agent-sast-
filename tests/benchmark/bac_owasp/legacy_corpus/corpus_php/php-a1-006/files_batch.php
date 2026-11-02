<?php
// 批量取文件元数据：/files_batch.php?ids=3,7,9

session_start();

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit;
}

$ids = $_GET['ids'] ?? '';

$files = [];
foreach (explode(',', $ids) as $raw) {
    $fileId = trim($raw);
    if ($fileId === '') {
        continue;
    }

    $stmt = $pdo->prepare('SELECT id, name, mime, size FROM files WHERE id = ?');
    $stmt->execute([$fileId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row !== false) {
        $files[] = $row;
    }
}

header('Content-Type: application/json');
echo json_encode($files);

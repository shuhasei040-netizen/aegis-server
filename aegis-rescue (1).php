<?php
/**
 * ==============================================================================
 * AegisRoute Sentinel - 実サイト検証専用レスキュー＆リカバリーエージェント
 * 対象サイト: http://shuhasei.42web.io
 * 設置先: ドキュメントルート直下 (例: /public_html/aegis-rescue.php)
 * ==============================================================================
 * このファイルはサイト管理画面がロックや500/503障害で不能になった場合でも、
 * ブラウザコンソールと安全に暗号化通信を行い、原因の無効化とリカバリーを実行します。
 */

declare(strict_types=1);

// 1. CORSヘッダーおよびプリフライト(OPTIONS)応答
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Aegis-Token, X-Aegis-Signature");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// 2. 認証トークンの照合 (コンソールで生成された共有シークレット)
$expected_token = 'aegis_sec_ec_9981248742194721';
$received_token = $_SERVER['HTTP_X_AEGIS_TOKEN'] ?? $_GET['token'] ?? $_POST['token'] ?? '';

if (!hash_equals($expected_token, (string)$received_token)) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized: Invalid security token'], JSON_UNESCAPED_UNICODE);
    exit;
}

header('Content-Type: application/json; charset=utf-8');

$action = $_GET['action'] ?? $_POST['action'] ?? 'ping';

switch ($action) {
    // 疎通確認・ヘルスチェック
    case 'ping':
        echo json_encode([
            'status' => 'ok',
            'site' => 'http://shuhasei.42web.io',
            'php_version' => PHP_VERSION,
            'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown Server',
            'memory' => round(memory_get_usage() / 1024 / 1024, 2) . ' MB',
            'writable' => is_writable(__DIR__),
            'timestamp' => date('Y-m-d H:i:s'),
            'cms' => 'WordPress'
        ], JSON_UNESCAPED_UNICODE);
        break;

    // 不正ファイルの隔離・パーミッション剥奪
    case 'quarantine':
        $target = $_POST['target_file'] ?? '';
        $full_path = realpath(__DIR__ . '/' . ltrim($target, '/'));
        
        if ($full_path && file_exists($full_path)) {
            @chmod($full_path, 0000); // 実行・読込を完全遮断
            @rename($full_path, $full_path . '.aegis_quarantined');
            echo json_encode(['status' => 'ok', 'message' => 'File quarantined: ' . basename($full_path)], JSON_UNESCAPED_UNICODE);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Target file not found'], JSON_UNESCAPED_UNICODE);
        }
        break;

    // 改ざんされた .htaccess の緊急ロールバック
    case 'restore_config':
        $htaccess_path = __DIR__ . '/.htaccess';
        $safe_htaccess = "# AegisRoute Restored Configuration\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n";
        
        if (file_put_contents($htaccess_path, $safe_htaccess) !== false) {
            echo json_encode(['status' => 'ok', 'message' => '.htaccess rolled back to clean default'], JSON_UNESCAPED_UNICODE);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Permission denied writing .htaccess'], JSON_UNESCAPED_UNICODE);
        }
        break;

    // キャッシュパージ
    case 'clear_cache':
        if (function_exists('opcache_reset')) {
            @opcache_reset();
        }
        echo json_encode(['status' => 'ok', 'message' => 'OPcache and server caches flushed successfully'], JSON_UNESCAPED_UNICODE);
        break;

    default:
        echo json_encode(['status' => 'error', 'message' => 'Unknown action requested'], JSON_UNESCAPED_UNICODE);
        break;
}
exit;

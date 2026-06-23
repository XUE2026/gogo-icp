<?php
/**
 * 密码 + TOTP 双因素认证 + 302 跳转代理
 * 
 * 环境变量：
 *   TARGET_IP        - 目标服务器 IP（必填）
 *   TARGET_PORT      - 默认端口（可选，查询参数 p/port/裸数字 优先级更高）
 *   TARGET_SCHEME    - 目标协议（默认 http）
 *   AUTH_PASSWD      - 第一关：密码（必填）
 *   AUTH_TOTP_SECRET - 第二关：TOTP 密钥 Base32（必填，SHA1 30s）
 *   AUTH_SALT        - Cookie 签名盐值（可选，默认自动生成）
 * 
 * 端口指定方式（优先级从高到低）：
 *   1. ?p=8088
 *   2. ?port=8088
 *   3. ?8088（裸数字）
 *   4. TARGET_PORT 环境变量
 *   5. 不指定（走默认 80）
 */

// ==================== TOTP 工具函数 ====================

function base32_decode_custom($input) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input = strtoupper(str_replace('=', '', $input));
    $binary = '';
    $buffer = 0;
    $bits = 0;
    for ($i = 0; $i < strlen($input); $i++) {
        $val = strpos($alphabet, $input[$i]);
        if ($val === false) continue;
        $buffer = ($buffer << 5) | $val;
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $binary .= chr(($buffer >> $bits) & 0xFF);
        }
    }
    return $binary;
}

function generate_totp($secret, $period = 30) {
    $key = base32_decode_custom($secret);
    $counter = pack('N*', 0) . pack('N*', intval(time() / $period));
    $hash = hash_hmac('sha1', $counter, $key, true);
    $offset = ord($hash[19]) & 0x0F;
    $code = ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF);
    return str_pad($code % 1000000, 6, '0', STR_PAD_LEFT);
}

// ==================== Cookie 签名工具 ====================

function get_auth_salt() {
    $salt = getenv('AUTH_SALT');
    if (empty($salt)) {
        $salt = substr(getenv('AUTH_TOTP_SECRET') ?: '', 0, 16);
    }
    return $salt ?: 'default-salt-change-me-2024';
}

function build_auth_cookie() {
    $salt = get_auth_salt();
    $ts = time();
    $token = bin2hex(random_bytes(16));
    $sig = hash_hmac('sha256', "$token.$ts", $salt);
    return "$token.$ts.$sig";
}

function validate_auth_cookie($cookie_val) {
    $parts = explode('.', $cookie_val);
    if (count($parts) !== 3) return false;
    [$token, $ts, $sig] = $parts;
    if (time() - intval($ts) > 7 * 86400) return false;
    $salt = get_auth_salt();
    $expected_sig = hash_hmac('sha256', "$token.$ts", $salt);
    return hash_equals($expected_sig, $sig);
}

// ==================== 端口提取工具 ====================

/**
 * 从查询字符串中提取端口号（排除 auth_step/redirect 参数干扰）
 * 支持：?p=8088、?port=8088、?8088（裸数字）
 */
function extract_port_from_query($query_string) {
    if (empty($query_string)) return null;

    $parts = explode('&', $query_string);
    $bare_numbers = [];

    foreach ($parts as $part) {
        $part = trim($part);
        if (empty($part)) continue;

        // 跳过认证参数
        if (strpos($part, 'auth_step=') === 0 || strpos($part, 'redirect=') === 0) continue;

        if (strpos($part, '=') !== false) {
            [$key, $value] = explode('=', $part, 2);
            $key = urldecode($key);
            $value = urldecode($value);
            if (($key === 'p' || $key === 'port') && is_numeric($value)) {
                return intval($value);
            }
        } else {
            // 裸数字：?8088
            if (is_numeric($part)) {
                $bare_numbers[] = intval($part);
            }
        }
    }

    return !empty($bare_numbers) ? $bare_numbers[0] : null;
}

// ==================== 读取环境变量 ====================

$target_ip     = getenv('TARGET_IP');
$target_scheme = getenv('TARGET_SCHEME') ?: 'http';
$auth_passwd   = getenv('AUTH_PASSWD');
$auth_totp     = getenv('AUTH_TOTP_SECRET');

// 必填变量检查
if (empty($target_ip)) {
    http_response_code(500);
    exit('Error: TARGET_IP environment variable is not set.');
}
if (empty($auth_passwd)) {
    http_response_code(500);
    exit('Error: AUTH_PASSWD environment variable is not set.');
}
if (empty($auth_totp)) {
    http_response_code(500);
    exit('Error: AUTH_TOTP_SECRET environment variable is not set.');
}

// ==================== 端口检测 ====================

// 1) 优先从当前查询字符串提取
$target_port = extract_port_from_query($_SERVER['QUERY_STRING'] ?? '');
// 2) 在认证流程中，从 redirect 参数里的原始 URL 提取
if (empty($target_port) && isset($_GET['redirect'])) {
    $redirect_parts = parse_url($_GET['redirect']);
    if (isset($redirect_parts['query'])) {
        $target_port = extract_port_from_query($redirect_parts['query']);
    }
}
// 3) 最后回退到环境变量
if (empty($target_port)) {
    $target_port = getenv('TARGET_PORT');
}

// ==================== 认证检查 ====================

$auth_cookie  = $_COOKIE['auth_token'] ?? '';
$is_verified  = !empty($auth_cookie) && validate_auth_cookie($auth_cookie);

if (!$is_verified) {
    // 获取原始请求 URI 作为跳转目标
    $orig_uri = $_SERVER['REQUEST_URI'] ?? '/';
    // 如果已经在 auth 流程中，从参数取 redirect
    $redirect_to = $_GET['redirect'] ?? $orig_uri;
    // 清理掉 redirect 里残留的 auth_step/auth 参数
    $redirect_to = preg_replace('/[?&]auth_step=[^&]*/', '', $redirect_to);
    $redirect_to = preg_replace('/[?&]redirect=[^&]*/', '', $redirect_to);
    $redirect_to = rtrim($redirect_to, '?&') ?: '/';

    $step   = $_GET['auth_step'] ?? 'password';
    $error  = '';

    // ---- Step 1: 密码验证 ----
    if ($step === 'password' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (hash_equals($auth_passwd, $_POST['password'])) {
            $goto = '?auth_step=totp&redirect=' . urlencode($redirect_to);
            header('Location: ' . $goto, true, 302);
            exit();
        } else {
            $error = '密码错误';
        }
    }

    // ---- Step 2: TOTP 验证 ----
    if ($step === 'totp' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['totp'])) {
        $expected_totp = generate_totp($auth_totp);
        if (hash_equals($expected_totp, $_POST['totp'])) {
            $cookie_val = build_auth_cookie();
            setcookie('auth_token', $cookie_val, time() + 7 * 86400, '/', '', true, true);
            header('Location: ' . $redirect_to, true, 302);
            exit();
        } else {
            $error = '验证码错误';
        }
    }

    // ---- 显示认证页面 ----
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
    ?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>访问验证</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{display:flex;justify-content:center;align-items:center;min-height:100vh;background:linear-gradient(135deg,#667eea,#764ba2);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
.card{background:#fff;padding:40px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.15);width:380px;max-width:90vw}
.card h2{text-align:center;margin-bottom:8px;color:#1a1a2e;font-size:22px}
.card p.desc{text-align:center;color:#888;margin-bottom:24px;font-size:14px}
.error{color:#e74c3c;background:#fde8e8;padding:10px 14px;border-radius:8px;margin-bottom:16px;text-align:center;font-size:14px}
.input-group{margin-bottom:16px}
.input-group input{width:100%;padding:12px 14px;border:2px solid #e0e0e0;border-radius:10px;font-size:16px;transition:border-color .2s;outline:none}
.input-group input:focus{border-color:#667eea}
.btn{width:100%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:10px;font-size:16px;cursor:pointer;transition:opacity .2s}
.btn:hover{opacity:.9}
.steps{display:flex;justify-content:center;gap:8px;margin-bottom:24px}
.step-dot{width:10px;height:10px;border-radius:50%;background:#e0e0e0}
.step-dot.active{background:#667eea}
.step-dot.done{background:#52c41a}
</style>
</head>
<body>
<div class="card">
    <div class="steps">
        <div class="step-dot <?= $step === 'password' ? 'active' : 'done' ?>"></div>
        <div class="step-dot <?= $step === 'totp' ? 'active' : ($step === 'password' ? '' : 'done') ?>"></div>
    </div>
    <h2><?= $step === 'password' ? '密码验证' : '二次验证' ?></h2>
    <p class="desc"><?= $step === 'password' ? '请输入访问密码' : '请输入 TOTP 验证码' ?></p>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="post" action="?auth_step=<?= $step ?>&redirect=<?= urlencode($redirect_to) ?>">
        <div class="input-group">
            <?php if ($step === 'password'): ?>
            <input type="password" name="password" placeholder="请输入密码" required autofocus>
            <?php else: ?>
            <input type="text" name="totp" placeholder="请输入 6 位验证码" required pattern="[0-9]{6}" maxlength="6" autofocus>
            <?php endif; ?>
        </div>
        <button type="submit" class="btn">确认</button>
    </form>
</div>
</body>
</html>
<?php
    exit();
}

// ==================== 已验证 -> 执行 302 跳转 ====================

$request_uri = $_SERVER['REQUEST_URI'] ?? '/';

// 手动清理 URI：移除 auth 参数和端口参数，保留其他
$uri_parts = explode('?', $request_uri, 2);
$path       = $uri_parts[0];
$query_parts = isset($uri_parts[1]) ? explode('&', $uri_parts[1]) : [];
$clean_parts = [];

foreach ($query_parts as $part) {
    $part = trim($part);
    if (empty($part)) continue;
    // 跳过认证参数
    if (strpos($part, 'auth_step=') === 0 || strpos($part, 'redirect=') === 0) continue;
    // 跳过端口参数
    if (strpos($part, '=') !== false) {
        [$key] = explode('=', $part, 2);
        $key = urldecode($key);
        if ($key === 'p' || $key === 'port') continue;
    } elseif (is_numeric($part)) {
        continue; // 裸数字端口
    }
    $clean_parts[] = $part;
}

$clean_uri = $path . (!empty($clean_parts) ? '?' . implode('&', $clean_parts) : '');

// 构建目标 URL
$redirect_url = $target_scheme . '://' . $target_ip;
if (!empty($target_port) && $target_port !== '80' && $target_port !== '443') {
    $redirect_url .= ':' . $target_port;
}
$redirect_url .= $clean_uri;

header('Location: ' . $redirect_url, true, 302);
exit();
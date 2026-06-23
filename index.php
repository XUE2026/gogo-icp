<?php
// 从环境变量读取目标IP（部署时在Vercel设置，敏感变量）
$target_ip = getenv('TARGET_IP');
if (empty($target_ip)) {
    http_response_code(500);
    exit('Error: TARGET_IP environment variable is not set.');
}

// 从环境变量读取目标端口（默认80）
$target_port = getenv('TARGET_PORT');
if (empty($target_port)) {
    $target_port = '80';
}

// 从环境变量读取目标协议（默认http，如果目标支持https可改）
$target_scheme = getenv('TARGET_SCHEME');
if (empty($target_scheme)) {
    $target_scheme = 'http';
}

// 获取用户请求的完整URI（路径+查询参数，如 /abc/def?x=1）
$request_uri = $_SERVER['REQUEST_URI'];
if (empty($request_uri)) {
    $request_uri = '/';
}

// 构建跳转URL（保留路由和端口）
$redirect_url = $target_scheme . '://' . $target_ip;
if ($target_port != '80' && $target_port != '443') {
    $redirect_url .= ':' . $target_port;
}
$redirect_url .= $request_uri;

// 执行302临时重定向（浏览器地址栏会变成目标IP的URL）
header('Location: ' . $redirect_url, true, 302);
exit();
?>
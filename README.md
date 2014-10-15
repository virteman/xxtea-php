# XXTEA for PHP

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for PHP.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts string instead of uint32 array, and the key is also string.

## Installation

Download the xxtea.php, and put it in your develepment directory.

## Usage

```php
<?php
    require_once("xxtea.php");
    $str = "Hello World! 你好，中国！";
    $key = "1234567890";
    $encrypt_data = xxtea_encrypt($str, $key);
    $decrypt_data = xxtea_decrypt($encrypt_data, $key);
    if ($str == $decrypt_data) {
        echo "success!";
    } else {
        echo "fail!";
    }
?>
```
```php
<?php
    //class oo usage
    require_once "xxtea_class.php";
    $str = "Hello World! 你好，中国！";
    $key = "1234567890";
    $encrypt_data = XXTEA::encrypt($str, $key);
    $decrypt_data = XXTEA::decrypt($encrypt_data, $key);
    if ($str == $decrypt_data) {
        echo "success!";
    } else {
        echo "fail!";
    }

````

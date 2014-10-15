<?php
/**
 *                                                    
 * XXTEA::class.php                                    
 *                                                    
 * XXTEA encryption algorithm library for PHP.        
 *                                                    
 * Encryption Algorithm Authors:                      
 *      David J. Wheeler                              
 *      Roger M. Needham                              
 *                                                    
 * Code Author: Ma Bingyao <mabingyao@gmail.com>      
 *
 * OO version base on ma bingyao's function version
 *
 * @author virteman@qq.com
 *                                                    
 */

class XXTEA {

	const "XXTEA_DELTA" = 0x9E3779B9;

	//long int convert to string
    private static function long2str($v, $w) {
        $len = count($v);
        $n = ($len - 1) << 2;
        if ($w) {
            $m = $v[$len - 1];
            if (($m < $n - 3) || ($m > $n)) return false;
            $n = $m;
        }
        $s = array();
        for ($i = 0; $i < $len; $i++) {
            $s[$i] = pack("V", $v[$i]);
        }
        if ($w) {
            return substr(join('', $s), 0, $n);
        }
        else {
            return join('', $s);
        }
    }

    private static function str2long($s, $w) {
        $v = unpack("V*", $s. str_repeat("\0", (4 - strlen($s) % 4) & 3));
        $v = array_values($v);
        if ($w) {
            $v[count($v)] = strlen($s);
        }
        return $v;
    }

    private static function int32($n) {
    	return ($n & 0xffffffff);
    }

    private static function mx($sum, $y, $z, $p, $e, $k) {
        return ((($z >> 5 & 0x07ffffff) ^ $y << 2) + (($y >> 3 & 0x1fffffff) ^ $z << 4)) ^
               (($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z));
    }

    private static function fixk($k) {
        if (count($k) < 4) {
            for ($i = count($k); $i < 4; $i++) {
                $k[$i] = 0;
            }
        }
        return $k;
    }
    /**
     * @param $str is the string to be encrypted.
     * @param $key is the decrypt key. It is the same as the encrypted key.
     */
    public static function encrypt($str, $key) {
        if ($str == "") {
            return "";
        }
        $v = XXTEA::str2long($str, true);
        $k = XXTEA::fixk(XXTEA::str2long($key, false));
        $n = count($v) - 1;
        $z = $v[$n];
        $y = $v[0];
        $q = floor(6 + 52 / ($n + 1));
        $sum = 0;
        while (0 < $q--) {
            $sum = XXTEA::int32($sum + XXTEA_DELTA);
            $e = $sum >> 2 & 3;
            for ($p = 0; $p < $n; $p++) {
                $y = $v[$p + 1];
                $z = $v[$p] = XXTEA::int32($v[$p] + XXTEA::mx($sum, $y, $z, $p, $e, $k));
            }
            $y = $v[0];
            $z = $v[$n] = XXTEA::int32($v[$n] + XXTEA::mx($sum, $y, $z, $p, $e, $k));
        }
        return XXTEA::long2str($v, false);
    }

    /**
     * @param $str is the string to be decrypted.
     * @param $key is the decrypt key. It is the same as the encrypt key.
     */
    public static function decrypt($str, $key) {
        if ($str == "") {
            return "";
        }
        $v = XXTEA::str2long($str, false);
        $k = XXTEA::fixk(XXTEA::str2long($key, false));
        $n = count($v) - 1;

        $z = $v[$n];
        $y = $v[0];
        $q = floor(6 + 52 / ($n + 1));
        $sum = XXTEA::int32($q * XXTEA_DELTA);
        while ($sum != 0) {
            $e = $sum >> 2 & 3;
            for ($p = $n; $p > 0; $p--) {
                $z = $v[$p - 1];
                $y = $v[$p] = XXTEA::int32($v[$p] - XXTEA::mx($sum, $y, $z, $p, $e, $k));
            }
            $z = $v[$n];
            $y = $v[0] = XXTEA::int32($v[0] - XXTEA::mx($sum, $y, $z, $p, $e, $k));
            $sum = XXTEA::int32($sum - XXTEA_DELTA);
        }
        return XXTEA::long2str($v, true);
    }
}
?>

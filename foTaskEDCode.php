<?php

/**
 * 加密算法
 * @auther yzy
 * @time  2024年1月24日
 */
class FoTask
{
    /**
     * @var string[]  map
     */
    protected $pkKey='yzy';

    function setPkKey($k)
    {
        if (strlen($k)>4 ) return false;
        $this->pkKey = $k;
    }
    protected $foTaskMap = [
        0 => "灵",
        1 => "易",
        2 => "尔",
        3 => "叁",
        4 => "饲",
        5 => "伍",
        6 => "陆",
        7 => "妻",
        8 => "捌",
        9 => "酒",
        '+' => '加',
        '-' => '减',
        '/' => '杠',
        'a' => '汝',
        'b' => '施',
        'c' => '诸',
        'd' => '佛',
        'e' => '纳',
        'f' => '付',
        'g' => '诛',
        'h' => '哈',
        'i' => '隘',
        'j' => '卐',
        'k' => '克',
        'l' => '衲',
        'n' => '尼',
        'm' => '魔',
        'o' => '噢',
        'p' => '披',
        'q' => '签',
        'r' => '日',
        's' => '斯',
        't' => '嚏',
        'u' => '痴',
        'v' => '次',
        'w' => '问',
        'x' => '薛',
        'y' => '游',
        'z' => '转',
        'A' => '乳',
        'B' => '军',
        'C' => '充',
        'D' => '都',
        'E' => '饿',
        'F' => '放',
        'G' => '该',
        'H' => '会',
        'I' => '习',
        'J' => '界',
        'K' => '坑',
        'L' => '楼',
        'N' => '内',
        'M' => '嘛',
        'O' => '嚄',
        'P' => '拍',
        'Q' => '切',
        'R' => '热',
        'S' => '刷',
        'T' => '图',
        'U' => '㓗',
        'V' => '本',
        'W' => '无',
        'X' => '修',
        'Y' => '永',
        'Z' => '证',
    ];

    function foTaskEncode($code)
    {
        $lst = '';
        $code = base64_encode($code);
        $dengyuPw = 0;

        for ($i = 0; $i < mb_strlen($code); $i++) {
            $char = mb_substr($code, $i, 1);

            if ($char == '=') {
                $dengyuPw++;
                continue;
            }
            $lst .= $this->foTaskMap[$char].iconv("GB2312","UTF-8",chr(rand(180,240)));

        }
        $dengyuPw == 1 && $dengyu = "阿托伐";
        $dengyuPw == 2 && $dengyu = "阿弥陀佛";
        $lst = "佛曰：" . $lst . $dengyu;
        return $lst;
    }

    function foTaskDecode($code)
    {
        $code = substr($code, 9);
        $map = array_flip($this->foTaskMap);
        $last = '';
        if (strstr($code, '阿弥陀佛')) $last = '==';
        if (strstr($code, '阿托伐')) $last = '=';
        $code = explode('阿弥陀佛', $code);
        $code = $code[0];
        $code = explode('阿托伐', $code);
        $code = $code[0];
        $lst = '';
        for ($i = 0; $i < mb_strlen($code); $i++) {
            $char = mb_substr($code, $i, 1);
            $lst .= $map[$char];
        }
        return base64_decode($lst . $last);
    }



    function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {
        // 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
        $ckey_length = 4;
        // 密匙
        $key = md5($key ? $key :$this->pkKey);
        // 密匙a会参与加解密
        $keya = md5(substr($key, 0, 16));
        // 密匙b会用来做数据完整性验证
        $keyb = md5(substr($key, 16, 16));
        // 密匙c用于变化生成的密文
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';
        // 参与运算的密匙
        $cryptkey = $keya.md5($keya.$keyc);
        $key_length = strlen($cryptkey);
        // 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)，解密时会通过这个密匙验证数据完整性
        // 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确
        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
        $string_length = strlen($string);
        $result = '';
        $box = range(0, 255);
        $rndkey = array();
        // 产生密匙簿
        for($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        // 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上对并不会增加密文的强度
        for($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        // 核心加解密部分
        for($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            // 从密匙簿得出密匙进行异或，再转成字符
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if($operation == 'DECODE') {
            // substr($result, 0, 10) == 0 验证数据有效性
            // substr($result, 0, 10) - time() > 0 验证数据有效性
            // substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16) 验证数据完整性
            // 验证数据有效性，请看未加密明文的格式
            if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
                return substr($result, 26);
            } else {
                return '';
            }
        } else {
            // 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因
            // 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码
            return $keyc.str_replace('=', '', base64_encode($result));
        }
    }

}
$fo = new FoTask();
//$code = $fo->foTaskEncode($code);
//var_dump($code);
//
//$de = $fo->foTaskDecode($code);
//var_dump($de);
$fo->setPkKey('yzy');
if (!empty($_POST['r'])) echo  $fo->foTaskEncode($fo->authcode($_POST['r'],1));
if (!empty($_POST['f'])) echo  $fo->authcode($fo->foTaskDecode($_POST['f']));
<?php

error_reporting(E_ALL);
ini_set("memory_limit", "10M");

$opt = getopt('i:e:');
$dev = $opt['i'] ?? "any";
$exp = $opt['e'] ?? "tcp";

tcpsniff($dev, $exp, function (array $pktHdr, array $ipHdr, array $tcpHdr, array $tcpOpt, $payload) {
    $t = fmt_ts($pktHdr["ts"]);

    $flags = $tcpHdr["th_flags"];
    $seq = $tcpHdr["th_seq"];
    $ack = $tcpHdr["th_ack"];
    
    $ipSrc = long2ip($ipHdr["ip_src"]);
    $ipDst = long2ip($ipHdr["ip_dst"]);
    $src = "{$ipSrc}:{$tcpHdr["th_sport"]}";
    $dst = "{$ipDst}:{$tcpHdr["th_dport"]}";

	$flags = fmt_flags($flags);
	$len = strlen($payload);
	$win = $tcpHdr["th_win"] * (2 ** $tcpOpt["snd_wscale"]);
	echo "$t $src -> $dst $flags seq $seq, ack $ack, win $win, len $len\n";
	if ($len) {
        echo Hex::dump($payload);
    }
    echo "\n";
});

function fmt_flags($flags)
{
	$str = [];
	if ($flags & TH_SYN) {
		$str[] = "SYN";
	}
	if ($flags & TH_ACK) {
		$str[] = "ACK";
	}
	if ($flags & TH_PUSH) {
		$str[] = "PSH";
	}
	if ($flags & TH_FIN) {
		$str[] = "FIN";
	}
	if ($flags & TH_RST) {
		$str[] = "RST";
	}
	return implode(" ", $str);
}

function fmt_ts($ts)
{
    $now = DateTime::createFromFormat("U.u", $ts);
    if ($now === false) { // 无小数点不满足.u格式
        return date("H:i:s", $ts);
    }
    $now->setTimeZone(new DateTimeZone('Asia/Shanghai'));
    return rtrim($now->format("H:i:s.u"), "0");
}

class Hex
{
    /**
     * @param string $str
     * @param int $nCols n columns
     * @param int $nHexs n hexs per column
     * @param string $sep separation between column
     * @param string $placeholder placeholder for invisible char
     * @return string
     */
    public static function dump($str, $nCols = 8, $nHexs = 4, $sep = " ", $placeholder = ".")
    {
        // 两个hex一个char, 必须凑成偶数
        $nHexs = $nHexs % 2 === 0 ? $nHexs : $nHexs + 1;
        $halfPerGroup = $nHexs / 2;

        $hexLines = str_split(bin2hex($str), $nCols * $nHexs);
        $charLines = str_split(static::toASCII($str, $placeholder), $nCols * $halfPerGroup);

        $lineHexWidth = $nCols * $nHexs + strlen($sep) * ($nCols - 1);

        $buffer = "";

        $offset = 0;
        foreach ($hexLines as $i => $line) {
            $hexs = static::split($line, $nHexs, $sep);
            $chars = $charLines[$i];

            $buffer .= sprintf("0x%06s: %-{$lineHexWidth}s  %s" . PHP_EOL, dechex($offset), $hexs, $chars);
            $offset += $nCols;
        }

        return $buffer;
    }

    private static function split($str, $len, $sep)
    {
        return implode($sep, str_split($str, $len));
    }

    private static function toASCII($str, $placeholder = ".")
    {
        static $from = "";
        static $to = "";

        if ($from == "") {
            for ($char = 0; $char <= 0xFF; $char++) {
                $from .= chr($char);
                $to .= ($char >= 0x20 && $char <= 0x7E) ? chr($char) : $placeholder;
            }
        }

        return strtr($str, $from, $to);
    }
}

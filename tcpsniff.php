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
    echo "$t $src -> $dst $flags seq $seq, ack $ack, len $len\n";
	/*if ($tcpOpt["snd_wscale"]) {
		print_r($tcpOpt);
	}*/
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

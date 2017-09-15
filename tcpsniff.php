<?php

// TODO: undeclareclass
// TODO: undeffunc

error_reporting(E_ALL);
ini_set("memory_limit", "10M");

$opt = getopt('i:e:');
$dev = $opt['i'] ?? "any";
$exp = $opt['e'] ?? "tcp";

tcpsniff($dev, $exp, function($pktHdr, $ipHdr, $tcpHdr, $payload) {
// tcpsniff("lo0", "tcp and port 9999", function($pktHdr, $ipHdr, $tcpHdr, $payload) {
	$t = ts_fmt($pktHdr["ts"]);

	$flags = $tcpHdr["th_flags"];
	$seq = $tcpHdr["th_seq"];
	$ack = $tcpHdr["th_ack"];
	
	$ipSrc = long2ip($ipHdr["ip_src"]);
	$ipDst = long2ip($ipHdr["ip_dst"]);
	$src = "{$ipSrc}:{$tcpHdr["th_sport"]}";
	$dst = "{$ipDst}:{$tcpHdr["th_dport"]}";

	if ($flags & TH_FIN) {
		echo "$t FIN $src -> $dst seq $seq, ack $ack\n";
	} else if ($flags & TH_SYN) {
		echo "$t SYN $src -> $dst seq $seq, ack $ack\n";
	} else if ($flags & TH_RST) {
		echo "$t RST $src -> $dst seq $seq, ack $ack\n";
	} else if ($flags & TH_PUSH) {
		echo "$t PSH $src -> $dst seq $seq, ack $ack\n";
		echo bin2hex($payload), "\n";
	} else if ($flags & TH_ACK) {
		echo "$t ACK $src -> $dst seq $seq, ack $ack\n";
	}
});

function isClose($tcpFlags) {
	return $tcpFlags & TH_FIN || $tcpFlags & TH_RST;
}

function ts_fmt($ts) {
	$now = DateTime::createFromFormat("U.u", $ts);
	if ($now === false) { // 无小数点不满足.u格式
		return date("H:i:s", $ts);
	}
	$now->setTimeZone(new DateTimeZone('Asia/Shanghai'));
	return $now->format("H:i:s.u");
}
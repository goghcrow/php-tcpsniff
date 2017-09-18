<?php


// example

$tcpsniff = new TCPSniff();
$tcpsniff->on(TCPSniff::EVT_SESSION, function(TCPSession $session) {
    $session->once(TCPSession::EVT_CONNECT, function(TCPSession $session) {
        echo "CONNECT $session\n";
    });
    $session->once(TCPSession::EVT_CLOSE, function(TCPSession $session) {
        echo "CLOSE $session\n";
    });
    $session->on(TCPSession::EVT_SEND, function(TCPSession $session) {
        echo "SEND $session len $session->payloadLen\n";
        echo $session->payload, "\n";
    });
    $session->on(TCPSession::EVT_RECEIVE, function(TCPSession $session) {
        echo "RCVD $session len $session->payloadLen\n";
        echo $session->payload, "\n";
    });
});
$tcpsniff->start();


//////////////////////////////////////////////////////////////////////////////////////

class EventEmitter
{
    const ADD = "newListener";
    const REMOVE = "removeListener";
    const ERROR = "error";

    protected $eventHandlers = [];

    /**
     * @param $event
     * @param array ...$args
     * @return bool
     * @throws \Throwable
     *
     * EventEmitter::emit(EventEmitter::ERROR, new \Exception());
     */
    public function emit($event, ...$args)
    {
        if (isset($this->eventHandlers[$event])) {
            foreach ($this->eventHandlers[$event] as $listener) {
                try {
                    $listener(...$args);
                } catch (\Throwable $ex) {
                    if ($event === static::ERROR || !isset($this->eventHandlers[static::ERROR])) {
                        throw $ex;
                    }
                    $this->emit(static::ERROR, $event, $ex, ...$args);
                }
            }
            return true;
        } else {
            if ($event === static::ERROR) {
                throw $args[0];
            }
            return false;
        }
    }

    public function on($event, callable $listener, $prepend = false)
    {
        if (!isset($this->eventHandlers[$event])) {
            $this->eventHandlers[$event] = [];
        }

        // 避免递归emit Add事件, 先emit再add
        if (isset($this->eventHandlers[static::ADD])) {
            $this->emit(static::ADD, $event, $listener);
        }

        if ($prepend) {
            array_unshift($this->eventHandlers[$event], $listener);
        } else {
            $this->eventHandlers[$event][] = $listener;
        }

        return $this;
    }

    public function once($event, callable $listener, $prepend = false)
    {
        return $this->on($event, $this->onceWrap($event, $listener), $prepend);
    }

    /**
     * @param string|null $event
     * @param callable|null $listener
     * @return $this
     *
     * remove(type, listener) 移除type事件的listener
     * remove(type) 移除type事件所有listener
     * remote() 移除EventEmitter所有type的所有listener
     */
    public function remove($event = null, callable $listener = null) {
        if ($event === null) {
            assert($listener === null);
        }

        if ($listener === null) {
            $this->removeAllListeners($event);
        } else {
            $this->removeListener($event, $listener);
        }

        return $this;
    }

    private function removeListener($event, callable $listener)
    {
        if (!isset($this->eventHandlers[$event])) {
            return;
        }

        foreach ($this->eventHandlers[$event] as $key => $listener_) {
            if ($listener === $listener_) {
                unset($this->eventHandlers[$event][$key]);
                // 没有listener, 清空type, 可以使用isset(eventHandlers[type]) 方便判断
                if (empty($this->eventHandlers[$event])) {
                    unset($this->eventHandlers[$event]);
                }

                if (isset($this->eventHandlers[static::REMOVE])) {
                    $this->emit(static::REMOVE, $event, $listener);
                }
                break;
            }
        }
    }

    private function removeAllListeners($event = null)
    {
        if (isset($this->eventHandlers[static::REMOVE])) {
            if ($event === null) {
                foreach ($this->eventHandlers as $event => $_) {
                    if ($event === static::REMOVE) {
                        continue;
                    }
                    $this->removeAllListeners($event);
                }
                $this->removeAllListeners(static::REMOVE);
            } else {
                if (isset($this->eventHandlers[$event])) {
                    // LIFO order
                    $listeners = array_reverse($this->eventHandlers[$event]);
                    foreach ($listeners as $listener) {
                        $this->removeListener($event, $listener);
                    }
                }
            }
        } else {
            if ($event === null) {
                $this->eventHandlers = [];
            } else {
                unset($this->eventHandlers[$event]);
            }
        }
    }

    private function onceWrap($event, callable $listener)
    {
        return $g = function(...$args) use($event, $listener, &$g) {
            // 一次性事件自动移除
            $this->removeListener($event, $g);
            $listener(...$args);
        };
    }
}

class TCPSniff extends EventEmitter
{
    const EVT_SESSION = "session";

    private $dev;
    private $filter;

    /**
     * @var TCPSession[]
     */
    private $sessions = [];

    public function __construct($dev = "any", $filter = "tcp")
    {
        $this->dev = $dev;
        $this->filter = $filter;
    }

    public function start()
    {
        return tcpsniff($this->dev, $this->filter, [$this, "onSegmentReceived"]);
    }

    public function onSegmentReceived(array $pktHdr, array $ipHdr, array $tcpHdr, array $tcpOpt, $payload)
    {
        $frame = new PktHdr();
        $frame->caplen = $pktHdr["caplen"];
        $frame->len = $pktHdr["len"];
        $frame->ts = $pktHdr["ts"];

        $packet = new IPHdr();
        $packet->hdrLen = $ipHdr["ip_hl"];
        $packet->ver = $ipHdr["ip_v"];
        $packet->tos = $ipHdr["ip_tos"];
        $packet->len = $ipHdr["ip_len"];
        $packet->id = $ipHdr["ip_id"];
        $packet->ttl = $ipHdr["ip_ttl"];
        $packet->protocol = $ipHdr["ip_p"];
        $packet->sum = $ipHdr["ip_sum"];
        $packet->sIP = long2ip($ipHdr["ip_src"]);
        $packet->dIP = long2ip($ipHdr["ip_dst"]);
        //
        // $packet->sHost = gethostbyname($packet->sIP);
        // $packet->dHost = gethostbyname($packet->dIP);

        $segment = new TCPHdr();
        $segment->sPort = $tcpHdr["th_sport"];
        $segment->dPort = $tcpHdr["th_dport"];
        $segment->seqNum = $tcpHdr["th_seq"];
        $segment->ackNum = $tcpHdr["th_ack"];
        $segment->offset = $tcpHdr["th_off"];
        $segment->flags = $tcpHdr["th_flags"];
        $segment->win = $tcpHdr["th_win"];
        $segment->checkSum = $tcpHdr["th_sum"];
        $segment->urp = $tcpHdr["th_urp"];

        $flags = $tcpHdr["th_flags"];
        $segment->FIN = $flags & TCPFlag::FIN;
        $segment->SYN = $flags & TCPFlag::SYN;
        $segment->RST = $flags & TCPFlag::RST;
        $segment->PSH = $flags & TCPFlag::PSH;
        $segment->ACK = $flags & TCPFlag::ACK;
        $segment->URG = $flags & TCPFlag::URG;
        $segment->ECE = $flags & TCPFlag::ECE;
        $segment->CWR = $flags & TCPFlag::CWR;

        $segment->rcvTsVal = $tcpOpt["rcv_tsval"];
        $segment->rcvTsEcr = $tcpOpt["rcv_tsecr"];
        $segment->sackOk = $tcpOpt["sack_ok"];
        $segment->sndWinScale = $tcpOpt["snd_wscale"];
        $segment->mssClamp = $tcpOpt["mss_clamp"];

        $key = $this->sessionKey($packet, $segment);

        if (isset($this->sessions[$key])) {
            $new = false;
        } else {
            $new = true;
            $session = new TCPSession();
            $session->on(TCPSession::EVT_CLOSE, function() use($key) {
                if (function_exists("swoole_timer_after")) {
                    swoole_timer_after(1000, function() use($key) {
                        unset($this->sessions[$key]);
                    });
                } else {
                    // $this->sessions 在any模式，网卡中转数据数据包重复会导致内存sessions数据不断增长
                    unset($this->sessions[$key]);
                }
            });
            $this->sessions[$key] = $session;

        }
        $session = $this->sessions[$key];
        $session->trackPacket($frame, $packet, $segment, $payload);

        if ($new) {
            $this->emit(static::EVT_SESSION, $session);
            // is_new && estab 不一定是 三次握手, 可能packet携带数据
            if ($session->state === TCPState::ESTABLISHED) {
                $session->stateChange();
            }
        }
    }

    private function sessionKey(IPHdr $packet, TCPHdr $segment)
    {
        $src = "{$packet->sIP}:{$segment->sPort}";
        $dst = "{$packet->dIP}:{$segment->dPort}";

        if ($src < $dst) {
            $key = "$src-$dst";
        } else {
            $key = "$dst-$src";
        }
        return $key;
    }
}


class TCPSession extends EventEmitter
{
    const EVT_SEND = "send";
    const EVT_RECEIVE = "receive";
    const EVT_CONNECT = "connect";
    const EVT_CLOSE = "close";

    /**
     * @var PktHdr
     */
    public $frame;
    /**
     * @var IPHdr
     */
    public $packet;
    /**
     * @var TCPHdr
     */
    public $segment;
    public $payload;
    public $payloadLen;

    public $state;

    public $src;
    public $dst;
    public $missedSyn;
    public $sndISN;
    public $sndNxtSeq;
    public $rcvISN;
    public $sndPkts = [];
    public $rcvPkts = [];

    public function trackPacket(PktHdr $frame, IPHdr $packet, TCPHdr $segment, $payload)
    {
        $this->frame = $frame;
        $this->packet = $packet;
        $this->segment = $segment;
        $this->payload = $payload;
        $this->payloadLen = strlen($payload);

        if ($this->state === null) {
            $this->src = "{$packet->sIP}:{$segment->sPort}";
            $this->dst = "{$packet->dIP}:{$segment->dPort}";

            if ($segment->SYN && !$segment->ACK) {
                $this->state = TCPState::SYN_SENT;
            } else {
                // 这里可能在三次握手或者挥手中
                // 在establish中检查是否是FIN
                $this->missedSyn = true;
                $this->state = TCPState::ESTABLISHED;
            }
            $this->sndISN = $segment->seqNum; // initialize seq num
            $this->sndNxtSeq = $segment->seqNum + 1;
        } else if ($segment->SYN && !$segment->ACK) {
            // 这里可能是重发syn包, 也可能因为VPN软件虚拟网卡, any模式下,数据包重复
        } else {
            $this->stateChange();
        }
    }

    public function stateChange()
    {
        switch ($this->state) {
            case TCPState::SYN_SENT:
                $this->synSent();
                break;
            case TCPState::SYN_RECEIVED:
                $this->synReceived();
                break;
            case TCPState::ESTABLISHED:
                $this->established();
                break;
            case TCPState::FIN_WAIT_1:
            case TCPState::FIN_WAIT_2:
                $this->finWait();
                break;
            case TCPState::CLOSE_WAIT:
                $this->closeWait();
                break;
            case TCPState::LAST_ACK:
                $this->lastAck();
                break;
            case TCPState::CLOSING:
                $this->closing();
                break;
            case TCPState::CLOSED:
                $this->closed();
                break;
        }
    }

    private function synSent()
    {
        $src = $this->currentSrc();
        $synAck = $this->segment->SYN && $this->segment->ACK;
        if ($src === $this->dst && $synAck) {
            $this->rcvISN = $this->segment->seqNum;
            $this->state = TCPState::SYN_RECEIVED;
        } else if($this->segment->RST) {
            $this->state = TCPState::CLOSED;
            $this->emit(static::EVT_CLOSE, $this);
        }
    }

    private function synReceived()
    {
        $src = $this->currentSrc();
        if ($src === $this->src && $this->segment->ACK) {
            $this->emit(static::EVT_CONNECT, $this);
            $this->state = TCPState::ESTABLISHED;
        }
    }

    private function established()
    {
        // 连接另一端到达ESTABLISHED状态： establish 三次握手最后一次, 通过检查ack值，确认是establish...
        // if ($this->segment->seqAck ===  synAck -> seq + 1) {
        //     return;
        // }

        $src = $this->currentSrc();
        if ($src === $this->src) {
            if ($this->payloadLen) {
                if (isset($this->sndPkts[$this->segment->seqNum + $this->payloadLen])) {
                    // ignore retransmit
                } else {
                    $this->sndPkts[$this->segment->seqNum + $this->payloadLen] = true;
                    $this->emit(static::EVT_SEND, $this);
                }
            }
            if ($this->segment->FIN) {
                $this->state = TCPState::FIN_WAIT_1;
            }
            // rst ?
        } else if ($src === $this->dst) {
            if ($this->payloadLen) {
                if (isset($this->rcvPkts[$this->segment->seqNum + $this->payloadLen])) {
                    // ignore retransmit
                } else {
                    $this->rcvPkts[$this->segment->seqNum + $this->payloadLen] = true;
                    $this->emit(static::EVT_RECEIVE, $this);
                }
            }
            if ($this->segment->FIN) {
                $this->state = TCPState::CLOSE_WAIT;
            }
            // rst?
        }
    }

    // finWait1 finWait2 ... half close
    private function finWait()
    {
        $src = $this->currentSrc();
        if ($src === $this->dst && $this->segment->FIN) {
            $this->state = TCPState::CLOSING;
        } else {
            // time_wait?
        }
    }

    private function closeWait()
    {
        $src = $this->currentSrc();
        if ($src === $this->src && $this->segment->FIN) {
            $this->state = TCPState::LAST_ACK;
        }
    }

    private function lastAck()
    {
        $src = $this->currentSrc();
        if ($src === $this->dst) {
            $this->state = TCPState::CLOSED;
            $this->emit(static::EVT_CLOSE, $this);
        }
    }

    private function closing()
    {
        $src = $this->currentSrc();
        if ($src === $this->src) {
            $this->state = TCPState::CLOSED;
            $this->emit(static::EVT_CLOSE, $this);
        }
    }

    private function closed()
    {

    }

    private function currentSrc()
    {
        return "{$this->packet->sIP}:{$this->segment->sPort}";
    }

    public function __toString()
    {
        $sIP = $this->packet->sIP;
        $dIP = $this->packet->dIP;
        $sPort = $this->segment->sPort;
        $dPort = $this->segment->dPort;
        return "$sIP:$sPort -> $dIP:$dPort";
    }
}



class TCPState
{
    const CLOSED       = "CLOSED";
    const LISTEN       = "LISTEN";
    const SYN_SENT     = "SYN_SENT";
    const SYN_RECEIVED = "SYN_RECEIVED";
    const ESTABLISHED  = "ESTABLISHED";
    const CLOSE_WAIT   = "CLOSE_WAIT";
    const LAST_ACK     = "LAST_ACK";
    const FIN_WAIT_1   = "FIN_WAIT_1";
    const FIN_WAIT_2   = "FIN_WAIT_2";
    const CLOSING      = "CLOSING";
    const TIME_WAIT    = "TIME_WAIT";
};

class TCPFlag
{
    const FIN = TH_FIN;
    const SYN = TH_SYN;
    const RST = TH_RST;
    const PSH = TH_PUSH;
    const ACK = TH_ACK;
    const URG = TH_URG;
    const ECE = TH_ECE;
    const CWR = TH_CWR;
}

class PktHdr
{
    public $ts;
    public $caplen;
    public $len;
}

class IPHdr
{
    public $hdrLen;
    public $ver;
    public $tos;
    public $len;
    public $id;
    public $protocol;
    public $sum;
    public $ttl;
    public $sIP;
    public $dIP;

    public $sHost;
    public $dHost;
}

class TCPHdr
{
    public $flags;
    public $sPort;
    public $dPort;
    public $seqNum;
    public $ackNum;
    public $win;
    public $checkSum;
    public $urp;
    public $offset;

    public $FIN;
    public $SYN;
    public $RST;
    public $PSH;
    public $ACK;
    public $URG;
    public $ECE;
    public $CWR;

    // options
    public $rcvTsVal;
    public $rcvTsEcr;
    public $sackOk;
    public $sndWinScale;
    public $mssClamp;
}


if (false) {
    define("TH_FIN", 0x01);
    define("TH_SYN", 0x02);
    define("TH_RST", 0x04);
    define("TH_PUSH", 0x08);
    define("TH_ACK", 0x10);
    define("TH_URG", 0x20);
    define("TH_ECE", 0x40);
    define("TH_CWR", 0x80);

    /**
     * @param string $dev
     * @param string $filter
     * @param callable $handler
     * @param array|null $option
     * @return bool
     */
    function tcpsniff(string $dev, string $filter, callable $handler, array $option = null) { return false; }

    /**
     * @param array $pktHdr
     * @param array $ipHdr
     * @param array $tcpHdr
     * @param array $tcpOpt
     * @param string $payload
     */
    $handler = function(array $pktHdr, array $ipHdr, array $tcpHdr, array $tcpOpt, string $payload) {};
}
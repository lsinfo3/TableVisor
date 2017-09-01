-record(tcp, {
    sport = 0 :: pkt:in_port_t(),
    dport = 0 :: pkt:in_port_t(),
    seqno = 0 :: pkt:uint32_t(),
    ackno = 0 :: pkt:uint32_t(),
    off = 5 :: pkt:bit4(),
    ns  = 0 :: pkt:bit(),
    cwr = 0 :: pkt:bit(),
    ece = 0 :: pkt:bit(),
    urg = 0 :: pkt:bit(),
    ack = 0 :: pkt:bit(),
    psh = 0 :: pkt:bit(),
    rst = 0 :: pkt:bit(),
    syn = 0 :: pkt:bit(),
    fin = 0 :: pkt:bit(),
    win = 0 :: pkt:uint16_t(),
    sum = 0 :: pkt:uint16_t(),
    urp = 0 :: pkt:uint16_t(),
    opt = <<>> :: binary()
}).
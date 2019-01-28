use pcap_parser::{
    parse_pcap,
    parse_pcapng,
    Capture,
    Packet
};

pub struct Error;

pub fn try_parse_file<'a>(input: &'a[u8]) -> Result<Box<Capture + 'a>,Error> {
    // try pcapng
    match parse_pcapng(input) {
        Ok((_,capture)) => { return Ok(Box::new(capture)); },
        _               => ()
    }
    // try pcap
    match parse_pcap(input) {
        Ok((_,capture)) => { return Ok(Box::new(capture)); },
        _               => ()
    }
    Err(Error)
}

pub fn get_data_raw<'a>(packet: &'a Packet) -> &'a[u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[..maxlen]
}

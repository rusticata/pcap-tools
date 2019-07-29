use pcap_parser::*;

use nom::le_u64;

pub const MICROS_PER_SEC: u32 = 1_000_000;

#[derive(Debug,PartialEq,Eq)]
pub enum PcapType {
    Unknown,
    Pcap,
    PcapNG
}

pub struct InterfaceInfo {
    pub link_type: Linktype,
    pub if_tsresol: u8,
    pub if_tsoffset: u64,
    pub snaplen: u32,
}

impl InterfaceInfo {
    pub fn new() -> InterfaceInfo {
        InterfaceInfo{
            link_type: Linktype(0),
            if_tsresol: 0,
            if_tsoffset: 0,
            snaplen: 0,
        }
    }
}

pub struct Error;

pub fn pcapng_build_interface<'a>(idb: &'a InterfaceDescriptionBlock<'a>) -> InterfaceInfo {
    let link_type = idb.linktype;
    // extract if_tsoffset and if_tsresol
    let mut if_tsresol : u8 = 6;
    let mut if_tsoffset : u64 = 0;
    for opt in idb.options.iter() {
        match opt.code {
            OptionCode::IfTsresol  => { if !opt.value.is_empty() { if_tsresol =  opt.value[0]; } },
            OptionCode::IfTsoffset => { if opt.value.len() >= 8 { if_tsoffset = le_u64(opt.value).unwrap_or((&[],0)).1 /* LittleEndian::read_u64(opt.value) */; } },
            _ => (),
        }
    }
    let snaplen = idb.snaplen;
    InterfaceInfo{
        link_type, if_tsresol, if_tsoffset, snaplen
    }
}

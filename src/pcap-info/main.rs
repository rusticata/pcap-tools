extern crate pcap_tools;
use pcap_tools::common::*;

extern crate clap;
use clap::{Arg,App,crate_version};

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

extern crate nom;
extern crate pcap_parser;

use nom::error::ErrorKind;
use pcap_parser::*;

#[derive(Debug)]
struct Stats {
    pcap_type: PcapType,
    major: u16,
    minor: u16,
    big_endian: bool,
    num_packets: u32,
    num_bytes: u64,
    link_type: Linktype,
    shb_hardware: Option<String>,
    shb_os: Option<String>,
    shb_userappl: Option<String>,
}

impl Stats {
    pub fn new() -> Stats {
        Stats{
            pcap_type: PcapType::Unknown,
            major: 0,
            minor: 0,
            big_endian: false,
            num_packets: 0,
            num_bytes: 0,
            link_type: Linktype(0),
            shb_hardware: None,
            shb_os: None,
            shb_userappl: None,
        }
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let unknown = String::from("<Unknown>");
        fmt.write_str("Stats:\n")?;
        writeln!(fmt, "    Format: {:?}", self.pcap_type)?;
        writeln!(fmt, "    Version: {}.{}", self.major, self.minor)?;
        writeln!(fmt, "    Num packets: {}", self.num_packets)?;
        writeln!(fmt, "    Num bytes: {}", self.num_bytes)?;
        writeln!(fmt, "    Link type: {}", self.link_type)?;
        writeln!(fmt, "    Hardware: {}", self.shb_hardware.as_ref().unwrap_or(&unknown))?;
        writeln!(fmt, "    OS: {}", self.shb_os.as_ref().unwrap_or(&unknown))?;
        writeln!(fmt, "    Application: {}", self.shb_userappl.as_ref().unwrap_or(&unknown))?;
        writeln!(fmt, "")
    }
}

fn main() {
    let matches = App::new("Pcap info tool")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Display Pcap file information")
        .arg(Arg::with_name("verbose")
             .help("Be verbose")
             .short("v")
             .long("verbose"))
        .arg(Arg::with_name("INPUT")
             .help("Input file name")
             .required(true)
             .index(1))
        .get_matches();

    let input_filename = matches.value_of("INPUT").unwrap();
    let verbose = matches.is_present("verbose");

    if verbose {
        println!("Pcap information");
    }

    let path = Path::new(&input_filename);
    let display = path.display();
    let mut file = match File::open(path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(file) => file,
    };

    let metadata = file.metadata().unwrap();
    println!("File name: {}", input_filename);
    println!("File size: {}", metadata.len());

    let res = pcap_get_stats(&mut file);

    if let Ok(stats) = res {
        if verbose {
            println!("{}", stats);
            println!("Done.");
        }
    }
}

fn pcap_get_stats<R:Read>(f: &mut R) -> Result<Stats,&'static str> {
    let mut stats = Stats::new();

    let capacity = 65536;
    let mut interfaces = Vec::new();
    let mut reader = pcap_parser::create_reader(capacity, f)
        .or(Err("Error creating reader"))
        ?;
    let (offset, block) = reader.next()
        .or(Err("Error reading file header"))
        ?;
    match block {
        PcapBlockOwned::NG(Block::SectionHeader(ref shb)) => {
            stats.pcap_type = PcapType::PcapNG;
            stats.major = shb.major_version;
            stats.minor = shb.minor_version;
            stats.big_endian = shb.is_bigendian();
            for opt in &shb.options {
                match opt.code {
                    OptionCode::ShbHardware => {
                        let s = String::from_utf8_lossy(opt.value);
                        stats.shb_hardware = Some(String::from(s));
                    },
                    OptionCode::ShbOs => {
                        let s = String::from_utf8_lossy(opt.value);
                        stats.shb_os = Some(String::from(s));
                    },
                    OptionCode::ShbUserAppl => {
                        let s = String::from_utf8_lossy(opt.value);
                        stats.shb_userappl = Some(String::from(s));
                    },
                    _ => ()
                }
            }
        },
        PcapBlockOwned::LegacyHeader(ref hdr) => {
            let if_info = InterfaceInfo {
                link_type: hdr.network,
                if_tsresol: 0,
                if_tsoffset: 0,
                snaplen: hdr.snaplen,
            };
            interfaces.push(if_info);
            stats.pcap_type = PcapType::Pcap;
            stats.link_type = hdr.network;
            stats.major = hdr.version_major;
            stats.minor = hdr.version_minor;
            stats.big_endian = hdr.is_bigendian();
        },
        _ => unreachable!(),
    };
    reader.consume(offset);

    let mut last_incomplete_index = 0;
    let mut block_count = 1usize;
    let mut consumed = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                block_count += 1;
                match block {
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        interfaces = Vec::new();
                        consumed += offset;
                        reader.consume(offset);
                        continue;
                    },
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        let if_info = pcapng_build_interface(idb);
                        interfaces.push(if_info);
                        consumed += offset;
                        reader.consume(offset);
                        continue;
                    },
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < interfaces.len());
                        // let if_info = &interfaces[epb.if_id as usize];
                        // let (ts_sec, ts_frac, unit) = pcap_parser::build_ts(epb.ts_high, epb.ts_low, 
                        //                                                     if_info.if_tsoffset, if_info.if_tsresol);
                        // let unit = unit as u32; // XXX lossy cast
                        // let ts_usec = if unit != MICROS_PER_SEC {
                        //     ts_frac/ ((unit / MICROS_PER_SEC) as u32) } else { ts_frac };
                        // let data = pcap_parser::data::get_packetdata(epb.data, if_info.link_type, epb.caplen as usize)
                        //     .expect("Parsing PacketData failed");
                        stats.num_packets += 1;
                        stats.num_bytes += epb.caplen as u64;
                    },
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(interfaces.len() > 0);
                        // let if_info = &interfaces[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        // let data = pcap_parser::data::get_packetdata(spb.data, if_info.link_type, blen)
                        //     .expect("Parsing PacketData failed");
                        stats.num_packets += 1;
                        stats.num_bytes += blen as u64;
                    },
                    PcapBlockOwned::LegacyHeader(ref hdr) => {
                        eprintln!("Legacy pcap: second header ?!");
                        let if_info = InterfaceInfo{
                            link_type: hdr.network,
                            if_tsoffset: 0,
                            if_tsresol: 6,
                            snaplen: hdr.snaplen,
                        };
                        interfaces.push(if_info);
                        consumed += offset;
                        reader.consume(offset);
                        continue;
                    },
                    PcapBlockOwned::Legacy(ref b) => {
                        assert!(interfaces.len() > 0);
                        // let if_info = &interfaces[0];
                        // let blen = b.caplen as usize;
                        // let data = pcap_parser::data::get_packetdata(b.data, if_info.link_type, blen)
                        //     .expect("Parsing PacketData failed");
                        stats.num_packets += 1;
                        stats.num_bytes += b.caplen as u64;
                    },
                    PcapBlockOwned::NG(Block::InterfaceStatistics(_)) |
                        PcapBlockOwned::NG(Block::NameResolution(_)) => {
                            // XXX just ignore
                            consumed += offset;
                            reader.consume(offset);
                            continue;
                        },
                    _ => {
                        eprintln!("unsupported block");
                        consumed += offset;
                        reader.consume(offset);
                        continue;
                    }
                };
                        consumed += offset;
                reader.consume(offset);
                continue;
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::NomError(ErrorKind::Complete)) => {
                if last_incomplete_index == block_count {
                    eprintln!("*** Could not read complete data block.");
                    eprintln!("***     consumed: {} bytes", consumed);
                    eprintln!("*** Hint: the reader buffer size may be too small, or the input file nay be truncated.");
                    break;
                }
                last_incomplete_index = block_count;
                // refill the buffer
                eprintln!("refill");
                reader.refill().or(Err("Refill error"))?;
                continue;
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    let _ = block_count;

    Ok(stats)
}

extern crate pcap_tools;
use pcap_tools::common::*;

extern crate clap;
use clap::{crate_version, App, Arg};

use std::cmp::min;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process;

extern crate nom;
extern crate pcap_parser;

use nom::error::ErrorKind;
use pcap_parser::data::*;
use pcap_parser::*;
// use pcap_parser::Capture;

#[derive(Debug)]
struct Stats {
    num_packets: u32,
    num_bytes: u64,
}

fn main() {
    let matches = App::new("Pcap rewrite tool")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Rewrite Pcap file from one format to another")
        .arg(
            Arg::with_name("verbose")
                .help("Be verbose")
                .short("v")
                .long("verbose"),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Input file name")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("OUTPUT")
                .help("Output file name")
                .required(true)
                .index(2),
        )
        .get_matches();

    let input_filename = matches.value_of("INPUT").unwrap();
    let output_filename = matches.value_of("OUTPUT").unwrap();
    let verbose = matches.is_present("verbose");

    if verbose {
        eprintln!("Pcap rewrite tool");
    }

    let path = Path::new(&input_filename);
    let display = path.display();
    let mut file = match File::open(path) {
        Err(why) => {
            eprintln!("couldn't open {}: {}", display, why.description());
            process::exit(1);
        }
        Ok(file) => file,
    };

    let p = Path::new(&output_filename);
    let mut file_dest = File::create(&p).unwrap();

    match pcap_convert(&mut file, &mut file_dest) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("pcap rewrite failed: {}", e);
            process::exit(1);
        }
    }
}

fn pcap_convert<R: Read, W: Write>(from: &mut R, to: &mut W) -> Result<(), &'static str> {
    let capacity = 65536;
    let mut interfaces = Vec::new();
    let mut reader = pcap_parser::create_reader(capacity, from).or(Err("Error creating reader"))?;
    let (offset, block) = reader.next().or(Err("Error reading file header"))?;
    let in_pcap_type;
    let in_pcap_big_endian;
    match block {
        PcapBlockOwned::NG(Block::SectionHeader(ref shb)) => {
            in_pcap_type = PcapType::PcapNG;
            // stats.major = shb.major_version;
            // stats.minor = shb.minor_version;
            in_pcap_big_endian = shb.is_bigendian();
            // for opt in &shb.options {
            //     match opt.code {
            //         OptionCode::ShbHardware => {
            //             let s = String::from_utf8_lossy(opt.value);
            //             stats.shb_hardware = Some(String::from(s));
            //         },
            //         OptionCode::ShbOs => {
            //             let s = String::from_utf8_lossy(opt.value);
            //             stats.shb_os = Some(String::from(s));
            //         },
            //         OptionCode::ShbUserAppl => {
            //             let s = String::from_utf8_lossy(opt.value);
            //             stats.shb_userappl = Some(String::from(s));
            //         },
            //         _ => ()
            //     }
            // }
        }
        PcapBlockOwned::LegacyHeader(ref hdr) => {
            let if_info = InterfaceInfo {
                link_type: hdr.network,
                if_tsresol: 0,
                if_tsoffset: 0,
                snaplen: hdr.snaplen,
            };
            interfaces.push(if_info);
            in_pcap_type = PcapType::Pcap;
            // stats.link_type = hdr.network;
            // stats.major = hdr.version_major;
            // stats.minor = hdr.version_minor;
            in_pcap_big_endian = hdr.is_bigendian();
        }
        _ => unreachable!(),
    };
    reader.consume(offset);

    let mut last_incomplete_index = 0;
    let mut block_count = 1usize;
    let mut stats = Stats {
        num_packets: 0,
        num_bytes: 0,
    };

    let snaplen = 65535; // XXX
    let written = pcap_write_header(to, snaplen)?;
    stats.num_bytes += written as u64;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                block_count += 1;
                match block {
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        interfaces = Vec::new();
                        reader.consume(offset);
                        continue;
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        let if_info = pcapng_build_interface(idb);
                        interfaces.push(if_info);
                        reader.consume(offset);
                        continue;
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < interfaces.len());
                        let if_info = &interfaces[epb.if_id as usize];
                        let written = pcap_write_epb(to, epb, &if_info, snaplen)?;
                        stats.num_packets += 1;
                        stats.num_bytes += written;
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(interfaces.len() > 0);
                        // let if_info = &interfaces[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        // let data = pcap_parser::data::get_packetdata(spb.data, if_info.link_type, blen)
                        //     .expect("Parsing PacketData failed");
                        stats.num_packets += 1;
                        stats.num_bytes += blen as u64;
                    }
                    PcapBlockOwned::LegacyHeader(ref hdr) => {
                        eprintln!("Legacy pcap: second header ?!");
                        let if_info = InterfaceInfo {
                            link_type: hdr.network,
                            if_tsoffset: 0,
                            if_tsresol: 6,
                            snaplen: hdr.snaplen,
                        };
                        interfaces.push(if_info);
                        reader.consume(offset);
                        continue;
                    }
                    PcapBlockOwned::Legacy(ref b) => {
                        assert!(interfaces.len() > 0);
                        // let if_info = &interfaces[0];
                        // let blen = b.caplen as usize;
                        // let data = pcap_parser::data::get_packetdata(b.data, if_info.link_type, blen)
                        //     .expect("Parsing PacketData failed");
                        //                             let data = {
                        //                                 let data = parse_data(&packet);
                        //                                 if data.len() > snaplen as usize {
                        //                                     eprintln!("truncating block {} to {} bytes", block_count, snaplen);
                        //                                     &data[..snaplen as usize]
                        //                                 } else {
                        //                                     data
                        //                                 }
                        //                             };
                        let written = pcap_write_legacy_block(to, b, snaplen)?;
                        stats.num_packets += 1;
                        stats.num_bytes += written;
                    }
                    PcapBlockOwned::NG(Block::InterfaceStatistics(_))
                    | PcapBlockOwned::NG(Block::NameResolution(_)) => {
                        // XXX just ignore
                        reader.consume(offset);
                        continue;
                    }
                    _ => {
                        eprintln!("unsupported block");
                        reader.consume(offset);
                        continue;
                    }
                };
                reader.consume(offset);
                continue;
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::NomError(ErrorKind::Complete)) => {
                if last_incomplete_index == block_count {
                    eprintln!("Could not read complete data block.");
                    eprintln!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
                    break;
                }
                last_incomplete_index = block_count;
                // refill the buffer
                eprintln!("refill");
                reader.refill().or(Err("Refill error"))?;
                continue;
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    let _ = block_count;
    let _ = in_pcap_type;
    let _ = in_pcap_big_endian;

    eprintln!("Done.");
    eprintln!("stats: {:?}", stats);

    Ok(())
}

fn pcap_write_header<W: Write>(to: &mut W, snaplen: u32) -> Result<usize, &'static str> {
    let mut hdr = pcap_parser::PcapHeader::new();
    hdr.snaplen = snaplen;
    hdr.network = Linktype::IPV4;
    let s = hdr.to_vec();
    to.write(&s).or(Err("Couldn't write header"))?;
    Ok(s.len())
}

fn pcap_write_legacy_block<W: Write>(
    to: &mut W,
    block: &LegacyPcapBlock,
    snaplen: u32,
) -> Result<u64, &'static str> {
    // XXX truncate data to snaplen
    let s = block.to_vec();
    let sz = to.write(&s).or(Err("write error"))?;

    Ok(sz as u64)
}

fn pcap_write_epb<W: Write>(
    to: &mut W,
    epb: &EnhancedPacketBlock,
    if_info: &InterfaceInfo,
    snaplen: u32,
) -> Result<u64, &'static str> {
    let (ts_sec, ts_frac, unit) = pcap_parser::build_ts(
        epb.ts_high,
        epb.ts_low,
        if_info.if_tsoffset,
        if_info.if_tsresol,
    );
    let unit = unit as u32; // XXX lossy cast
    let ts_usec = if unit != MICROS_PER_SEC {
        ts_frac / ((unit / MICROS_PER_SEC) as u32)
    } else {
        ts_frac
    };
    let pdata = pcap_parser::data::get_packetdata(epb.data, if_info.link_type, epb.caplen as usize)
        .expect("Parsing PacketData failed");
    let caplen = min(snaplen, epb.caplen) as usize;
    let data = match pdata {
        PacketData::L2(data) => &data[14..], // XXX this can fail
        PacketData::L3(_, data) => data,
        PacketData::L4(_, _) => unimplemented!(),
        PacketData::Unsupported(_) => unimplemented!(),
    };
    // truncate data to snaplen
    let data = &data[..caplen];
    assert_eq!(caplen, data.len());
    let b = LegacyPcapBlock {
        ts_sec,
        ts_usec,
        caplen: caplen as u32,
        origlen: epb.origlen,
        data,
    };
    let s = b.to_vec();
    let sz = to.write(&s).or(Err("write error"))?;

    Ok(sz as u64)
}

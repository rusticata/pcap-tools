extern crate clap;
use clap::{Arg,App,crate_version};

extern crate circular;

use circular::Buffer;
use std::io::{Read,Write};

use std::error::Error;
use std::fs::File;
use std::path::Path;

use std::cmp::min;
use std::process;

extern crate pcap_parser;

use pcap_parser::*;
use pcap_parser::data::*;
// use pcap_parser::Capture;

extern crate nom;
use nom::HexDisplay;
use nom::{Needed,Offset};

extern crate pcap_tools;

use pcap_tools::common::*;

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
        .arg(Arg::with_name("verbose")
             .help("Be verbose")
             .short("v")
             .long("verbose"))
        .arg(Arg::with_name("INPUT")
             .help("Input file name")
             .required(true)
             .index(1))
        .arg(Arg::with_name("OUTPUT")
             .help("Output file name")
             .required(true)
             .index(2))
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
        },
        Ok(file) => file,
    };


    let p = Path::new(&output_filename);
    let mut file_dest = File::create(&p).unwrap();

    match pcap_convert(&mut file, &mut file_dest) {
        Ok(_)  => (),
        Err(e) => {
            eprintln!("pcap rewrite failed: {}", e);
            process::exit(1);
        }
    }
}

fn pcap_convert<R:Read, W:Write>(from: &mut R, to:&mut W) -> Result<(),&'static str> {
    let mut capacity = 16384;
    let buffer_max_size = 65536;
    let mut b = Buffer::with_capacity(capacity);
    let sz = from.read(b.space()).or(Err("unable to read data"))?;
    b.fill(sz);
    // println!("write {:#?}", sz);

    let mut stats = Stats{
        num_packets: 0,
        num_bytes: 0,
    };
    let mut parse_data : for<'a> fn (&'a Packet) -> &'a[u8] = get_data_raw;


    let (length,in_pcap_type) = {
        if let Ok((remaining,_h)) = pcapng::parse_sectionheaderblock(b.data()) {
            (b.data().offset(remaining), PcapType::PcapNG)
        } else if let Ok((remaining,h)) = pcap::parse_pcap_header(b.data()) {
            let link_type = Linktype(h.network);
            parse_data = get_linktype_parse_fn(link_type).ok_or("could not find function to decode linktype")?;
            (b.data().offset(remaining), PcapType::Pcap)
        } else {
            return Err("couldn't parse input file header")
        }
    };

    // println!("consumed {} bytes", length);
    b.consume(length);

    let snaplen = 65535; // XXX
    let written = pcap_write_header(to, snaplen)?;
    stats.num_bytes += written as u64;

    let mut block_count = 1usize;
    let mut consumed = length;
    let mut last_incomplete_offset = 0;

    loop {
        // refill the buffer
        let sz = from.read(b.space()).or(Err("unable to read data"))?;
        b.fill(sz);
        // println!("refill: {} more bytes, available data: {} bytes, consumed: {} bytes",
        //          sz, b.available_data(), consumed);

        // if there's no more available data in the buffer after a write, that means we reached
        // the end of the file
        if b.available_data() == 0 {
            // println!("no more data to read or parse, stopping the reading loop");
            break;
        }

        let needed: Option<Needed>;

        // println!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));

        match in_pcap_type {
            PcapType::Unknown => { return Err("unknown file type"); },
            PcapType::Pcap => {
                loop {
                    let length = {
                        // read block
                        match pcap::parse_pcap_frame(b.data()) {
                            Ok((remaining,packet)) => {
                                block_count += 1;
                                // eprintln!("parse_block ok, count {}", block_count);
                                // println!("parsed packet: {:?}", packet);
                                let data = {
                                    let data = parse_data(&packet);
                                    if data.len() > snaplen as usize {
                                        eprintln!("truncating block {} to {} bytes", block_count, snaplen);
                                        &data[..snaplen as usize]
                                    } else {
                                        data
                                    }
                                };
                                let written = pcap_write_packet(to, &packet, data)?;
                                stats.num_packets += 1;
                                stats.num_bytes += written as u64;
                                b.data().offset(remaining)
                            },
                            Err(nom::Err::Incomplete(n)) => {
                                // println!("not enough data, needs a refill: {:?}", n);

                                needed = Some(n);
                                break;
                            },
                            Err(nom::Err::Failure(e)) => {
                                eprintln!("parse failure: {:?}", e);
                                return Err("parse error");
                            },
                            Err(nom::Err::Error(_e)) => {
                                // panic!("parse error: {:?}", e);
                                eprintln!("parse error");
                                eprintln!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
                                return Err("parse error");
                            },
                        }
                    };

                    // println!("consuming {} of {} bytes", length, b.available_data());
                    b.consume(length);
                    consumed += length;
                }
            }
            PcapType::PcapNG => {
                let mut if_info = InterfaceInfo::new();
                loop {
                    let length = {
                        // read block
                        match pcapng::parse_block(b.data()) {
                            Ok((remaining,block)) => {
                                block_count += 1;
                                // eprintln!("parse_block ok, count {}", block_count);
                                // println!("parsed block: {:?}", block);
                                match block {
                                    Block::SectionHeader(ref _hdr) => {
                                        eprintln!("warning: new section header block");
                                    },
                                    Block::InterfaceDescription(ref ifdesc) => {
                                        if_info = pcapng_build_interface(ifdesc);
                                        parse_data = get_linktype_parse_fn(if_info.link_type).ok_or("could not find function to decode linktype")?;
                                    },
                                    Block::SimplePacket(_) |
                                    Block::EnhancedPacket(_) => {
                                        let packet = pcapng_build_packet(&if_info, &block).ok_or("could not convert block to packet")?;
                                        let data = {
                                            let data = parse_data(&packet);
                                            if data.len() > snaplen as usize {
                                                eprintln!("truncating block {} to {} bytes", block_count, snaplen);
                                                &data[..snaplen as usize]
                                            } else {
                                                data
                                            }
                                        };
                                        let written = pcap_write_packet(to, &packet, data)?;
                                        stats.num_packets += 1;
                                        stats.num_bytes += written as u64;
                                    },
                                    _ => (),
                                }
                                b.data().offset(remaining)
                            },
                            Err(nom::Err::Incomplete(n)) => {
                                // println!("not enough data, needs a refill: {:?}", n);

                                needed = Some(n);
                                break;
                            },
                            Err(nom::Err::Failure(e)) => {
                                eprintln!("parse failure: {:?}", e);
                                return Err("parse error");
                            },
                            Err(nom::Err::Error(_e)) => {
                                // panic!("parse error: {:?}", e);
                                eprintln!("parse error");
                                eprintln!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
                                return Err("parse error");
                            },
                        }
                    };

                    // println!("consuming {} of {} bytes", length, b.available_data());
                    b.consume(length);
                    consumed += length;
                }
            }
        }

        if let Some(Needed::Size(sz)) = needed {
            if sz > b.capacity() {
                // println!("growing buffer capacity from {} bytes to {} bytes", capacity, capacity*2);
                capacity = (capacity * 3) / 2;
                if capacity > buffer_max_size {
                    eprintln!("requesting capacity {} over buffer_max_size {}", capacity, buffer_max_size);
                    return Err("buffer size too small");
                }
                b.grow(capacity);
            } else {
                // eprintln!("incomplete, but less missing bytes {} than buffer size {} consumed {}", sz, capacity, consumed);
                if last_incomplete_offset == consumed {
                    eprintln!("seems file is truncated, exiting");
                    break;
                }
                last_incomplete_offset = consumed;
            }
        }
    }



    let _ = block_count;
    let _ = consumed;

    eprintln!("Done.");
    eprintln!("stats: {:?}", stats);

    Ok(())
}

fn wrap_get_data_nflog<'a>(packet: &'a Packet) -> &'a[u8] {
    get_data_nflog(packet).expect("extract data from nflog packet")
}

fn get_linktype_parse_fn(link_type:Linktype) -> Option<for<'a> fn (&'a Packet) -> &'a[u8]>
{
    // See http://www.tcpdump.org/linktypes.html
    let f : Option<for<'a> fn (&'a Packet) -> &'a[u8]> = match link_type {
        Linktype(0)     => Some(get_data_null),
        Linktype(1)     => Some(get_data_ethernet),
        Linktype(113)   => Some(get_data_linux_cooked),
        Linktype(228)   => Some(get_data_raw),
        Linktype::NFLOG => Some(wrap_get_data_nflog),
        _ => None
    };
    f
}

fn pcap_write_header<W:Write>(to:&mut W, snaplen:u32) -> Result <usize,&'static str> {
    let mut hdr = pcap_parser::PcapHeader::new();
    hdr.snaplen = snaplen;
    hdr.network = 228; // DATALINK_RAWIPV4
    let s = hdr.to_string();
    to.write(&s).or(Err("Couldn't write header"))?;
    Ok(s.len())
}

fn pcap_write_packet<W:Write>(to:&mut W, packet:&Packet, data:&[u8]) -> Result<usize,&'static str> {
    let rec_hdr = pcap_parser::PacketHeader{
        ts_sec: packet.header.ts_sec as u32,
        ts_usec: packet.header.ts_usec as u32,
        caplen: data.len() as u32, // packet.header.caplen,
        len: data.len() as u32, // packet.header.len,
    };
    // debug!("rec_hdr: {:?}", rec_hdr);
    // debug!("data (len={}): {}", data.len(), data.to_hex(16));
    let s = rec_hdr.to_string();
    let sz = to.write(&s).or(Err("write error"))? + to.write(&data).or(Err("write error"))?;

    Ok(sz)
}

extern crate clap;
use clap::{Arg,App,crate_version};

extern crate circular;

use circular::Buffer;
use std::io::Read;

use std::cmp::min;
use std::error::Error;
use std::fs::File;
use std::path::Path;

use std::fmt;

extern crate pcap_parser;

use pcap_parser::*;

extern crate nom;
use nom::HexDisplay;
use nom::{Needed,Offset};

extern crate pcap_tools;
use pcap_tools::common;
use common::PcapType;

#[derive(Debug)]
struct Stats {
    pcap_type: PcapType,
    major: u16,
    minor: u16,
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

    let mut capacity = 16384;
    let buffer_max_size = 65536;
    let mut b = Buffer::with_capacity(capacity);
    let sz = f.read(b.space()).expect("should write");
    b.fill(sz);
    // println!("write {:#?}", sz);

    let length = {
        // parse the section header
        let res = parse_sectionheaderblock(b.data());

        // `available_data()` returns how many bytes can be read from the buffer
        // `data()` returns a `&[u8]` of the current data
        // `to_hex(_)` is a helper method of `nom::HexDisplay` to print a hexdump of a byte slice
        // println!("data({} bytes):\n{}", b.available_data(), (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
        if let Ok((remaining, h)) = res {
            // println!("parsed header: {:?}", h);
            stats.pcap_type = PcapType::PcapNG;
            stats.major = h.major_version;
            stats.minor = h.minor_version;
            for opt in h.options {
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

            // `offset()` is a helper method of `nom::Offset` that can compare two slices and indicate
            // how far they are from each other. The parameter of `offset()` must be a subset of the
            // original slice
            b.data().offset(remaining)
        } else if let Ok((remaining,h)) = pcap::parse_pcap_header(b.data()) {
            stats.pcap_type = PcapType::Pcap;
            stats.link_type = Linktype(h.network);
            stats.major = h.version_major;
            stats.minor = h.version_minor;
            b.data().offset(remaining)
        } else {
            panic!("couldn't parse header");
        }
    };

    // println!("consumed {} bytes", length);
    b.consume(length);

    // we will count the number of tag and use that and return value for the generator
    let mut block_count = 1usize;
    let mut consumed = length;
    let mut last_incomplete_offset = 0;

    loop {
        // refill the buffer
        let sz = f.read(b.space()).expect("should write");
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

        match stats.pcap_type {
            PcapType::Unknown => panic!("unknown file type"),
            PcapType::Pcap => {
                loop {
                    let (length,_) = {
                        // read block
                        match pcap::parse_pcap_frame(b.data()) {
                            Ok((remaining,packet)) => {
                                block_count += 1;
                                // eprintln!("parse_block ok, count {}", block_count);
                                // println!("parsed packet: {:?}", packet);
                                stats.num_packets += 1;
                                stats.num_bytes += packet.header.caplen as u64;
                                (b.data().offset(remaining), packet)
                            },
                            // `Incomplete` means the nom parser does not have enough data to decide,
                            // so we wait for the next refill and then retry parsing
                            Err(nom::Err::Incomplete(n)) => {
                                // println!("not enough data, needs a refill: {:?}", n);

                                needed = Some(n);
                                break;
                            },

                            // stop on an error. Maybe something else than a panic would be nice
                            Err(nom::Err::Failure(e)) => {
                                panic!("parse failure: {:?}", e);
                            },

                            // stop on an error. Maybe something else than a panic would be nice
                            Err(nom::Err::Error(_e)) => {
                                // panic!("parse error: {:?}", e);
                                eprintln!("parse error");
                                println!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
                                panic!("parse error");
                            },
                        }
                    };

                    // println!("consuming {} of {} bytes", length, b.available_data());
                    b.consume(length);
                    consumed += length;
                }
            }
            PcapType::PcapNG => {
                loop {
                    let (length,_) = {
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
                                        stats.link_type = Linktype(ifdesc.linktype as i32);
                                    },
                                    Block::EnhancedPacket(ref p) => {
                                        stats.num_packets += 1;
                                        stats.num_bytes += p.caplen as u64;
                                    },
                                    _ => (),
                                }
                                (b.data().offset(remaining), block)
                            },
                            // `Incomplete` means the nom parser does not have enough data to decide,
                            // so we wait for the next refill and then retry parsing
                            Err(nom::Err::Incomplete(n)) => {
                                // println!("not enough data, needs a refill: {:?}", n);

                                needed = Some(n);
                                break;
                            },

                            // stop on an error. Maybe something else than a panic would be nice
                            Err(nom::Err::Failure(e)) => {
                                panic!("parse failure: {:?}", e);
                            },

                            // stop on an error. Maybe something else than a panic would be nice
                            Err(nom::Err::Error(_e)) => {
                                // panic!("parse error: {:?}", e);
                                eprintln!("parse error");
                                println!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
                                panic!("parse error");
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
                    panic!("requesting capacity {} over buffer_max_size {}", capacity, buffer_max_size);
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

    Ok(stats)
}

extern crate clap;
use clap::{Arg,App,crate_version};

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

extern crate pcap_parser;

// use pcap_parser::Capture;

// extern crate nom;
// use nom::HexDisplay;
// use nom::IResult;

extern crate pcap_tools;

use pcap_tools::common;

#[derive(Debug)]
struct Stats {
    num_packets: u32,
    num_bytes: u64,
}

fn main() {
    let mut stats = Stats{
        num_packets: 0,
        num_bytes: 0,
    };

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
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(file) => file,
    };

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(_) => (),
    };

    match common::try_parse_file(&buffer) {
        Ok(cap) => {
            let linktype = cap.get_datalink();
            if verbose {
                eprintln!("linktype: {:?}", linktype);
            }
            // See http://www.tcpdump.org/linktypes.html
            let get_data = match linktype {
                // pcap_parser::Linktype(0) => get_data_null,
                // pcap_parser::Linktype(1) => get_data_ethernet,
                // pcap_parser::Linktype(113) => get_data_linux_cooked,
                pcap_parser::Linktype(228) => common::get_data_raw,
                pcap_parser::Linktype(239) => pcap_parser::get_data_nflog,
                e @ _ => panic!("unsupported data link type {:?}", e),
            };
            let p = Path::new(&output_filename);
            let mut f = File::create(&p).unwrap();

            // Write header
            {
                let mut hdr = pcap_parser::PcapHeader::new();
                hdr.snaplen = cap.get_snaplen();
                hdr.network = 228; // DATALINK_RAWIPV4
                let s = hdr.to_string();
                stats.num_bytes += s.len() as u64;
                f.write(&s).unwrap();
            }

            // eprintln!("count: {}", cap.iter_packets().count());
            for packet in cap.iter_packets() {
                // debug!("packet: {:?}", packet);
                let data = get_data(&packet);
                // debug!("packet: {:?}", packet);
                // debug!("ts: {} {}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);

                let rec_hdr = pcap_parser::PacketHeader{
                    ts_sec: packet.header.ts_sec as u32,
                    ts_usec: packet.header.ts_usec as u32,
                    caplen: data.len() as u32, // packet.header.caplen,
                    len: data.len() as u32, // packet.header.len,
                };
                // debug!("rec_hdr: {:?}", rec_hdr);
                // debug!("data (len={}): {}", data.len(), data.to_hex(16));
                let s = rec_hdr.to_string();
                stats.num_bytes += s.len() as u64;
                f.write(&s).unwrap();
                f.write(&data).unwrap();

                stats.num_packets += 1;
                stats.num_bytes += data.len() as u64;
            }
        },
        Err(_)  => { panic!("File looks like neither pcap nor pcap-ng"); }
    }

    if verbose {
        eprintln!("Done.");
        eprintln!("stats: {:?}", stats);
    }
}

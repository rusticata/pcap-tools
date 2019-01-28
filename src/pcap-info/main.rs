extern crate clap;
use clap::{Arg,App};

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

extern crate pcap_parser;

use pcap_parser::*;

extern crate nom;
// use nom::HexDisplay;

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

    let matches = App::new("Pcap info tool")
        .version("0.1")
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
        .arg(Arg::with_name("OUTPUT")
             .help("Output file name")
             .required(true)
             .index(2))
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

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(_) => (),
    };

    // try pcap first
    match PcapCapture::from_file(&buffer) {
        Ok(capture) => {
            println!("Format: PCAP");
            println!("Linktype: {:?}", capture.get_datalink());
            println!("Snaplen: {}", capture.header.snaplen);
            println!("Version: {}.{}", capture.header.version_major, capture.header.version_minor);
            println!("{:?}", capture.header);
            for _packet in capture.iter_packets() {
                stats.num_packets += 1;
            }
        },
        _ => (),
    }

    // try pcapng
    // XXX do that only if pcap failed
    match parse_pcapng(&buffer) {
        Ok((rem, ref mut capture)) => {
            println!("Format: PCAPNG");
            println!("Num sections: {}", capture.sections.len());
            for (snum,section) in capture.sections.iter().enumerate() {
                println!("Section {}:", snum);
                for (inum,interface) in section.interfaces.iter().enumerate() {
                    println!("    Interface {}:", inum);
                    println!("        Linktype: {:?}", interface.header.linktype);
                    println!("        Snaplen: {}", interface.header.snaplen);
                    println!("        if_tsresol: {}", interface.if_tsresol);
                    println!("        if_tsoffset: {}", interface.if_tsoffset);
                    println!("        Num blocks: {}", interface.blocks.len());
                    println!("        Num packets: {}", interface.iter_packets().count());
                }
            //     println!("{:?}", section);
            }
            for _packet in capture.iter_packets() {
                // println!("packet: {:?}", packet);
                // println!("packet: caplen={} len={} ts={}.{}", packet.header.caplen, packet.header.len, packet.header.ts_sec, packet.header.ts_usec);
                stats.num_packets += 1;
            }
            // XXX checks
            // 0. sections must be non-empty, and all sections must have at least one interface
            for (snum,s) in capture.sections.iter().enumerate() {
                if s.interfaces.is_empty() {
                    println!("CRITICAL: empty section {}", snum);
                }
            }
            // 1. all interfaces in a section should have same linktype
            for (snum,s) in capture.sections.iter().enumerate() {
                let link0 = s.interfaces[0].header.linktype;
                let res = s.interfaces.iter().find(|x| x.header.linktype != link0);
                if let Some(interface) = res {
                    println!("CRITICAL: one interface has different linktype ({} vs {}) from first interface in section {}", interface.header.linktype, link0, snum);
                }
            }
            // 2. check for extra bytes
            if rem.len() > 0 {
                println!("Extra bytes after PCAPNG structure ({} bytes)", rem.len());
            }
            // XXX end of checks
        },
        _ => (),
    }

    // { // XXX
    //     match parse_section(&buffer) {
    //         IResult::Done(rem, section) => {
    //             println!("{:?}", section);
    //             if !rem.is_empty() {
    //                 println!(" !!! rem not empty, probably more sections to parse");
    //             }
    //             for interface in section.iter_interfaces() {
    //                 println!("interface , header={:?}", interface.header);
    //             }
    //             for packet in section.iter_packets() {
    //                 println!("packet: caplen={} len={} ts={}.{}", packet.header.caplen, packet.header.len, packet.header.ts_sec, packet.header.ts_usec);
    //                 //println!("packet: {:?}", packet);
    //             }
    //             let v = section.sorted_by_timestamp();
    //             assert_eq!(v.iter().count(), section.iter_packets().count());
    //         },
    //         e => println!("parse_section failed: {:?}", e),
    //     }
    // } // XXX

    if verbose {
        println!("Stats: {:?}", stats);
        println!("Done.");
    }
}

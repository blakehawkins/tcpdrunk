use std::collections::HashMap;
use std::io::{Result, Write};

use colored::*;
use nom::branch::alt;
use nom::bytes::streaming::{tag, take, take_while1};
use nom::combinator::map;
use nom::sequence::{pair, preceded, separated_pair};
use nom::IResult;
use oops::Oops;
use stdinix::stdinix;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
struct Opt {
    /// Either "hex" or "approximation".
    #[structopt(short = "r", long = "representation", default_value = "approximation")]
    repr: String,
}

#[derive(Debug, PartialEq)]
enum TcpdumpLine<'a> {
    Ip(&'a [u8], &'a [u8]),
    Tcp(HostPort<'a>, HostPort<'a>, &'a [u8]),
    Data(&'a [u8], &'a [u8]),
}

fn not_whitespace(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|byte: u8| !byte.is_ascii_whitespace())(input)
}

fn not_linebreak(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|byte: u8| byte != b'\n')(input)
}

fn not_colon(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|byte: u8| byte != b':')(input)
}

// 00:55:30.875722
fn parse_timestamp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    not_whitespace(input)
}

// (tos 0x0, ttl 63, id 60307, offset 0, flags [DF], proto TCP (6), length 117)
fn frame_info(input: &[u8]) -> IResult<&[u8], &[u8]> {
    not_linebreak(input)
}

fn parse_ip_line(input: &[u8]) -> IResult<&[u8], TcpdumpLine> {
    map(
        separated_pair(parse_timestamp, tag(" IP "), frame_info),
        |(a, b)| TcpdumpLine::Ip(a, b),
    )(input)
}

#[derive(Debug, PartialEq)]
struct HostPort<'a> {
    host: &'a [u8],
    port: &'a [u8],
}

fn parse_host_port(input: &[u8]) -> HostPort {
    let last_dot = input.iter().rposition(|v| v == &b'.').unwrap();
    HostPort {
        host: &input[0..last_dot],
        port: &input[last_dot + 1..]
    }
}

// "    192.168.0.10.8008"
fn tcp_source(input: &[u8]) -> IResult<&[u8], HostPort> {
    map(preceded(tag("    "), not_whitespace), parse_host_port)(input)
}

// " > 192.168.0.20.50314"
fn tcp_dest(input: &[u8]) -> IResult<&[u8], HostPort> {
    map(preceded(tag(" > "), not_colon), parse_host_port)(input)
}

// : Flags [.], cksum 0x0e2e (correct), seq 4278946470, ack 3104177948, win 508, options [nop,nop,TS val 3361824424...
fn tcp_info(input: &[u8]) -> IResult<&[u8], &[u8]> {
    not_linebreak(input)
}

fn parse_tcp_line(input: &[u8]) -> IResult<&[u8], TcpdumpLine> {
    map(pair(pair(tcp_source, tcp_dest), tcp_info), |((a, b), c)| {
        TcpdumpLine::Tcp(a, b, c)
    })(input)
}

// "        0x0000"
fn offset(input: &[u8]) -> IResult<&[u8], &[u8]> {
    not_colon(input)
}

// ":  4500 0233 b512 4000 4006 0244 c0a8 000a"
fn data(input: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag(":  "), take(39usize))(input)
}

// "  .OK..Transfer-En"
fn approximation(input: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag("  "), not_linebreak)(input)
}

// "        0x0000:  4500 0135 eb92 4000 3f06 cdc1 c0a8 0014  E..5..@.?......."
fn parse_data_line(input: &[u8]) -> IResult<&[u8], TcpdumpLine> {
    map(pair(pair(offset, data), approximation), |((_, b), c)| {
        TcpdumpLine::Data(b, c)
    })(input)
}

fn tcpdump_parser(input: &[u8]) -> IResult<&[u8], TcpdumpLine> {
    alt((parse_ip_line, parse_tcp_line, parse_data_line))(input)
}

fn colored_string<'a>(text: &'a [u8], map: &mut HashMap<String, ColoredString>) -> ColoredString {
    let len = map.len();
    let key = text
        .into_iter()
        .cloned()
        .map(char::from)
        .collect::<String>();
    map.entry(key.clone())
        .or_insert_with(|| {
            key.clone().color(match len % 6 {
                0 => Color::Red,
                1 => Color::Green,
                2 => Color::Yellow,
                3 => Color::Blue,
                4 => Color::Magenta,
                5 => Color::Cyan,
                _ => panic!("Impossible"),
            })
        })
        .to_owned()
}

fn write_repr(approximation: &String, hex: &String, config: &Opt) {
    match &config.repr[..] {
        "approximation" => println!("{}", approximation),
        "hex" => println!("{}", hex),
        _ => eprintln!("Data ignored"),
    }
}

fn write_out<'a, 'b>(
    hex: &'a mut String,
    approximation: &'a mut String,
    parsed: &'b TcpdumpLine,
    colors: &'a mut HashMap<String, ColoredString>,
    config: &Opt,
) -> () {
    match (hex.len(), parsed) {
        (_, TcpdumpLine::Data(hx, apprx)) => {
            hex.extend(vec![' '].into_iter());
            hex.extend(hx.into_iter().cloned().map(char::from));
            approximation.extend(apprx.into_iter().cloned().map(char::from));
        }
        (len, _) if len > 0 => {
            write_repr(approximation, hex, config);
            approximation.clear();
            hex.clear();

            write_out(hex, approximation, parsed, colors, config);
        }
        (_, TcpdumpLine::Tcp(source, dest, _)) => {
            println!(
                "\n{} -> {}",
                colored_string(source.host, colors),
                colored_string(dest.host, colors)
            );
        }
        _ => (),
    }
}

fn main() -> Result<()> {
    let options = Opt::from_args();
    let mut hex = String::new();
    let mut approximation = String::new();
    let mut colors = HashMap::new();
    stdinix(|line| {
        std::io::stdout().flush()?;
        let parsed = tcpdump_parser(line.as_bytes())
            .map_err(|e| eprintln!("{:?}", e))
            .oops("Failed to parse")?
            .1;

        write_out(&mut hex, &mut approximation, &parsed, &mut colors, &options);
        std::io::stdout().flush()?;

        Ok(())
    })?;

    if !hex.is_empty() {
        write_repr(&approximation, &hex, &options);
        std::io::stdout().flush()?;
    }

    Ok(())
}

mod test {
    use crate::*;

    #[test]
    fn test_timestamp() {
        assert_eq!(
            parse_timestamp("00:55:30.853902 IP".as_bytes()).unwrap().1,
            "00:55:30.853902".as_bytes()
        );
    }

    #[test]
    fn test_frame_info() {
        let parsed = frame_info(
            "(tos 0x0, ttl 63, id 60307, offset 0, flags [DF], proto TCP (6), length 117)
"
            .as_bytes(),
        );
        eprintln!("{:?}", parsed);
        assert_eq!(
            parsed.unwrap().1,
            "(tos 0x0, ttl 63, id 60307, offset 0, flags [DF], proto TCP (6), length 117)"
                .as_bytes()
        )
    }

    #[test]
    fn test_ip_line() {
        assert_eq!(
            parse_ip_line("00:55:30.853902 IP (tos 0x0, ttl 63, id 60304, offset 0, flags [DF], proto TCP (6), length 60)
".as_bytes()).unwrap().1,
            TcpdumpLine::Ip("00:55:30.853902".as_bytes(), "(tos 0x0, ttl 63, id 60304, offset 0, flags [DF], proto TCP (6), length 60)".as_bytes())
        );
    }
}

//! GDB remote protocol tests against a scripted in-memory debugserver.

use super::BoxStream;
use super::debugserver::*;
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};

/// Replays `input` as debugserver's bytes and records what the client wrote.
struct Scripted {
    input: Cursor<Vec<u8>>,
    output: Arc<Mutex<Vec<u8>>>,
}

impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for Scripted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn scripted(input: &[u8]) -> (Client, Arc<Mutex<Vec<u8>>>) {
    let output = Arc::new(Mutex::new(Vec::new()));
    let stream: BoxStream = Box::new(Scripted {
        input: Cursor::new(input.to_vec()),
        output: output.clone(),
    });
    (Client::new(stream), output)
}

fn written(output: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(output.lock().unwrap().clone()).unwrap()
}

fn reply(payload: &str) -> Vec<u8> {
    encode(payload)
}

#[test]
fn packets_are_framed_with_a_modulo_256_checksum() {
    assert_eq!(encode("OK"), b"$OK#9a");
    assert_eq!(checksum(&[0xff, 0x02]), 0x01);
    assert_eq!(hex(b"/a"), "2f61");
    assert_eq!(arguments_packet(&["/a", "-v"]), "A4,0,2f61,4,1,2d76");
    assert_eq!(unescape(b"a}\x03b}"), "a#b}");
    assert_eq!(command_name("QSetWorkingDir:2f"), "QSetWorkingDir");
    assert_eq!(command_name("A4,0,2f61"), "A");
    assert_eq!(command_name("D"), "D");
}

#[test]
fn errors_explain_debuggability_and_locked_devices() {
    let task = describe(
        "qLaunchSuccess",
        "/x",
        "Efailed to get the task for process 9",
    );
    assert!(task.contains("get-task-allow entitlement"), "{task}");
    assert!(task.contains("process 9"), "{task}");
    let locked = describe("A", "/x", "Elaunch failed: Locked");
    assert!(locked.contains("device is locked"), "{locked}");
    assert_eq!(
        describe("D", "/x", "E01"),
        "debugserver D failed for /x: E01"
    );
}

#[test]
fn sends_retransmit_after_a_nak() {
    let mut input = b"-+".to_vec();
    input.extend(reply("OK"));
    let (mut client, output) = scripted(&input);
    assert_eq!(client.request("D").unwrap(), "OK");
    assert_eq!(written(&output), "$D#44$D#44+");
}

#[test]
fn sends_give_up_after_repeated_naks() {
    let (mut client, _) = scripted(b"---");
    let error = client.send("qLaunchSuccess").unwrap_err();
    assert!(
        error.contains("rejected packet qLaunchSuccess 3 times"),
        "{error}"
    );
}

#[test]
fn corrupted_replies_are_nakked_and_retransmissions_accepted() {
    let mut input = b"+junk$OK#00$OK#zz".to_vec();
    input.extend(reply("E}\x03"));
    let (mut client, output) = scripted(&input);
    assert_eq!(client.request("D").unwrap(), "E#");
    assert_eq!(written(&output), "$D#44--+");

    let (mut client, _) = scripted(b"$a#00$a#00$a#00");
    assert!(client.receive().unwrap_err().contains("bad checksums"));
}

#[test]
fn dropped_connections_and_oversized_replies_fail() {
    let (mut client, _) = scripted(b"");
    let error = client.send("D").unwrap_err();
    assert!(error.contains("closed unexpectedly"), "{error}");
    let (mut client, _) = scripted(b"$OK");
    assert!(
        client
            .receive()
            .unwrap_err()
            .contains("closed unexpectedly")
    );

    let mut huge = b"$".to_vec();
    huge.resize((1 << 20) + 2, b'x');
    let (mut client, _) = scripted(&huge);
    assert!(client.receive().unwrap_err().contains("exceeds"));
}

#[test]
fn write_failures_are_reported() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("broken pipe"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(Broken.flush().is_ok());
    assert_eq!(Broken.read(&mut [0]).unwrap(), 0);
    let mut client = Client::new(Box::new(Broken));
    let error = client.send("D").unwrap_err();
    assert!(
        error.contains("sending to debugserver: broken pipe"),
        "{error}"
    );
}

const LAUNCH: Launch<'static> = Launch {
    executable: "/private/var/containers/Bundle/Application/X/T.app/T",
    working_dir: "/var/mobile",
    environment: &[],
};

fn packets(output: &str) -> Vec<String> {
    output
        .split('$')
        .skip(1)
        .map(|packet| {
            let (payload, sum) = packet.split_once('#').unwrap();
            assert_eq!(&sum[..2], format!("{:02x}", checksum(payload.as_bytes())));
            payload.to_string()
        })
        .collect()
}

#[test]
fn launch_switches_to_no_ack_mode_and_detaches() {
    let mut input = b"+".to_vec();
    for _ in 0..7 {
        input.extend(reply("OK"));
    }
    let (mut client, output) = scripted(&input);
    let environment = ["A=1".to_string()];
    let launch = Launch {
        environment: &environment,
        ..LAUNCH
    };
    client.launch(&launch).unwrap();
    let output = written(&output);
    assert!(output.starts_with("$QStartNoAckMode#b0+$"), "{output}");
    let executable = hex(LAUNCH.executable.as_bytes());
    assert_eq!(
        packets(&output),
        [
            "QStartNoAckMode".to_string(),
            "QSetMaxPacketSize:400".to_string(),
            format!("QSetWorkingDir:{}", hex(b"/var/mobile")),
            format!("QEnvironmentHexEncoded:{}", hex(b"A=1")),
            format!("A{},0,{executable}", executable.len()),
            "qLaunchSuccess".to_string(),
            "D".to_string(),
        ]
    );
}

#[test]
fn launch_keeps_acknowledging_when_no_ack_mode_is_unsupported() {
    let mut input = b"+".to_vec();
    input.extend(reply(""));
    for _ in 0..3 {
        input.extend(b"+");
        input.extend(reply("OK"));
    }
    input.extend(b"+");
    input.extend(reply("Efailed to get the task for process 42"));
    let (mut client, output) = scripted(&input);
    let error = client.launch(&LAUNCH).unwrap_err();
    assert!(error.contains("get-task-allow"), "{error}");
    assert!(error.contains(LAUNCH.executable), "{error}");
    let output = written(&output);
    assert_eq!(output.matches('+').count(), 5, "{output}");
    assert_eq!(packets(&output).last().unwrap(), "qLaunchSuccess");
}

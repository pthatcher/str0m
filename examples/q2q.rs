use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

pub fn main() {
    init_log();

    let (client1, signaling1) = Client::prepare(0).unwrap();
    let (client2, signaling2) = Client::prepare(0).unwrap();

    let mut client1 = client1.start(Role::Active, signaling2).unwrap();
    let mut client2 = client2.start(Role::Passive, signaling1).unwrap();

    let join2 = thread::spawn(move || client2.run().unwrap());
    client1.run().unwrap();
    join2.join().unwrap();
}

enum Role {
    Active,
    Passive,
}

#[derive(Debug)]
struct Signaling {
    ice_ufrag: String,
    ice_pwd: String,
    dtls_fingerprint: String,
    udp_address: SocketAddr,
}

struct ConnectionPrep {
    str0m_handle: str0m::Rtc,
    udp_socket: UdpSocket,
}

struct Client {
    str0m_handle: str0m::Rtc,
    udp_socket: UdpSocket,
}

impl Client {
    fn prepare(udp_port: u16) -> Result<(ConnectionPrep, Signaling), str0m::RtcError> {
        let (udp_socket, _local_udp_addr) = create_udp_socket_v4(udp_port)
            .ok_or_else(|| str0m::RtcError::Other("Failed to create UDP socket".to_string()))?;
        let local_udp_addr = udp_socket.local_addr()?;
        let (str0m_handle, local_signaling) = create_str0m_client(local_udp_addr)?;
        Ok((
            ConnectionPrep {
                str0m_handle,
                udp_socket,
            },
            local_signaling,
        ))
    }

    fn run(&mut self) -> Result<(), str0m::RtcError> {
        let mut incoming_packet_buffer = [0u8; 1500];
        run_str0m_poll_loop(
            &mut self.str0m_handle,
            &self.udp_socket,
            &mut incoming_packet_buffer,
        )
    }
}

impl ConnectionPrep {
    fn start(self, role: Role, remote_signaling: Signaling) -> Result<Client, str0m::RtcError> {
        let Self {
            mut str0m_handle,
            udp_socket,
        } = self;
        start_str0m_client(&mut str0m_handle, role, remote_signaling)?;
        Ok(Client {
            str0m_handle,
            udp_socket,
        })
    }
}

fn init_log() {
    use std::env;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "chat=info,str0m=info");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}

fn create_udp_socket_v4(udp_port: u16) -> Option<(UdpSocket, SocketAddr)> {
    let ips_v4 = local_v4_ips();
    let ip_v4 = ips_v4.into_iter().next()?;
    let udp_address: SocketAddr = (ip_v4, udp_port).into();
    let udp_socket = UdpSocket::bind(udp_address).ok()?;
    Some((udp_socket, udp_address))
}

fn local_v4_ips() -> Vec<IpAddr> {
    use systemstat::Platform;

    let mut ips = vec![];
    for network in systemstat::System::new()
        .networks()
        .unwrap_or_default()
        .values()
    {
        for addr in &network.addrs {
            if let systemstat::IpAddr::V4(ip) = addr.addr {
                if !ip.is_loopback() && !ip.is_link_local() && !ip.is_broadcast() {
                    ips.push(IpAddr::V4(ip))
                }
            }
        }
    }
    ips
}

fn create_str0m_client(
    local_udp_addr: SocketAddr,
) -> Result<(str0m::Rtc, Signaling), str0m::RtcError> {
    let str0m_config = str0m::RtcConfig::new();
    let local_ice_ufrag = str0m_config.local_ice_credentials().ufrag.clone();
    let local_ice_pwd = str0m_config.local_ice_credentials().pass.clone();
    let local_dtls_fingerprint = str0m_config.dtls_cert().fingerprint().to_string();

    let mut str0m_handle = str0m_config.build();
    str0m_handle.direct_api().set_ice_lite(false);
    str0m_handle.add_local_candidate(str0m::Candidate::host(local_udp_addr)?);
    let local_signaling = Signaling {
        ice_ufrag: local_ice_ufrag,
        ice_pwd: local_ice_pwd,
        dtls_fingerprint: local_dtls_fingerprint,
        udp_address: local_udp_addr,
    };
    Ok((str0m_handle, local_signaling))
}

const DATA_CHANNEL_ID: u16 = 1;

fn start_str0m_client(
    str0m_handle: &mut str0m::Rtc,
    role: Role,
    remote_signaling: Signaling,
) -> Result<(), str0m::RtcError> {
    let dtls_fingerprint = remote_signaling
        .dtls_fingerprint
        .parse()
        .map_err(|_| str0m::RtcError::Other("Invalid DTLS fingerprint".to_string()))?;
    str0m_handle
        .direct_api()
        .set_remote_ice_credentials(str0m::change::IceCreds {
            ufrag: remote_signaling.ice_ufrag,
            pass: remote_signaling.ice_pwd,
        });
    str0m_handle
        .direct_api()
        .set_remote_fingerprint(dtls_fingerprint);
    str0m_handle.add_remote_candidate(str0m::Candidate::host(remote_signaling.udp_address)?);
    let active = match role {
        Role::Active => true,
        Role::Passive => false,
    };
    str0m_handle
        .direct_api()
        .create_data_channel(str0m::channel::ChannelConfig {
            label: "".to_owned(),
            protocol: "".to_owned(),
            negotiated: Some(DATA_CHANNEL_ID),
            ordered: true,
            reliability: str0m::channel::Reliability::Reliable,
        });
    str0m_handle.direct_api().set_ice_controlling(active);
    str0m_handle.direct_api().start_dtls(active)?;
    str0m_handle.direct_api().start_sctp(active);
    Ok(())
}

fn run_str0m_poll_loop(
    str0m_handle: &mut str0m::Rtc,
    udp_socket: &UdpSocket,
    incoming_packet_buffer: &mut [u8],
) -> Result<(), str0m::RtcError> {
    loop {
        if !str0m_handle.is_alive() {
            println!("Stopping str0m run loop because !str0m_handle.is_alive()");
            return Ok(());
        }
        let deadline = poll_str0m_outputs(str0m_handle, udp_socket)?;
        let Some(deadline) = deadline else {
            println!("Stopping str0m run loop because str0m_handle has no deadline");
            return Ok(())
        };
        poll_str0m_input(str0m_handle, udp_socket, incoming_packet_buffer, deadline)?;
    }
}

// Ok(None) or Err(_) means the client has stopped.
// Ok(Some(deadline)) means the client should be polled again at the deadline.
fn poll_str0m_outputs(
    str0m_handle: &mut str0m::Rtc,
    udp_socket: &UdpSocket,
) -> Result<Option<Instant>, str0m::RtcError> {
    loop {
        if !str0m_handle.is_alive() {
            return Ok(None);
        }
        match str0m_handle.poll_output() {
            Ok(str0m_output) => {
                match str0m_output {
                    str0m::Output::Transmit(transmit) => {
                        udp_socket.send_to(&transmit.contents, transmit.destination)?;
                    }
                    // There's nothing more to poll from str0m, so proceed with reading from UDP socket with a timeout.
                    str0m::Output::Timeout(deadline) => {
                        return Ok(Some(deadline));
                    }
                    str0m::Output::Event(event) => {
                        match event {
                            str0m::Event::IceConnectionStateChange(ice_state) => {
                                if ice_state == str0m::IceConnectionState::Disconnected {
                                    // Ice disconnect could result in trying to establish a new connection,
                                    // but this impl just disconnects directly.
                                    str0m_handle.disconnect();
                                    return Ok(None);
                                }
                            }
                            str0m::Event::Connected => {
                                println!("ICE and DTLS Connected");
                            }
                            str0m::Event::ChannelOpen(goofy_channel_id, _label) => {
                                println!("SCTP data channel open: {goofy_channel_id:?}");
                            }
                            str0m::Event::ChannelData(str0m::channel::ChannelData {
                                id: goofy_channel_id,
                                binary: _binary,
                                data,
                            }) => {
                                println!(
                                    "Received data from SCTP data channel: {goofy_channel_id:?}, {:?}",
                                    data.len()
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(err) => {
                println!("Stopping because str0m handle_input failed: {err:?}");
                str0m_handle.disconnect();
                return Err(err);
            }
        };
    }
}

fn poll_str0m_input(
    str0m_handle: &mut str0m::Rtc,
    udp_socket: &UdpSocket,
    incoming_packet_buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), str0m::RtcError> {
    if let Some(str0m_input) =
        read_socket_as_str0m_input(udp_socket, incoming_packet_buffer, deadline)?
    {
        if str0m_handle.is_alive() {
            if let Err(err) = str0m_handle.handle_input(str0m_input) {
                println!("Stopping because str0m handle_input failed: {err:?}");
                str0m_handle.disconnect();
                return Err(err);
            }
        }
    } else {
        str0m_handle.handle_input(str0m::Input::Timeout(Instant::now()))?;
    }
    Ok(())
}

// Ok(Some(input)) means we got something.
// Ok(None) means we got nothing (timeout) or the packet was invalid, so we skip it.
// Err(_) means the socket is busted.
fn read_socket_as_str0m_input<'a>(
    udp_socket: &UdpSocket,
    incoming_packet_buffer: &'a mut [u8],
    deadline: Instant,
) -> Result<Option<str0m::Input<'a>>, str0m::RtcError> {
    let local_addr = udp_socket.local_addr()?;
    // The read timeout is not allowed to be 0. In case it is 0, we set 1 millisecond.
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1));
    udp_socket.set_read_timeout(Some(timeout))?;
    match udp_socket.recv_from(incoming_packet_buffer) {
        Ok((packet_len, remote_addr)) => {
            match str0m::net::DatagramRecv::try_from(&incoming_packet_buffer[..packet_len]) {
                Ok(incoming_packet) => Ok(Some(str0m::Input::Receive(
                    Instant::now(),
                    str0m::net::Receive {
                        source: remote_addr,
                        destination: local_addr,
                        contents: incoming_packet,
                    },
                ))),
                Err(err) => {
                    println!("Failed to parse incoming packet: {err:?}");
                    Ok(None)
                }
            }
        }
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => Ok(None),
            _ => Err(err.into()),
        },
    }
}

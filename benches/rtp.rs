use std::{net::{Ipv4Addr, SocketAddr}, time::{Duration, Instant}};

use str0m::{self, rtp::VideoOrientation};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// TODO: Depend on tests::common::TestRtc?
pub struct Endpoint {
    pub rtc: str0m::Rtc,
    pub deadline: Instant,
    pub outputs: Vec<(Instant, str0m::Event)>,
}

impl Endpoint {
    // TODO: Depend on tests::common::connect_l_r()?
    fn connect_client_and_server(now: Instant) -> (Endpoint, Endpoint) {
        let client_rtc = str0m::Rtc::builder()
            .set_rtp_mode(true)
            .enable_raw_packets(true)
            .build();
        let server_rtc = str0m::Rtc::builder()
            .set_rtp_mode(true)
            .enable_raw_packets(true)
            // release packet straight away
            .set_reordering_size_audio(0)
            .build();

        let mut client = Self::new(client_rtc, now);
        let mut server = Self::new(server_rtc, now);

        let client_candidate = str0m::Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
        let server_candidate = str0m::Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
        client.rtc.add_local_candidate(client_candidate.clone());
        client.rtc.add_remote_candidate(server_candidate.clone());
        server.rtc.add_local_candidate(server_candidate);
        server.rtc.add_remote_candidate(client_candidate);

        let client_fingerprint = client.rtc.direct_api().local_dtls_fingerprint();
        let server_fingerprint = server.rtc.direct_api().local_dtls_fingerprint();

        client.rtc.direct_api().set_remote_fingerprint(server_fingerprint);
        server.rtc.direct_api().set_remote_fingerprint(client_fingerprint);

        let client_ice_creds = client.rtc.direct_api().local_ice_credentials();
        let server_ice_creds = server.rtc.direct_api().local_ice_credentials();

        client.rtc.direct_api().set_remote_ice_credentials(server_ice_creds);
        server.rtc.direct_api().set_remote_ice_credentials(client_ice_creds);

        client.rtc.direct_api().set_ice_controlling(true);
        server.rtc.direct_api().set_ice_controlling(false);

        client.rtc.direct_api().start_dtls(true).unwrap();
        server.rtc.direct_api().start_dtls(false).unwrap();

        client.rtc.direct_api().start_sctp(true);
        server.rtc.direct_api().start_sctp(false);
 
        // %%%
        while !client.rtc.is_connected() || !server.rtc.is_connected() {
            let (first, second) = if client.deadline < server.deadline {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
    
            let now = first.deadline;
            first.rtc.handle_input(str0m::Input::Timeout(now)).expect("Valid handling of timeout");
            match first.rtc.poll_output().expect("Valid output") {
                str0m::Output::Timeout(deadline) => {
                    first.deadline = deadline;
                }
                str0m::Output::Transmit(sent) => {
                    second.rtc.handle_input(str0m::Input::Receive(
                        now,
                        str0m::net::Receive {
                            proto: sent.proto,
                            source: sent.source,
                            destination: sent.destination,
                            contents: (&*sent.contents).try_into().expect("Valid contents"),
                        },
                    ));
                }
                str0m::Output::Event(event) => {
                    first.outputs.push((now, event));
                }
            }
        }

        (client, server)
    }

    fn new(rtc: str0m::Rtc, now: Instant) -> Self {
        Self {
            rtc,
            deadline: now,
            outputs: vec![],
        }
    }
}

// struct Endpoint {
//     is_server: bool,
//     ice_creds: str0m::IceCreds,
//     dtls_cert: str0m::change::DtlsCert,
//     rtc: str0m::Rtc,
// }

// impl Endpoint {
//     fn client(client_udp_addr: SocketAddr) -> Self {
//         Self::new(client_udp_addr, false)
//     }

//     fn server(server_udp_addr: SocketAddr) -> Self {
//         Self::new(server_udp_addr, true)
//     }

//     fn new(local_udp_addr: SocketAddr, is_server: bool) -> Self {
//         let is_client = !is_server;
//         let local_ice_creds = str0m::IceCreds::new();
//         let local_dtls_cert = str0m::change::DtlsCert::new_openssl();
//         let config = str0m::RtcConfig::new()
//             .set_dtls_cert(local_dtls_cert.clone())
//             .set_local_ice_credentials(local_ice_creds.clone())
//             .set_rtp_mode(true)
//             .clear_extension_map()
//             .enable_bwe(Some(str0m::bwe::Bitrate::kbps(500)))
//             .set_stats_interval(Some(Duration::from_secs(10)));
//         config.set_extension(1, str0m::rtp::Extension::RtpMid);
//         config.set_extension(3, str0m::rtp::Extension::TransportSequenceNumber);
//         config.set_extension(4, str0m::rtp::Extension::AudioLevel);
//         config.set_extension(5, str0m::rtp::Extension::RtpStreamId);
//         config.set_extension(6, str0m::rtp::Extension::RepairedRtpStreamId);
//         config.set_extension(8, str0m::rtp::Extension::VideoOrientation);
    
//         let mut rtc = config.build();
//         rtc.direct_api().set_ice_lite(is_server);
//         rtc.direct_api().set_ice_controlling(is_client);
//         rtc.add_local_candidate(str0m::Candidate::host(
//             local_udp_addr,
//             str0m::net::Protocol::Udp,
//         ).expect("Valid server UDP address"));
//         let mut negotiated_data_channel_id = 1;
//         if is_server {
//             negotiated_data_channel_id += 1;
//         }
//         let control_channel_id =
//         rtc
//             .direct_api()
//             .create_data_channel(str0m::channel::ChannelConfig {
//                 label: "control".to_string(),
//                 negotiated: Some(negotiated_data_channel_id),
//                 ordered: true,
//                 reliability: str0m::channel::Reliability::Reliable,
//                 ..Default::default()
//             });
//         rtc.direct_api().enable_twcc_feedback();

//         let mut audio_send_mid = *b"1               ";
//         if is_server {
//             audio_send_mid[0] += 1;
//         }
//         let audio_send_mid = str0m::media::Mid::from_array(audio_send_mid);
//         let audio_send_ssrc = rtc.direct_api().new_ssrc();
//         rtc.direct_api().declare_media(audio_send_mid, str0m::media::MediaKind::Audio);
//         rtc.direct_api().declare_stream_tx(audio_send_ssrc, None, audio_send_mid, None);

//         let mut video_send_mid = *b"3               ";
//         if is_server {
//             video_send_mid[0] += 1;
//         }
//         let video_send_mid = str0m::media::Mid::from_array(video_send_mid);
//         let video_send_ssrc = rtc.direct_api().new_ssrc();
//         let video_send_rtx_ssrc = rtc.direct_api().new_ssrc();
//         rtc.direct_api().declare_media(video_send_mid, str0m::media::MediaKind::Video);
//         rtc.direct_api().declare_stream_tx(video_send_ssrc, Some(video_send_rtx_ssrc), video_send_mid, None);

//         let mut audio_recv_mid = *b"1               ";
//         if is_client {
//             audio_recv_mid[0] += 1;
//         }
//         let audio_recv_mid = str0m::media::Mid::from_array(audio_recv_mid);
//         rtc.direct_api().declare_media(, str0m::media::MediaKind::Audio);

//         let mut video_recv_mid = *b"3               ";
//         if is_client {
//             video_recv_mid[0] += 1;
//         }
//         let video_recv_mid = str0m::media::Mid::from_array(video_recv_mid);
//         rtc.direct_api().declare_media(video_recv_mid, str0m::media::MediaKind::Video);


//         Self {
//             is_server,
//             ice_creds: local_ice_creds,
//             dtls_cert: local_dtls_cert,
//             rtc,
//         }
//     }

//     fn start(&mut self, remote: &Endpoint) {
//         let is_client = !self.is_server;

//         self.rtc.direct_api().set_remote_ice_credentials(remote.ice_creds.clone());
//         self.rtc.direct_api().set_remote_fingerprint(remote.dtls_cert.fingerprint());
//         self.rtc.direct_api().start_sctp(is_client);
//         // %%%%% set_remote_ice_credentials
//         self.rtc.direct_api().start_dtls(is_client).expect("Can start server DTLS");
//     }

//     fn foo()

// }

                // %%%% need this 
        // rtc.handle_input(str0m::Input::Timeout(now));
        // %%%% need this
        // self.str0m_handle.handle_input(Input::Receive(
        //     context.translate_kernel_network_time(kernel_network_time, now),
        //     Receive {
        //         proto: network_route.protocol.into(),
        //         source: network_route.remote_addr,
        //         destination: network_route.local_addr,
        //         contents,
        //     },
        // }
        // %%%% need this to send audio
        // let audio_stream_tx = rtc.direct_api().stream_tx(&audio_ssrc).expect("A audio stream TX");
        // audio_stream_tx.write_rtp(
        //     str0m::media::Pt::from(audio_pt),
        //     str0m::rtp::SeqNo::from(audio_seqnum),
        //     audio_timestamp as u32,
        //     now,
        //     false,
        //     str0m::rtp::ExtensionValues {
        //         audio_level: Some(audio_level),
        //         true,
        //         ..Default::default()
        //     },
        //     false,
        //     vec![0u8; 125],  // About 50kbps when sent every 20ms
        // ).expect("write_rtp succeeds");

        // %%%% need this to send video
//         let video_stream_tx = rtc.direct_api().stream_tx(&video_ssrc).expect("A video stream TX");
//         video_stream_tx.write_rtp(
//             str0m::media::Pt::from(video_pt),
//             str0m::rtp::SeqNo::from(video_seqnum),
//             video_timestamp as u32,
//             now,
//             false,
//             str0m::rtp::ExtensionValues {
//                 video_orientation: Some(str0m::rtp::VideoOrientation::Deg0)
//                 ..Default::default()
//             },
// true,
//             vec![0u8; 1250],  // About 1mbps when sent every 10ms
//         ).expect("write_rtp succeeds");

// // %%%% needs this to drive
//         match rtc.poll_output() {
//             Ok(Output::Timeout(deadline)) => {  
//                 if let Some(new_deadline) = self.str0m_deadlines.set_if_earlier(
//                     str0m_deadline,
//                     self.str0m_handle.last_timeout_reason(),
//                     now,
//                 ) {
//                     context.schedule_endpoint_connection_task_at(
//                         new_deadline,
//                         self.connection_index,
//                         EndpointConnectionTask::Wake,
//                     );
//                 }
//                 return;
//             }

//     fn client(client_udp_addr: SocketAddr, server_ice_creds: str0m::IceCreds) -> Self {
//         // %%% dedup
//         let ice_creds = str0m::IceCreds::new();
//         let dtls_cert = str0m::change::DtlsCert::new_openssl();
//         let config = str0m::RtcConfig::new()
//             .set_dtls_cert(dtls_cert)
//             .set_local_ice_credentials(ice_creds)
//             .set_rtp_mode(true)
//             .clear_extension_map()
//             .enable_bwe(Some(str0m::bwe::Bitrate::kbps(500)))
//             .set_stats_interval(Some(Duration::from_secs(10)));
//         config.set_extension(1, str0m::rtp::Extension::RtpMid);
//         config.set_extension(3, str0m::rtp::Extension::TransportSequenceNumber);
//         config.set_extension(4, str0m::rtp::Extension::AudioLevel);
//         config.set_extension(5, str0m::rtp::Extension::RtpStreamId);
//         config.set_extension(6, str0m::rtp::Extension::RepairedRtpStreamId);
//         config.set_extension(8, str0m::rtp::Extension::VideoOrientation);
    
//         let mut rtc = config.build();
//         rtc.direct_api().set_ice_lite(false);
//         rtc.direct_api().set_ice_controlling(true);
//         rtc.add_local_candidate(str0m::Candidate::host(
//             client_udp_addr,
//             str0m::net::Protocol::Udp,
//         ).expect("Valid client UDP address"));
//         rtc.direct_api().set_remote_ice_credentials(server_ice_creds);
//         rtc.direct_api().start_dtls(false).expect("Can start client DTLS");
//         rtc
//             .direct_api()
//             .create_data_channel(str0m::channel::ChannelConfig {
//                 label: "control".to_string(),
//                 // %%%% should this be 1 or 3?
//                 negotiated: Some(2),
//                 ordered: true,
//                 reliability: str0m::channel::Reliability::Reliable,
//                 ..Default::default()
//             });
//         rtc.direct_api().start_sctp(true);
//         rtc.direct_api().enable_twcc_feedback();
//         // %%%% need this 
//         rtc.handle_input(str0m::Input::Timeout(now));


//         Self {
//             rtc,
//         }
//     }

pub fn bench(c: &mut Criterion) {
    let now = Instant::now();
    let (client, server) = Endpoint::connect_client_and_server(now);
    assert!(client.rtc.is_connected(), "client not connected");
    assert!(server.rtc.is_connected(), "server not connected");

    // let client_address = "127.0.0.1:5001".parse().expect("A valid client address");
    // let mut client = Endpoint::client(client_address);

    // let server_address = "127.0.0.1:5002".parse().expect("A valid server address");
    // let mut server = Endpoint::server(server_address);

    // client.start(&server);
    // server.start(&client);

    // c.bench_function("send RTP", |b| b.iter(|| send_rtp()));
}

criterion_group!(benches, bench);
criterion_main!(benches);
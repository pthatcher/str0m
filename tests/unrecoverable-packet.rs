mod common;

use std::time::Instant;

use common::{connect_l_r, connect_l_r_with_rtc, init_crypto_default, init_log, progress};
use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::media::Pt;
use str0m::rtp::{ExtensionValues, RtpWrite, SeqNo, Ssrc};
use str0m::{Event, Rtc, RtcError};

fn write_packet(l: &mut common::TestRtc, ssrc: Ssrc, pt: Pt, seq_no: SeqNo, time: u32) {
    let wallclock = l.start + l.duration();
    let mut direct = l.direct_api();
    let stream = direct.stream_tx(&ssrc).expect("stream tx");

    stream.write_rtp(
        RtpWrite::new(pt, seq_no, time, wallclock, vec![0x11, 0x22, 0x33, 0x44])
            .ext_vals(ExtensionValues::default())
            .nackable(true),
    );
}

#[test]
fn emits_unrecoverable_event_in_rtp_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "vid".into();
    let ssrc_tx: Ssrc = 42.into();
    let ssrc_rtx: Ssrc = 44.into();

    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api()
        .declare_stream_tx(ssrc_tx, Some(ssrc_rtx), mid, None);

    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api()
        .expect_stream_rx(ssrc_tx, Some(ssrc_rtx), mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    // Create a sequence gap where packet 11 is missing and later slides out of the
    // NACK window when packet 112 is received.
    write_packet(&mut l, ssrc_tx, pt, 10.into(), 47_000_000);
    progress(&mut l, &mut r)?;

    write_packet(&mut l, ssrc_tx, pt, 112.into(), 47_102_000);
    progress(&mut l, &mut r)?;

    let got = r.events.iter().find_map(|(_, e)| match e {
        Event::RtpPacketUnrecoverable(v) => Some((v.ssrc, v.seq_no)),
        _ => None,
    });

    assert_eq!(got, Some((ssrc_tx, 11.into())));

    Ok(())
}

#[test]
fn does_not_emit_unrecoverable_event_outside_rtp_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let (mut l, mut r) = connect_l_r_with_rtc(Rtc::new(now), Rtc::new(now));

    let mid = "vid".into();
    let ssrc_tx: Ssrc = 42.into();
    let ssrc_rtx: Ssrc = 44.into();

    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api()
        .declare_stream_tx(ssrc_tx, Some(ssrc_rtx), mid, None);

    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api()
        .expect_stream_rx(ssrc_tx, Some(ssrc_rtx), mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    write_packet(&mut l, ssrc_tx, pt, 10.into(), 47_000_000);
    progress(&mut l, &mut r)?;

    write_packet(&mut l, ssrc_tx, pt, 112.into(), 47_102_000);
    progress(&mut l, &mut r)?;

    let has_unrecoverable = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::RtpPacketUnrecoverable(_)));

    assert!(
        !has_unrecoverable,
        "RtpPacketUnrecoverable event should only be emitted in RTP mode"
    );

    Ok(())
}

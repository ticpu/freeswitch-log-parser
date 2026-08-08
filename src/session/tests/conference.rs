//! Conference instance identity and negotiated media.

use super::*;

#[test]
fn conference_execute_shares_one_instance() {
    let tracker = track(vec![
        format!("{UUID1} EXECUTE [depth=0] loopback/tty-a conference(835)"),
        format!("{UUID2} EXECUTE [depth=0] sofia/internal/1000 conference(835)"),
        format!("{UUID3} EXECUTE [depth=0] sofia/internal/1001 conference(844)"),
    ]);

    let first = tracker.sessions()[UUID1].conference.clone().unwrap();
    let second = tracker.sessions()[UUID2].conference.clone().unwrap();
    let other = tracker.sessions()[UUID3].conference.clone().unwrap();

    assert_eq!(first.name, "835");
    assert_eq!(first.instance, UUID1, "first joiner names the instance");
    assert_eq!(second.instance, UUID1);
    assert_eq!(other.name, "844");
    assert_ne!(other.instance, first.instance);

    let mut members: Vec<&str> = tracker.conference_members(&first.instance).collect();
    members.sort_unstable();
    assert_eq!(members, [UUID1, UUID2]);
}

#[test]
fn conference_transfer_line_joins() {
    let tracker = track(vec![full_line(
        UUID1,
        TS1,
        "Transfer loopback/tty-a to inline[conference:835@default]",
    )]);
    let membership = tracker.sessions()[UUID1].conference.clone().unwrap();
    assert_eq!(membership.name, "835");
    assert_eq!(
        membership.profile, None,
        "the transfer context is not a conference profile"
    );
}

#[test]
fn conference_variables_fill_member_id() {
    let tracker = track(vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} variable_conference_name: [835]"),
        format!("{UUID1} variable_conference_member_id: [3]"),
        format!("{UUID1} variable_conference_uuid: [{UUID2}]"),
        full_line(UUID1, TS2, "later"),
    ]);
    let membership = tracker.sessions()[UUID1].conference.clone().unwrap();
    assert_eq!(membership.name, "835");
    assert_eq!(membership.member_id, Some(3));
    assert_eq!(membership.conference_uuid.as_deref(), Some(UUID2));
}

#[test]
fn reused_name_after_the_last_leave_is_a_new_instance() {
    let tracker = track(vec![
        format!("{UUID1} EXECUTE [depth=0] loopback/tty-a conference(835)"),
        full_line(
            UUID1,
            TS1,
            "Channel leaving conference, cause: NORMAL_CLEARING",
        ),
        format!("{UUID2} EXECUTE [depth=0] sofia/internal/1000 conference(835)"),
    ]);

    assert!(
        tracker.sessions()[UUID1].conference.is_none(),
        "leaving clears the membership"
    );
    let rejoined = tracker.sessions()[UUID2].conference.clone().unwrap();
    assert_eq!(rejoined.instance, UUID2);
}

#[test]
fn media_keeps_the_outcome_and_the_deduped_offer_set() {
    let tracker = track(vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [opus:102:16000:20:0:1]/[G722:9:16000:20:64000:1]",
        ),
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [opus:102:16000:20:0:1]/[opus:116:16000:20:0:1]",
        ),
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [opus:116:16000:20:0:1] ++++ is saved as a match",
        ),
        full_line(UUID1, TS2, "Video Codec Compare [H264:109]/[H263:34]"),
        full_line(
            UUID1,
            TS2,
            "Video Codec Compare [H264:109] +++ is saved as a match",
        ),
        full_line(
            UUID1,
            TS2,
            "Set Codec sofia/internal/1000 opus/16000 20 ms 320 samples 0 bits 1 channels",
        ),
        full_line(
            UUID1,
            TS2,
            "sofia/internal/1000 Original read codec set to opus:116",
        ),
    ]);
    let media = &tracker.sessions()[UUID1].media;

    assert_eq!(
        media.audio.offered.len(),
        1,
        "the same remote offer compared twice is one entry: {:?}",
        media.audio.offered
    );
    assert_eq!(media.audio.negotiated.as_ref().unwrap().name, "opus");
    assert_eq!(media.audio.negotiated.as_ref().unwrap().payload_type, 116);

    assert_eq!(media.video.negotiated.as_ref().unwrap().name, "H264");
    assert!(
        media.audio.negotiated != media.video.negotiated,
        "audio and video outcomes are tracked apart"
    );

    assert_eq!(media.read_codec.as_ref().unwrap().payload_type, 116);
    assert_eq!(media.active_audio.as_ref().unwrap().clock_rate, Some(16000));
}

#[test]
fn a_member_still_present_holds_the_instance_open() {
    let tracker = track(vec![
        format!("{UUID1} EXECUTE [depth=0] loopback/tty-a conference(835)"),
        format!("{UUID2} EXECUTE [depth=0] sofia/internal/1000 conference(835)"),
        full_line(
            UUID1,
            TS1,
            "Channel leaving conference, cause: NORMAL_CLEARING",
        ),
        format!("{UUID3} EXECUTE [depth=0] sofia/internal/1001 conference(835)"),
    ]);
    assert_eq!(
        tracker.sessions()[UUID3]
            .conference
            .as_ref()
            .unwrap()
            .instance,
        UUID1
    );
}

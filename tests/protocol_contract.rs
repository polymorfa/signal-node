use prost::Message;
use signal_node::proto::{self, frame::Body, service_request::Op};

#[test]
fn connection_lease_names_preserve_version_one_wire_tags() {
    assert_eq!(proto::PROTOCOL_VERSION, 1);
    assert_eq!(proto::SUBPROTOCOL, "polymorfa.signal.v1");
    assert_eq!(proto::Code::ConnectionUnavailable as i32, 8);
    let request = proto::ServiceRequest {
        connection_id: "stable".into(),
        lease_generation: 9,
        op: Some(Op::ClaimConnection(proto::ClaimConnection {
            generation: 7,
        })),
    };
    // Root selector tag1, generation tag2 and claim tag10 are unchanged.
    let wire = b"\x0a\x06stable\x10\x09\x52\x02\x08\x07";
    assert_eq!(request.encode_to_vec(), wire);
    assert_eq!(
        proto::ServiceRequest::decode(wire.as_slice()).unwrap(),
        request
    );

    let event = proto::Frame::with(
        0,
        Body::ConnectionEvent(proto::ConnectionEvent {
            connection_id: "stable".into(),
            state: proto::connection_event::State::Connected as i32,
            ..Default::default()
        }),
    );
    // The unsolicited account event retains frame tag9 and state value2.
    let wire = b"\x4a\x0a\x0a\x06stable\x10\x02";
    assert_eq!(event.encode_to_vec(), wire);
    assert_eq!(proto::Frame::decode(wire.as_slice()).unwrap(), event);
}

#[test]
fn companion_identity_fields_preserve_additive_tags_and_opaque_bytes() {
    let receive = proto::Receive {
        device_identity: vec![1, 2, 3],
        ..Default::default()
    };
    let bundle = proto::Bundle {
        device_identity: vec![1, 2, 3],
        ..Default::default()
    };
    assert_eq!(receive.encode_to_vec(), [0x52, 3, 1, 2, 3]);
    assert_eq!(bundle.encode_to_vec(), [0x42, 3, 1, 2, 3]);
    assert_eq!(
        proto::Receive::decode(&[0x52, 3, 1, 2, 3][..]).unwrap(),
        receive
    );
    assert_eq!(
        proto::Bundle::decode(&[0x42, 3, 1, 2, 3][..]).unwrap(),
        bundle
    );
    assert!(
        proto::Receive::decode(&[][..])
            .unwrap()
            .device_identity
            .is_empty()
    );
    assert!(
        proto::Bundle::decode(&[][..])
            .unwrap()
            .device_identity
            .is_empty()
    );
}

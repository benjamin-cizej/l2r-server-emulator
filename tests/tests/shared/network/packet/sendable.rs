use shared::network::packet::sendable::SendablePacket;

#[test]
fn it_auth_encrypts() {
    let mut packet = SendablePacket::new();
    packet.write_bytes(vec![
        0, 118, 138, 89, 5, 33, 198, 0, 0, 100, 155, 116, 166, 105, 129, 172, 252, 236, 37, 198,
        64, 57, 20, 44, 7, 106, 197, 192, 83, 168, 184, 167, 27, 165, 253, 109, 99, 188, 94, 228,
        64, 68, 219, 92, 46, 167, 219, 178, 53, 105, 169, 199, 200, 12, 114, 229, 163, 200, 196,
        177, 200, 188, 217, 252, 37, 83, 207, 89, 34, 10, 221, 182, 69, 187, 22, 68, 200, 211, 127,
        37, 221, 39, 42, 31, 138, 214, 229, 24, 67, 52, 28, 198, 192, 50, 67, 180, 207, 124, 177,
        15, 215, 158, 88, 175, 149, 156, 131, 15, 137, 39, 174, 218, 162, 44, 62, 196, 232, 186,
        184, 87, 53, 125, 235, 203, 96, 65, 251, 53, 186, 228, 1, 167, 151, 216, 221, 222, 14, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 228, 7, 68, 16, 71, 250, 226, 54, 124, 180,
        162, 52, 59, 59, 166, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    packet.auth_encypher(-1866898459);
    let bytes = packet.to_bytes();
    let (_, result) = bytes.split_at(2);

    let expected: Vec<u8> = vec![
        0, 118, 138, 89, 239, 165, 185, 145, 234, 140, 129, 114, 54, 59, 29, 30, 112, 211, 231,
        190, 140, 65, 194, 136, 212, 136, 94, 165, 117, 35, 236, 170, 90, 149, 175, 22, 199, 80,
        238, 187, 164, 116, 87, 224, 60, 127, 188, 221, 114, 40, 184, 240, 199, 66, 241, 249, 17,
        222, 140, 127, 178, 111, 248, 55, 186, 117, 62, 125, 227, 58, 19, 109, 67, 87, 242, 91, 6,
        108, 27, 96, 118, 192, 164, 123, 191, 104, 145, 101, 59, 198, 140, 133, 248, 23, 151, 67,
        200, 222, 52, 8, 9, 222, 134, 25, 230, 65, 226, 201, 117, 35, 190, 123, 60, 29, 112, 161,
        110, 86, 190, 234, 142, 20, 25, 67, 123, 234, 22, 139, 111, 107, 238, 194, 251, 176, 16,
        154, 116, 104, 205, 68, 122, 104, 205, 68, 122, 104, 205, 68, 122, 104, 205, 68, 122, 168,
        210, 204, 154, 212, 53, 137, 246, 115, 48, 172, 192, 113, 132, 18, 52, 75, 191, 180, 85,
        75, 191, 180, 85, 75, 191, 180, 0, 0, 0, 0,
    ];

    assert_eq!(expected, result.to_vec());
}

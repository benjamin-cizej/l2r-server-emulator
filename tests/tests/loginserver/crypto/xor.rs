use loginserver::crypto::xor::{xor_decypher_packet, xor_encypher_packet};

#[test]
fn it_decyphers_auth() {
    let mut bytes = vec![
        0, 0, 0, 0, 0, 107, 145, 2, 4, 186, 95, 2, 4, 78, 228, 47, 6, 156, 76, 238, 127, 142, 2,
        138, 205, 214, 230, 160, 93, 86, 254, 44, 118, 176, 75, 6, 4, 136, 239, 171, 91, 136, 49,
        242, 181, 10, 184, 179, 251, 152, 69, 32, 110, 25, 189, 159, 5, 2, 207, 232, 87, 1, 64, 4,
        190, 60, 17, 137, 96, 99, 115, 238, 164, 163, 152, 92, 140, 218, 181, 31, 169, 184, 160,
        20, 182, 93, 88, 222, 170, 164, 141, 231, 94, 54, 164, 227, 200, 94, 152, 154, 100, 96,
        136, 4, 229, 215, 125, 121, 74, 41, 18, 9, 10, 201, 15, 90, 39, 227, 232, 206, 134, 96,
        216, 82, 189, 47, 136, 35, 242, 102, 252, 212, 224, 182, 144, 162, 142, 170, 151, 211, 235,
        170, 151, 211, 235, 170, 151, 211, 235, 170, 151, 211, 235, 234, 233, 221, 21, 36, 105,
        169, 216, 234, 228, 3, 196, 229, 147, 236, 230, 204, 84, 82, 187, 204, 84, 82, 187, 204,
        84, 82, 187, 204, 84, 82,
    ];
    let expected = vec![
        0, 0, 0, 0, 4, 33, 198, 0, 0, 124, 4, 233, 250, 197, 87, 242, 237, 233, 77, 152, 202, 220,
        24, 234, 14, 99, 111, 124, 207, 249, 58, 41, 114, 200, 231, 97, 179, 255, 33, 166, 246,
        141, 121, 126, 140, 98, 251, 147, 97, 126, 25, 78, 107, 27, 242, 120, 168, 252, 240, 20,
        213, 253, 174, 124, 94, 224, 157, 28, 196, 195, 251, 189, 216, 9, 236, 165, 43, 189, 42,
        19, 199, 237, 24, 197, 44, 6, 210, 7, 152, 174, 17, 7, 22, 23, 204, 137, 212, 190, 31, 153,
        63, 86, 210, 131, 223, 240, 147, 127, 188, 17, 18, 51, 47, 234, 151, 144, 89, 124, 63, 3,
        221, 122, 160, 78, 243, 138, 171, 143, 210, 232, 108, 182, 102, 28, 7, 113, 101, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 49, 63, 133, 189, 126, 77, 170, 28, 72, 105, 144,
        154, 41, 199, 190, 93, 0, 0, 0, 0, 0, 0, 0, 187, 204, 84, 82, 187, 204, 84, 82,
    ];

    xor_decypher_packet(&mut bytes).unwrap();
    assert_eq!(bytes, expected);
}

#[test]
fn it_returns_err_on_decypher_auth_with_size_less_than_12() {
    let mut bytes = vec![0; 5];
    xor_decypher_packet(&mut bytes).unwrap_err();
}

#[test]
fn it_auth_encrypts() {
    let mut bytes = vec![
        0, 118, 138, 89, 5, 33, 198, 0, 0, 100, 155, 116, 166, 105, 129, 172, 252, 236, 37, 198,
        64, 57, 20, 44, 7, 106, 197, 192, 83, 168, 184, 167, 27, 165, 253, 109, 99, 188, 94, 228,
        64, 68, 219, 92, 46, 167, 219, 178, 53, 105, 169, 199, 200, 12, 114, 229, 163, 200, 196,
        177, 200, 188, 217, 252, 37, 83, 207, 89, 34, 10, 221, 182, 69, 187, 22, 68, 200, 211, 127,
        37, 221, 39, 42, 31, 138, 214, 229, 24, 67, 52, 28, 198, 192, 50, 67, 180, 207, 124, 177,
        15, 215, 158, 88, 175, 149, 156, 131, 15, 137, 39, 174, 218, 162, 44, 62, 196, 232, 186,
        184, 87, 53, 125, 235, 203, 96, 65, 251, 53, 186, 228, 1, 167, 151, 216, 221, 222, 14, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 228, 7, 68, 16, 71, 250, 226, 54, 124, 180,
        162, 52, 59, 59, 166, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

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

    xor_encypher_packet(&mut bytes, -1866898459).unwrap();
    assert_eq!(expected, bytes);
}
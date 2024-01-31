pub mod receivable;
pub mod sendable;

pub fn swap32(block: &[u8]) -> [u8; 8] {
    let mut output = [0u8; 8];
    let mut iteration = 1;
    for i in block.chunks(4) {
        let mut counter = iteration * 4;

        for j in i {
            output[counter - 1] = j.clone();
            counter -= 1;
        }

        iteration += 1;
    }

    output
}

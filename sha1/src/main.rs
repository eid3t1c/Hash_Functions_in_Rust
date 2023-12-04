use byte_string::ByteStr;
use byte_string::ByteString;
use modular::*;
use std::io;

fn default_state() -> (i64, i64, i64, i64, i64) {
    (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
}

fn padding(message : String) -> Vec<Vec<u32>> {
    let bmessage = ByteString(message.as_bytes().to_vec());
    let message_length  = bmessage.len();
    let padding_length = (64 - message_length as i8 - 8 - 1) as usize;
    let mut first_round_vals= Vec::new();
    let mut R1_vals = Vec::new();
    let mut padded = vec![];
    padded.extend_from_slice(&bmessage);
    padded.push(0x80);
    padded.extend(vec![0; padding_length.rem_euclid(64)]);
    padded.extend_from_slice(&(message_length*8).to_be_bytes().to_vec());
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for i in (0..padded.len()).step_by(4) {
        let block: Vec<u8> = padded[i..i + 4].to_vec();
        blocks.push(block);
    } 
    for b in &blocks {
        let num = u32::from_be_bytes((&b[..]).try_into().unwrap());
        first_round_vals.push(num);
        if first_round_vals.len() == 16 {
            R1_vals.push(first_round_vals.clone());
            first_round_vals.clear();
        }
    }

    R1_vals

}
// SHA-1 Functions
fn ch(x : i64,y : i64,z : i64) -> i64 {
    (x & y) ^ (!x & z)  
}

fn maj(x : i64,y : i64,z : i64) -> i64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn parity(x : i64,y : i64,z : i64) -> i64 {
     x ^ y ^ z
}

fn rotate_left(x: i64, y: i64) -> i64 {
    ((x << y) | (x >> (32-y))) & 0xFFFFFFFFi64 
}

const k: [i64; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

fn SHA1(message : String) {
    let mut state = default_state();
    let mut a: i64;
    let mut b: i64;
    let mut c: i64;
    let mut d: i64;
    let mut e: i64;
    let first = padding(message);
    let mut rounds: Vec<i64> = Vec::new();
    for i in(0..first.len()) {
        
        for r in (0..16) {
            rounds.push(first[i][r] as i64);
        }
        
        for w in (16..80) {
            rounds.push(((rotate_left(rounds[w-3] ^ rounds[w-8] ^ rounds[w-14] ^ rounds[w-16], 1))) & 0xFFFFFFFF);
        }
        
        let mut a = state.0 & 0xFFFFFFFF;;
        let mut b = state.1 & 0xFFFFFFFF;;
        let mut c = state.2 & 0xFFFFFFFF;;
        let mut d = state.3 & 0xFFFFFFFF;;
        let mut e = state.4 & 0xFFFFFFFF;;
        let mut T: i64;
        for round in 0..80 { 
            if round < 20 {
                T = ((rotate_left(a,5) + ch(b,c,d) + e + k[0] + rounds[round]) & 0xFFFFFFFF);
            }
            else if round < 40 {
                T = ((rotate_left(a,5) + parity(b,c,d) + e + k[1] + rounds[round]) & 0xFFFFFFFF);
            }
            else if  round < 60 {
                T = ((rotate_left(a,5) + maj(b,c,d) + e + k[2] + rounds[round]) & 0xFFFFFFFF);
            }
            else {
                T = ((rotate_left(a,5) + parity(b,c,d) + e + k[3] + rounds[round]) & 0xFFFFFFFF);
            }
            e = d;
            d = c;
            c = rotate_left(b, 30);
            b = a;
            a = T;
            
        }
        state.0 += a & 0xFFFFFFFF;
        state.1 += b & 0xFFFFFFFF;
        state.2 += c & 0xFFFFFFFF;
        state.3 += d & 0xFFFFFFFF;
        state.4 += e & 0xFFFFFFFF;
        rounds.clear();

    }
    // Final state of I-th block
    let mut hex_string = String::new();

    for &h in &[state.0, state.1, state.2, state.3, state.4] {
        let b = (h as i32).to_be_bytes(); 
        for &byte in &b {
            hex_string.push_str(&format!("{:02x}", byte));
        }
    }
    print!("\n{:?}", hex_string); 
}

fn main() {
    println!("Enter a message: \n");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    let message = input.trim().to_string();
    SHA1(message);
}
use byte_string::ByteStr;
use byte_string::ByteString;
use modular::*;
use std::io;

fn default_state() -> (i64, i64, i64, i64, i64, i64, i64, i64) {
    (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
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

// SHA-256 Functions
fn ch(x : i64,y : i64,z : i64) -> i64 {
    (x & y) ^ (!x & z)  
}

fn maj(x : i64,y : i64,z : i64) -> i64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn right_shift(x : i64, y : i64) -> i64{
    x >> y
}

fn rotate_right(x: i64, y: i64) -> i64 {
    ((x >> y) | (x << (32-y))) & 0xFFFFFFFF
}

fn sigma0(x : i64) -> i64 {
    rotate_right(x.clone(), 7) ^ rotate_right(x.clone(),18) ^ right_shift(x.clone(), 3)
}

fn sigma1(x : i64) -> i64 {
    rotate_right(x.clone(), 17) ^ rotate_right(x.clone(),19) ^ right_shift(x.clone(), 10)
}

fn Sigma0(x : i64) -> i64 {
     rotate_right(x.clone(),2) ^ rotate_right(x.clone(), 13) ^ rotate_right(x.clone(), 22)
}

fn Sigma1(x : i64) -> i64 {
    rotate_right(x.clone(),6) ^ rotate_right(x.clone(), 11) ^ rotate_right(x.clone(), 25)
}

const k: [i64; 64] = [
    1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748,
    2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206,
    2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983,
    1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671,
    3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372,
    1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411,
    3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734,
    506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779,
    1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479,
    3329325298,
];


fn main() {
    println!("Enter a message: \n");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    let message = input.trim().to_string();
    let mut state = default_state();
    let mut a: i64;
    let mut b: i64;
    let mut c: i64;
    let mut d: i64;
    let mut e: i64;
    let mut f: i64;
    let mut g: i64;
    let mut h: i64;
    let first = padding(message);
    let mut rounds: Vec<i64> = Vec::new();
    for i in(0..first.len()) {
        
        for r in (0..16) {
            rounds.push(first[i][r] as i64);
        }
        
        for w in (16..64) {
            rounds.push((sigma1(rounds[w-2]) + rounds[w-7] + sigma0(rounds[w-15]) + rounds[w-16]) & 0xFFFFFFFF);
        }
        
        let mut a = state.0 & 0xFFFFFFFF;
        let mut b = state.1 & 0xFFFFFFFF;
        let mut c = state.2 & 0xFFFFFFFF;
        let mut d = state.3 & 0xFFFFFFFF;
        let mut e = state.4 & 0xFFFFFFFF;
        let mut f = state.5 & 0xFFFFFFFF;
        let mut g = state.6 & 0xFFFFFFFF;
        let mut h = state.7 & 0xFFFFFFFF;
        let mut T1: i64;
        let mut T2: i64;
        
        for round in 0..64 {
            T1 = (h + Sigma1(e) + ch(e,f,g)+ k[round] as i64 + rounds[round]) & 0xFFFFFFFF ;
            T2 = (Sigma0(a) + maj(a,b,c)) & 0xFFFFFFFF ; 
            h = g;
            g = f;
            f = e;
            e = (d + T1) & 0xFFFFFFFF;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) & 0xFFFFFFFF;
        }
        state.0 += a & 0xFFFFFFFF;
        state.1 += b & 0xFFFFFFFF;
        state.2 += c & 0xFFFFFFFF;
        state.3 += d & 0xFFFFFFFF;
        state.4 += e & 0xFFFFFFFF;
        state.5 += f & 0xFFFFFFFF;
        state.6 += g & 0xFFFFFFFF;
        state.7 += h & 0xFFFFFFFF;
        rounds.clear();
    }
    // Final state of I-th block
    let mut hex_string = String::new();

    for &h in &[state.0, state.1, state.2, state.3, state.4,state.5,state.6,state.7] {
        let b = (h as i32).to_be_bytes(); 
        for &byte in &b {
            hex_string.push_str(&format!("{:02x}", byte));
        }
    }
    print!("\n{:?}", hex_string); 
}

use byte_string::ByteStr;
use byte_string::ByteString;
use modular::*;
use std::io;

fn default_state() -> (i128, i128, i128, i128, i128, i128, i128, i128) {
    (0x22312194FC2BF72C,0x9F555FA3C84C64C2,0x2393B86B6F53B151,0x963877195940EABD,0x96283EE2A88EFFE3,0xBE5E1E2553863992,0x2B0199FC2C85B8AA,0x0EB72DDC81C52CA2)
}

fn padding(message : String) -> Vec<Vec<u64>> {
    let bmessage = ByteString(message.as_bytes().to_vec());
    let message_length  = bmessage.len() as u128;
    let block_size: [u8; 16] = (message_length * 8).to_be_bytes();
    let padding_length = (128 - message_length - 16 - 1) as usize;
    let mut first_round_vals= Vec::new();
    let mut R1_vals = Vec::new();
    let mut padded = vec![];
    padded.extend_from_slice(&bmessage);
    padded.push(0x80);
    padded.extend(vec![0; padding_length.rem_euclid(128)]);
    padded.extend_from_slice(&block_size.to_vec());
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for i in (0..padded.len()).step_by(8) {
        let block: Vec<u8> = padded[i..i + 8].to_vec();
        blocks.push(block);
    } 
    for b in &blocks {
        let num = u64::from_be_bytes((&b[..]).try_into().unwrap());
        first_round_vals.push(num);
        if first_round_vals.len() == 16 {
            R1_vals.push(first_round_vals.clone());
            first_round_vals.clear();
        }
    }

    R1_vals

}

// SHA-512 Functions
fn ch(x : i128,y : i128,z : i128) -> i128 {
    (x & y) ^ (!x & z)  
}

fn maj(x : i128,y : i128,z : i128) -> i128 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn right_shift(x : i128, y : i128) -> i128{
    x >> y
}

fn rotate_right(x: i128, y: i128) -> i128 {
    ((x >> y) | (x << (64-y))) & 0xFFFFFFFFFFFFFFFFFFFFFFFF
}

fn sigma0(x : i128) -> i128 {
    rotate_right(x.clone(), 1) ^ rotate_right(x.clone(),8) ^ right_shift(x.clone(), 7)
}

fn sigma1(x : i128) -> i128 {
    rotate_right(x.clone(), 19) ^ rotate_right(x.clone(),61) ^ right_shift(x.clone(), 6)
}

fn Sigma0(x : i128) -> i128 {
     rotate_right(x.clone(),28) ^ rotate_right(x.clone(), 34) ^ rotate_right(x.clone(), 39)
}

fn Sigma1(x : i128) -> i128 {
    rotate_right(x.clone(),14) ^ rotate_right(x.clone(), 18) ^ rotate_right(x.clone(), 41)
}

const k: [i128; 80] = [4794697086780616226, 8158064640168781261, 13096744586834688815, 16840607885511220156, 4131703408338449720, 6480981068601479193, 10538285296894168987, 12329834152419229976, 15566598209576043074, 1334009975649890238, 2608012711638119052, 6128411473006802146, 8268148722764581231, 9286055187155687089, 11230858885718282805, 13951009754708518548, 16472876342353939154, 17275323862435702243, 1135362057144423861, 2597628984639134821, 3308224258029322869, 5365058923640841347, 6679025012923562964, 8573033837759648693, 10970295158949994411, 12119686244451234320, 12683024718118986047, 13788192230050041572, 14330467153632333762, 15395433587784984357, 489312712824947311, 1452737877330783856, 2861767655752347644, 3322285676063803686, 5560940570517711597, 5996557281743188959, 7280758554555802590, 8532644243296465576, 9350256976987008742, 10552545826968843579, 11727347734174303076, 12113106623233404929, 14000437183269869457, 14369950271660146224, 15101387698204529176, 15463397548674623760, 17586052441742319658, 1182934255886127544, 1847814050463011016, 2177327727835720531, 2830643537854262169, 3796741975233480872, 4115178125766777443, 5681478168544905931, 6601373596472566643, 7507060721942968483, 8399075790359081724, 8693463985226723168, 9568029438360202098, 10144078919501101548, 10430055236837252648, 11840083180663258601, 13761210420658862357, 14299343276471374635, 14566680578165727644, 15097957966210449927, 16922976911328602910, 17689382322260857208, 500013540394364858, 748580250866718886, 1242879168328830382, 1977374033974150939, 2944078676154940804, 3659926193048069267, 4368137639120453308, 4836135668995329356, 5532061633213252278, 6448918945643986474, 6902733635092675308, 7801388544844847127];

fn main() {
    println!("Enter a message: \n");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    let message = input.trim().to_string();
    let mut state = default_state();
    let mut a: i128;
    let mut b: i128;
    let mut c: i128;
    let mut d: i128;
    let mut e: i128;
    let mut f: i128;
    let mut g: i128;
    let mut h: i128;
    let first = padding(message);
    let mut rounds: Vec<i128> = Vec::new();
    for i in(0..first.len()) {
        
        for r in (0..16) {
            rounds.push(first[i][r] as i128);
        }
        
        for w in (16..80) {
            rounds.push((sigma1(rounds[w-2]) + rounds[w-7] + sigma0(rounds[w-15]) + rounds[w-16]) & 0xFFFFFFFFFFFFFFFF);
        }
        
        let mut a = state.0 & 0xFFFFFFFFFFFFFFFF;
        let mut b = state.1 & 0xFFFFFFFFFFFFFFFF;
        let mut c = state.2 & 0xFFFFFFFFFFFFFFFF;
        let mut d = state.3 & 0xFFFFFFFFFFFFFFFF;
        let mut e = state.4 & 0xFFFFFFFFFFFFFFFF;
        let mut f = state.5 & 0xFFFFFFFFFFFFFFFF;
        let mut g = state.6 & 0xFFFFFFFFFFFFFFFF;
        let mut h = state.7 & 0xFFFFFFFFFFFFFFFF;
        let mut T1: i128;
        let mut T2: i128;
        
        for round in 0..80 {
            T1 = (h + Sigma1(e) + ch(e,f,g)+ k[round] as i128 + rounds[round]) & 0xFFFFFFFFFFFFFFFF ;
            T2 = (Sigma0(a) + maj(a,b,c)) & 0xFFFFFFFFFFFFFFFF ; 
            h = g;
            g = f;
            f = e;
            e = (d + T1) & 0xFFFFFFFFFFFFFFFF;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) & 0xFFFFFFFFFFFFFFFF;
        }
        state.0 += a & 0xFFFFFFFFFFFFFFFF;
        state.1 += b & 0xFFFFFFFFFFFFFFFF;
        state.2 += c & 0xFFFFFFFFFFFFFFFF;
        state.3 += d & 0xFFFFFFFFFFFFFFFF;
        state.4 += e & 0xFFFFFFFFFFFFFFFF;
        state.5 += f & 0xFFFFFFFFFFFFFFFF;
        state.6 += g & 0xFFFFFFFFFFFFFFFF;
        state.7 += h & 0xFFFFFFFFFFFFFFFF;
        rounds.clear();
    }
    // Final state of I-th block
    let mut hex_string = String::new();

    for &h in &[state.0, state.1, state.2, state.3] {
        let b = (h as i64).to_be_bytes(); 
        for &byte in &b {
            hex_string.push_str(&format!("{:02x}", byte));
        }
    }
   // let hex_string = hex_string.get(0..std::cmp::min(56, hex_string.len())).unwrap_or_default();;
    print!("\n{:?}", hex_string); 
}

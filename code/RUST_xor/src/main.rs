use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt}; 

fn main() {
    let file = File::open("/home/naptax/tmp/rudesbies.Par").unwrap(); // J ouvre le fichier

    let mut reader = BufReader::new(file); // J'en produit un Buffer
    let mut enc_code = vec![]; // Crée un nouveau vecteur contenant des u8

    reader.read_to_end(&mut enc_code).unwrap(); // Charge le contenu du buffer dans mon vecteur
    
    let code_offset = 0x0000014E; // offset du début du code à XORer 
    enc_code = enc_code[code_offset..].to_vec();
    
    let key: u32 = 0x919E1E2E; // la clé avec laquelle est réalisé le XOR

    let mut out = vec![]; // Crée un vecteur qui va recevoir le code déchiffré
    
    for i in 0..enc_code.len() {
        out.push(enc_code[i] ^ key.to_le_bytes()[i % 4]); // fait le XOR
    }
    /* Le modulo 4 permet de s'assurer que la clé est utilisée de manière cyclique pour chacun des bytes de la variable enc_code 
    en utilisant toujours les 4 premiers bytes de la clé pour chiffrer les 8 premiers bytes de la variable enc_code, 
    les 4 prochains bytes de la clé pour chiffrer les 8 prochains bytes de la variable enc_code, etc. */
    
    let mut file = File::create("/home/naptax/tmp/stage2.bin").unwrap();
    let mut writer = BufWriter::new(file);
    
    writer.write_all(&out).unwrap();
}
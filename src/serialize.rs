use ark_serialize::CanonicalSerialize;
use hex::ToHex;
use serde_json::Value;
use std::{fmt::Write, fs::File};

use std::io::Write as Otherwrite;

use crate::preprocessing::{AngleShares, BracketShares};

// exanple: file_path = "./outputs/serialized_result.json"
fn create_file(file_path: &str) -> Result<File, std::io::Error> {
    // ./outputs/name.json
    let file = File::create(file_path)?;
    Ok(file)
}

fn write_data(file: &mut File, data: &[u8]) -> Result<(), std::io::Error> {
    file.write_all(data)?;
    Ok(())
}

pub fn write_to_file<T: CanonicalSerialize>(
    datas: Vec<(String, T)>,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // crate file
    let create_file_result = create_file(file_path);

    match create_file_result {
        Ok(_) => println!("The file has been successfully created."),
        Err(e) => {
            eprintln!("couldn't create output.json: {e}");
            // error handling
            return Err(Box::new(e));
        }
    }

    let mut file = create_file_result.unwrap();

    // create JSON object
    let processed_data = datas
        .iter()
        .map(|(variable_name, data)| {
            // serialize data
            let mut byte = Vec::new();
            data.serialize(&mut byte).unwrap();

            // convert from Vec<u8> to HEX string
            let hex_string = byte.encode_hex::<String>();

            let mut prefixed_hex_string = String::new();
            write!(prefixed_hex_string, "0x{}", hex_string).unwrap();

            let value: Value = prefixed_hex_string.into();
            (variable_name, value)
        })
        .collect::<Vec<_>>();

    let json_data: Value = processed_data.into_iter().collect();

    let json_string = serde_json::to_string_pretty(&json_data).unwrap();

    let write_result = write_data(&mut file, json_string.as_bytes());

    match write_result {
        Ok(_) => println!("The data has been successfully written."),
        Err(e) => {
            eprintln!("couldn't write data: {e}");
            // error handling
            return Err(Box::new(e));
        }
    }
    Ok(())
}

pub fn write_r(
    peer_num: usize,
    r_angle: AngleShares,
    r_bracket: BracketShares,
) -> Result<(), std::io::Error> {
    // TODO: Implement logic to handle variable `required_num` by filling or truncating the data as necessary.
    let required_num = 3;

    // separation
    let separated_angles = r_angle.separetion();
    let separated_brackets = r_bracket.separetion();

    // check length
    assert!(separated_angles[0].0.len() == required_num);
    assert!(separated_brackets[0].0.len() == required_num);

    // write
    for i in 0..peer_num {
        let output_file_path = format!("./outputs/{}/online_setup.json", i);

        let mut write_datas = Vec::new();

        for j in 0..required_num {
            write_datas.push((
                format!("r{}_angle_public_modifier", j),
                separated_angles[i].0[j],
            ));
            write_datas.push((format!("r{}_angle_share", j), separated_angles[i].1[j]));
            write_datas.push((format!("r{}_angle_mac", j), separated_angles[i].2[j]));

            write_datas.push((format!("r{}_bracket_share", j), separated_brackets[i].0[j]));

            write_datas.push((format!("r{}_bracket_mac", j), separated_brackets[i].1 .0[j]));
            for k in 0..peer_num {
                write_datas.push((
                    format!("r{}_bracket_mac_{}", j, k),
                    separated_brackets[i].1 .1[k][j],
                ));
            }
        }

        write_to_file(write_datas, &output_file_path).unwrap();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr;
    #[test]
    #[ignore]
    fn test_serialize_field() {
        let a = Fr::from(2);

        write_to_file(a, "./outputs/serialized_result.json", "test").unwrap();
    }
}

use ark_serialize::CanonicalSerialize;
use hex::ToHex;
use serde_json::json;
use std::{fmt::Write, fs::File};

use std::io::Write as Otherwrite;

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
    data: T,
    file_path: &str,
    variable_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // serialize commitment
    let mut byte = Vec::new();

    data.serialize(&mut byte).unwrap();

    // convert from Vec<u8> to HEX string
    let hex_string = byte.encode_hex::<String>();

    let mut prefixed_hex_string = String::new();
    write!(prefixed_hex_string, "0x{}", hex_string).unwrap();

    // create JSON object
    let json_data = json!({ variable_name: prefixed_hex_string });

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

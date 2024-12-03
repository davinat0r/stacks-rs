use std::{fmt, str::FromStr};

const INDEX_THRESHOLD: u32 = 2147483648;

#[derive(Clone, Copy, Debug)]
pub struct ChildNumber {
    index: u32,
    is_hardened: bool
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChildNumberError {
    InvalidIndex,
    CannotParseindex
}
impl fmt::Display for ChildNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match *self{
            ChildNumberError::InvalidIndex => f.write_str(&format!("Invalid derivation index!")),
            ChildNumberError::CannotParseindex => f.write_str(&format!("Cannot parse index from string!")),
        }
        
    }
}
impl std::error::Error for ChildNumberError {}

impl ChildNumber {
    pub fn new(index: u32) -> Result<Self, ChildNumberError> {
        Ok(Self { index: index, is_hardened: Self::is_hardened(index)? })
    }

    fn is_hardened(index: u32) -> Result<bool, ChildNumberError> {
        if index < INDEX_THRESHOLD {
            Ok(false)
        } else if index >= INDEX_THRESHOLD && index <= (INDEX_THRESHOLD - 1) * 2 + 1 {
            Ok(true)
        } else {
            Err(ChildNumberError::InvalidIndex)
        }
    } 
}

impl FromStr for ChildNumber {
    type Err = ChildNumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.contains("'") {
            true => {
                let index = s.replace("'", "").parse::<u32>().map_err(|_err| {
                    ChildNumberError::CannotParseindex
                })?;
                ChildNumber::new(index + INDEX_THRESHOLD)
            },
            false => {
                let index = s.parse::<u32>().map_err(|_err| {
                    ChildNumberError::CannotParseindex
                })?;
                ChildNumber::new(index)
            },
        }
    }
}

impl PartialEq for ChildNumber {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.is_hardened == other.is_hardened
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_child_number() {
        let mut index = 0;
        let child_number = ChildNumber::new(index).unwrap();
        assert_eq!(child_number.index, index);
        assert_eq!(child_number.is_hardened, false);
        
        index = 2147483648;
        let hardened_child_number = ChildNumber::new(index).unwrap();
        assert_eq!(hardened_child_number.index, index);
        assert_eq!(hardened_child_number.is_hardened, true);
    }

    #[test]
    fn test_child_number_from_str() {
        let mut index = "0";
        let child_number = ChildNumber::from_str(&index).unwrap();
        assert_eq!(child_number.index, 0);
        assert_eq!(child_number.is_hardened, false);

        index = "44'"; // == 2147483648
        let hardened_child_number = ChildNumber::from_str(&index).unwrap();
        assert_eq!(hardened_child_number.index, 2147483692);
        assert_eq!(hardened_child_number.is_hardened, true);
    }

    #[test]
    fn test_child_number_exceeds_max() {
        let index = "4294967299";
        match ChildNumber::from_str(&index) {
            Ok(_res) => panic!("Should not be okay"),
            Err(err) => assert_eq!(err, ChildNumberError::CannotParseindex),
        }
    }

    #[test]
    fn test_child_number_with_invalid_str() {
        let index = "c";
        match ChildNumber::from_str(&index) {
            Ok(_res) => panic!("Should not be okay"),
            Err(err) => assert_eq!(err, ChildNumberError::CannotParseindex),
        }
    }
}
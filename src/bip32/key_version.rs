use core::{error, fmt};

const VERSION_LEN: usize = 4;

pub enum Version {
    XPrv,
    XPub,
    TPrv,
    TPub,
    ZPrv,
    ZPub,
    YPrv,
    YPub,
}

impl Version {
    pub fn to_bytes(&self) -> [u8; VERSION_LEN] {
        fn convert<'a>(version_string: &str, buf: &'a mut [u8; VERSION_LEN]) {
            buf.copy_from_slice(&hex::decode(version_string).unwrap());
        }
        let mut version_bytes = [0u8; VERSION_LEN];
        match *self {
            Version::XPrv => {
                convert("0488ade4", &mut version_bytes);
                version_bytes
            },
            Version::XPub => {
                convert("0488b21e", &mut version_bytes);
                version_bytes
            },
            Version::TPrv => {
                convert("04358394", &mut version_bytes);
                version_bytes
            },
            Version::TPub => {
                convert("043587cf", &mut version_bytes);
                version_bytes
            }
            Version::ZPrv => {
                convert("04b2430c", &mut version_bytes);
                version_bytes
            },
            Version::ZPub => {
                convert("04b24746", &mut version_bytes);
                version_bytes
            },
            Version::YPrv => {
                convert("049d7878", &mut version_bytes);
                version_bytes
            },
            Version::YPub => {
                convert("049d7cb2", &mut version_bytes);
                version_bytes
            },
        }
    }

    pub fn to_string<'a>(&'a self) -> &'a str {
        match *self {
            Version::XPrv => "xprv",
            Version::XPub => "xpub",
            Version::TPrv => "tprv",
            Version::TPub => "tpub",
            Version::ZPrv => "zprv",
            Version::ZPub => "zpub",
            Version::YPrv => "yprv",
            Version::YPub => "ypub",
        }
    }
}

impl TryFrom<&[u8]> for Version {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != VERSION_LEN {
            Err(Error::VersionTooShort)
        } else {
            match hex::encode(value).as_str() {
                "xprv" => Ok(Version::XPrv),
                "xpub" => Ok(Version::XPub),
                "tprv" => Ok(Version::TPrv),
                "tpub" => Ok(Version::TPub),
                "zprv" => Ok(Version::ZPrv),
                "zpub" => Ok(Version::ZPub),
                "yprv" => Ok(Version::YPrv),
                "ypub" => Ok(Version::YPub),
                _ => Err(Error::InvalidVersion)
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    VersionTooShort
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidVersion => write!(f, "Invalid version"),
            Error::VersionTooShort => write!(f, "Version too short"),
        }
    }
}

impl error::Error for Error { }

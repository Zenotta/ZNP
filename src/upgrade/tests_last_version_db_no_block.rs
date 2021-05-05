/// !!! AUTOGENERATED: DO NOT EDIT !!!
/// Generated with: `path_to_upgrade_bin/upgrade --type all --processing read > path_to_file.rs`
///
/// Upgrade with config [("compute", Test(0))]
/// Preserved hard coded compute database
pub type DbEntryType = (&'static [u8], &'static [u8], &'static [u8]);

/// Database for compute, Test(0)
pub const COMPUTE_DB_V0_2_0: &[DbEntryType] = &[(
    b"default",
    b"RequestListKey",
    b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7F\x00\x00\x0140",
)];
/// Database for compute_raft, Test(0)
pub const COMPUTE_RAFT_DB_V0_2_0: &[DbEntryType] = &[
(b"default", b"EntryKey_6", b"\x10\x02\x18\x06\x22\xCD\x02\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x0004d6006a3923d06c00be1c9f26e38142e1defbe0d5a57ea60d94255c20a59a04\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00225cf9332e9e3518ea7111c31fcfab29b5ba4bb66e8c6dcdf0b2c99b32ba893d\x01\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00ga6d71de293071a6b8105dc8977952bc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\xA9\x98r\x00\x00\x00\x00\x00\xA9\x98r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00b2791ed55fb72717d96e1197eee1ca7b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002\x10\x01\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00"),
(b"default", b"HardStateKey", b"\x08\x02\x10\x01\x18\x06"),
(b"default", b"LastEntryKey", b"\x06\x00\x00\x00\x00\x00\x00\x00"),
(b"default", b"SnaphotKey", b"\x0A\xF2\x28\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x40\x00\x00\x00\x00\x00\x00\x0004d6006a3923d06c00be1c9f26e38142e1defbe0d5a57ea60d94255c20a59a04\x40\x00\x00\x00\x00\x00\x00\x0024c87c26cf5233f59ffe9b3f8f19cd7e1cdcf871dafb2e3e800e15cf155da944\x03\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00g2f6dbde7bb8fad8bc8f2d60ed152fb7\x20\x00\x00\x00\x00\x00\x00\x00gdfcdf57e87352ab2fe3e9c356e1e718\x20\x00\x00\x00\x00\x00\x00\x00gffb9abab147d717bd9cb6da3987db62\x03\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00g2f6dbde7bb8fad8bc8f2d60ed152fb7\x03\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00g15d207734998a4c4343df9dd0195dbf\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x002000000000000000673135643230373733343939386134633433343364663964643031393564626600000000\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x06\x60\xBC\x187l\x074\xBA\x92\x06Y\xBF\x18\x93\x97\x2BG\x8C\xBF\x5C\x7D\x07\xC1\x3C\x3D\xC8\xB2\x08\xA1\x92\xC3\x8Dqk\xEC\x10\x95\xB3\x22\xEE\xEA\x07\x22\xF6Y\xF3\xC69\xEC\xF6\x8D\xED\x99\xD0N5\x00v\xE4\x5B\xDF\xB1\x02\x02\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\xF4\xF0\xC1\xA9Q\x95\x9E\x88\xFE4\x3D\xE5\xA2\xEB\xE7\xEF\xBC\xB1T\x22\x09\x0B5IW\x7FBM\xB6\x85\x1C\xA5\x00\x00\x00\x00\x2B\x00\x00\x00\x00\x00\x00\x00\x5D\x00\x00\x00\x03\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x00\x00\x00_\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00g15d207734998a4c4343df9dd0195dbf\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x002000000000000000673135643230373733343939386134633433343364663964643031393564626601000000\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00mXc\xAF\xDC\xC1\xB0\xA5\xF2\xCB\xAE\xE6\xC4U\xBF\xC6t\x1FtWr\x8B\x13\x5BP\x83\xF3n\xA2n\x87\x91\x10S\x06\x13K\x0AI\x20\xF0\xDD\x98B\xE1\xEF\x013\xE438\xA9Au\x9C\xFD\xD3\x28\x3D\x8F52D\x09\x02\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\xF4\xF0\xC1\xA9Q\x95\x9E\x88\xFE4\x3D\xE5\xA2\xEB\xE7\xEF\xBC\xB1T\x22\x09\x0B5IW\x7FBM\xB6\x85\x1C\xA5\x00\x00\x00\x00\x2B\x00\x00\x00\x00\x00\x00\x00\x5D\x00\x00\x00\x03\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x00\x00\x00_\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00g15d207734998a4c4343df9dd0195dbf\x02\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x002000000000000000673135643230373733343939386134633433343364663964643031393564626602000000\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00Y\xBF\xD8Au\xAF\xD1i\xBD\xAA\xF6\xAE\x8C\x3D\xC7s\x89\x90\xC6T\xE9N\x2C\x1D\x1Ck\xE6c\x0A\xAA\x2E1\x15\xCEnI\x16\xF6\x0EU\x3C2z\x7D\x20\xE4Y\x08u\xB0\x01\xD6\x3B\xEADS1\x94\x22\x88\xF7\xDDu\x0D\x02\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\xF4\xF0\xC1\xA9Q\x95\x9E\x88\xFE4\x3D\xE5\xA2\xEB\xE7\xEF\xBC\xB1T\x22\x09\x0B5IW\x7FBM\xB6\x85\x1C\xA5\x00\x00\x00\x00\x2B\x00\x00\x00\x00\x00\x00\x00\x5D\x00\x00\x00\x03\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x00\x00\x00_\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00gdfcdf57e87352ab2fe3e9c356e1e718\x02\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00g15d207734998a4c4343df9dd0195dbf\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x002000000000000000673135643230373733343939386134633433343364663964643031393564626603000000\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x82\x88U\xC3F\x18\xC4\xA6t\xA6\xEFN\xE4\x21\xC7\x9D\x99\xC7\xC3\x17\x40\x25\xAC\x3EZ\x9C\x21\xAD\xAE\x85\xDB\xD5\xB4\x1A_\xA6\x2Dm\xA8\x02\x84\xD0A\xA2\xA7\x16\xDF\xA4\xB47K\xC5zy\x9A\x82\x94A\xB3\x9B\xF1\x84\xCC\x0E\x02\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\xF4\xF0\xC1\xA9Q\x95\x9E\x88\xFE4\x3D\xE5\xA2\xEB\xE7\xEF\xBC\xB1T\x22\x09\x0B5IW\x7FBM\xB6\x85\x1C\xA5\x00\x00\x00\x00\x2B\x00\x00\x00\x00\x00\x00\x00\x5D\x00\x00\x00\x03\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x00\x00\x00_\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00g15d207734998a4c4343df9dd0195dbf\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x002000000000000000673135643230373733343939386134633433343364663964643031393564626604000000\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\xDC1\xA9\xCE\xCDt\xF7\x93\xC9\xA7z\xDE\x85\xB87\x2D\xEA\xE1\xB2bc\xC3\x2B\x28o\x2D\x82\x05\x7B\xE5\x16\xDFJ\xA4W9t\x27\xC5tny\xC0W\x82C\x24\x3A\x8E\xD9\xC0D\xEE\x7F\xC2\xF5\xD4\xD9\xBC\x7EFS\xB1\x0B\x02\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\xF4\xF0\xC1\xA9Q\x95\x9E\x88\xFE4\x3D\xE5\xA2\xEB\xE7\xEF\xBC\xB1T\x22\x09\x0B5IW\x7FBM\xB6\x85\x1C\xA5\x00\x00\x00\x00\x2B\x00\x00\x00\x00\x00\x00\x00\x5D\x00\x00\x00\x03\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x00\x00\x00_\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00gffb9abab147d717bd9cb6da3987db62\x02\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00g3beca40882c0403330fcced1c25786c\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x002000000000000000673362656361343038383263303430333333306663636564316332353738366300000000\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x09\xCCf\xC7v\x60\xF3\xAA\xD5yf\x20\xFC0\xAC6\x3B\xC1k\x1D\xB0\x97\x8EQ\xA81p\x92\x5E\xC1V\xB8\x2CM\xC3\x10\x14\xAB\xE0\xEDw\xE6\x02\xD4\xFAo\xF1\x2C\xDD\xBC2W8Z\xF0\xA7\xBB\xA8\x0D\x85h\xB4\x20\x05\x02\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\xA8\x0F\xC20Y\x0E8\xBDd\x8D\xC6\xBCK\x60\x19\xD3\x9E\x84\x1Fxez\xD5\x13\x8F5\x1Ap\xB6\x16\x5CC\x00\x00\x00\x00\x2B\x00\x00\x00\x00\x00\x00\x00\x5D\x00\x00\x00\x03\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x00\x00\x00_\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00g3beca40882c0403330fcced1c25786c\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x002000000000000000673362656361343038383263303430333333306663636564316332353738366301000000\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x13\xF2\xDE\x9C\x1E\xE9\x3Bp\x27X\x3D\xE1\xBC\xE6\xE9\x98\xAE\xA2\x20\x8A\x82\xD4\xA2\x27\x9E\x7Fdn\xC1\x5E\xD9\x86\x1E\xF2\x0E\x40\xD3\x11\xEEpKm\xCC\x98\xAD\xBB\x7E\xB2y\x2C\x12M\x88\xD4\x14\x9D\xC4\x07\xA3\xB0\x24\x91\x8C\x03\x02\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\xA8\x0F\xC20Y\x0E8\xBDd\x8D\xC6\xBCK\x60\x19\xD3\x9E\x84\x1Fxez\xD5\x13\x8F5\x1Ap\xB6\x16\x5CC\x00\x00\x00\x00\x2B\x00\x00\x00\x00\x00\x00\x00\x5D\x00\x00\x00\x03\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x00\x00\x00_\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00000000\x01\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00be570a79d3066e78714600f5eb0e9b91\x06\x00\x00\x00\x00\x00\x00\x00000000\x02\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x001e47c0a4a718ad926d8d4cf0c2070344\x06\x00\x00\x00\x00\x00\x00\x00000000\x03\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00ef8cee427395f08788b7b7ffb94326ea\x06\x00\x00\x00\x00\x00\x00\x00000000\x04\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x008767ae43bc20271fe841ccd4bce36d5d\x06\x00\x00\x00\x00\x00\x00\x00000010\x00\x00\x00\x00\x01\x00\x00\x00\x00\x7B\x00\x00\x00\x00\x00\x00\x00\x7B\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00e3f86d92484539e695581ee111580eb3\x06\x00\x00\x00\x00\x00\x00\x00000011\x00\x00\x00\x00\x01\x00\x00\x00\x00\xD2\x04\x00\x00\x00\x00\x00\x00\xD2\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00b78d8dae72a6b79401cebaa64a8063db\x06\x00\x00\x00\x00\x00\x00\x00000011\x01\x00\x00\x00\x01\x00\x00\x00\x00\xD3\x04\x00\x00\x00\x00\x00\x00\xD3\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x005a4f627b0be3245edc7601bf3236bc77\x20\x00\x00\x00\x00\x00\x00\x00g2f6dbde7bb8fad8bc8f2d60ed152fb7\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x20\x00\x00\x00\x00\x00\x00\x00g2f6dbde7bb8fad8bc8f2d60ed152fb7\x01\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x20\x00\x00\x00\x00\x00\x00\x00g2f6dbde7bb8fad8bc8f2d60ed152fb7\x02\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x20\x00\x00\x00\x00\x00\x00\x00g50675ae09b507f5b02bd05f5ba49f4f\x00\x00\x00\x00\x01\x00\x00\x00\x00\xA9\x98r\x00\x00\x00\x00\x00\xA9\x98r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00d0031ff80365354c3a3162a407a9fe92\x20\x00\x00\x00\x00\x00\x00\x00ga6d71de293071a6b8105dc8977952bc\x00\x00\x00\x00\x01\x00\x00\x00\x00\xA9\x98r\x00\x00\x00\x00\x00\xA9\x98r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00b2791ed55fb72717d96e1197eee1ca7b\x20\x00\x00\x00\x00\x00\x00\x00gdfcdf57e87352ab2fe3e9c356e1e718\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x20\x00\x00\x00\x00\x00\x00\x00gdfcdf57e87352ab2fe3e9c356e1e718\x01\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00fa2165facd049a33f1134c6043012ffb\x20\x00\x00\x00\x00\x00\x00\x00gffb9abab147d717bd9cb6da3987db62\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x20\x00\x00\x00\x00\x00\x00\x00gffb9abab147d717bd9cb6da3987db62\x01\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x007027eda6d9ef25d7e1c4f833475e544f\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x7D\x3B\xE5\x00\x00\x00\x00\x00\xA8\x98r\x00\x00\x00\x00\x00\x12\x08\x0A\x02\x08\x01\x10\x06\x18\x02"),
];

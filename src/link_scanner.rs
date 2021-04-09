use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use cid::Cid;
use std::{
    convert::TryFrom,
    io::{Cursor, Read, Seek},
};

/// Wrapper of bytes that allows links to be scanned for lazily as an iterator.
pub(crate) struct LinkScanner<R> {
    reader: R,
    remaining: usize,
    scratch: [u8; 70],
}

impl<R> LinkScanner<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            remaining: 1,
            // TODO the 70 value can be tweaked, don't need much more than 32 bytes for def Cid
            scratch: [0u8; 70],
        }
    }
}

impl<'a> From<&'a [u8]> for LinkScanner<Cursor<&'a [u8]>> {
    fn from(bytes: &'a [u8]) -> Self {
        Self::new(Cursor::new(bytes))
    }
}

impl<'a> From<&'a Vec<u8>> for LinkScanner<Cursor<&'a [u8]>> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        Self::new(Cursor::new(bytes))
    }
}

impl From<Vec<u8>> for LinkScanner<Cursor<Vec<u8>>> {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(Cursor::new(bytes))
    }
}

impl<R> Iterator for LinkScanner<R>
where
    R: Read + Seek,
{
    type Item = Cid;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            let (maj, extra) = cbor_read_header_buf(&mut self.reader, &mut self.scratch).ok()?;
            match maj {
                // MajUnsignedInt, MajNegativeInt, MajOther
                0 | 1 | 7 => {}
                // MajByteString, MajTextString
                2 | 3 => {
                    self.reader
                        .seek(std::io::SeekFrom::Current(extra as i64))
                        .ok()?;
                }
                // MajTag
                6 => {
                    // Check if the tag refers to a CID
                    if extra == 42 {
                        let (maj, extra) =
                            cbor_read_header_buf(&mut self.reader, &mut self.scratch).ok()?;
                        // The actual CID is expected to be a byte string
                        if maj != 2 || extra > 100 {
                            return None;
                        }
                        self.reader.read_exact(&mut self.scratch[..extra]).ok()?;
                        let c = Cid::try_from(&self.scratch[1..extra]).ok()?;
                        self.remaining -= 1;
                        return Some(c);
                    } else {
                        self.remaining += 1;
                    }
                }
                // MajArray
                4 => {
                    self.remaining += extra;
                }
                // MajMap
                5 => {
                    self.remaining += extra * 2;
                }
                _ => {
                    return None;
                }
            }
            self.remaining -= 1;
        }
        None
    }
}

/// Given a CBOR encoded Buffer, returns a tuple of:
/// the type of the CBOR object along with extra
/// elements we expect to read. More info on this can be found in
/// Appendix C. of RFC 7049 which defines the CBOR specification.
/// This was implemented because the CBOR library we use does not expose low
/// methods like this, requiring us to deserialize the whole CBOR payload, which
/// is unnecessary and quite inefficient for our usecase here.
pub(crate) fn cbor_read_header_buf<B: Read>(br: &mut B, scratch: &mut [u8]) -> Result<(u8, usize)> {
    let first = br.read_u8()?;
    let maj = (first & 0xe0) >> 5;
    let low = first & 0x1f;

    if low < 24 {
        Ok((maj, low as usize))
    } else if low == 24 {
        let val = br.read_u8()?;
        if val < 24 {
            return Err(anyhow!(
                "cbor input was not canonical (lval 24 with value < 24)"
            ));
        }
        Ok((maj, val as usize))
    } else if low == 25 {
        br.read_exact(&mut scratch[..2])?;
        let val = BigEndian::read_u16(&scratch[..2]);
        if val <= u8::MAX as u16 {
            return Err(anyhow!(
                "cbor input was not canonical (lval 25 with value <= MaxUint8)"
            ));
        }
        Ok((maj, val as usize))
    } else if low == 26 {
        br.read_exact(&mut scratch[..4])?;
        let val = BigEndian::read_u32(&scratch[..4]);
        if val <= u16::MAX as u32 {
            return Err(anyhow!(
                "cbor input was not canonical (lval 26 with value <= MaxUint16)"
            ));
        }
        Ok((maj, val as usize))
    } else if low == 27 {
        br.read_exact(&mut scratch[..8])?;
        let val = BigEndian::read_u64(&scratch[..8]);
        if val <= u32::MAX as u64 {
            return Err(anyhow!(
                "cbor input was not canonical (lval 27 with value <= MaxUint32)"
            ));
        }
        Ok((maj, val as usize))
    } else {
        Err(anyhow!("invalid header cbor_read_header_buf"))
    }
}

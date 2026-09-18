//! FFI-free pack integers for Miri (Q-56).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactError { Empty, TruncatedU16, TruncatedU32, TruncatedU64, OverflowUleb, ShortDst }
impl std::fmt::Display for CompactError { fn fmt(&self, f: &mut std::fmt::Formatter<'_> ) -> std::fmt::Result { write!(f,"{self:?}") } }
impl std::error::Error for CompactError {}
#[inline] pub fn compact_size_len(n: u64) -> usize { if n<253 {1} else if n<=u16::MAX as u64 {3} else if n<=u32::MAX as u64 {5} else {9} }
pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n<253 { out.push(n as u8); } else if n<=u16::MAX as u64 { out.push(253); out.extend_from_slice(&(n as u16).to_le_bytes()); }
    else if n<=u32::MAX as u64 { out.push(254); out.extend_from_slice(&(n as u32).to_le_bytes()); } else { out.push(255); out.extend_from_slice(&n.to_le_bytes()); }
}
pub fn read_compact_size(buf: &[u8]) -> Result<(u64,usize), CompactError> {
    if buf.is_empty() { return Err(CompactError::Empty); }
    match buf[0] {
        n @ 0..=252 => Ok((n as u64,1)),
        253 => { if buf.len()<3 { return Err(CompactError::TruncatedU16); } let v=u16::from_le_bytes([buf[1],buf[2]]); Ok((v as u64,3)) },
        254 => { if buf.len()<5 { return Err(CompactError::TruncatedU32); } let v=u32::from_le_bytes(buf[1..5].try_into().unwrap()); Ok((v as u64,5)) },
        255 => { if buf.len()<9 { return Err(CompactError::TruncatedU64); } let v=u64::from_le_bytes(buf[1..9].try_into().unwrap()); Ok((v,9)) },
    }
}
#[inline] pub fn uleb128_len(mut n: u64) -> usize { let mut len=1; while n>=0x80 { n>>=7; len+=1; } len }
pub fn write_uleb128_into(dst: &mut [u8], mut n: u64) -> Result<usize, CompactError> {
    let mut i=0; loop { if i>=dst.len() { return Err(CompactError::ShortDst); } let mut b=(n & 0x7f) as u8; n>>=7; if n!=0 { b|=0x80; } dst[i]=b; i+=1; if n==0 { return Ok(i); } }
}
pub fn write_uleb128(out: &mut Vec<u8>, n: u64) { let mut tmp=[0u8;10]; let used=write_uleb128_into(&mut tmp,n).unwrap(); out.extend_from_slice(&tmp[..used]); }
pub fn read_uleb128(buf: &[u8]) -> Result<(u64,usize), CompactError> {
    let mut result=0u64; let mut shift=0u32;
    for (i,&b) in buf.iter().enumerate() { if shift>=64 { return Err(CompactError::OverflowUleb); } result|= u64::from(b & 0x7f) << shift; if b & 0x80==0 { return Ok((result,i+1)); } shift+=7; }
    Err(CompactError::Empty)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn compact_roundtrip() {
        for n in [0,1,252,253,254,255,256,65535,65536,u32::MAX as u64,u32::MAX as u64+1,u64::MAX] {
            let mut out=Vec::new(); write_compact_size(&mut out,n); assert_eq!(out.len(), compact_size_len(n));
            let (dec,used)=read_compact_size(&out).unwrap(); assert_eq!(dec,n); assert_eq!(used,out.len());
        }
    }
    #[test] fn uleb_roundtrip() {
        for n in [0,1,127,128,255,16383,16384,u64::MAX] {
            let mut out=Vec::new(); write_uleb128(&mut out,n); assert_eq!(out.len(), uleb128_len(n));
            let (dec,_)=read_uleb128(&out).unwrap(); assert_eq!(dec,n);
        }
    }
    #[cfg(miri)] #[test] fn miri_compact() { for n in 0..10000u64 { let mut out=Vec::new(); write_compact_size(&mut out,n); let (dec,_)=read_compact_size(&out).unwrap(); assert_eq!(dec,n); } }
}

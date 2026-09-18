//! FFI-free Bitcoin script number encoding (Q-56 Miri island).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptNumError { Overflow, NonMinimal }
impl std::fmt::Display for ScriptNumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_> ) -> std::fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for ScriptNumError {}
pub fn encode_scriptnum(mut n: i64) -> Vec<u8> {
    if n==0 { return vec![]; }
    let neg = n<0; if neg { n=-n; }
    let mut out=Vec::new();
    while n>0 { out.push((n & 0xff) as u8); n>>=8; }
    if out.last().map(|b| b & 0x80!=0).unwrap_or(false) { out.push(if neg {0x80} else {0x00}); }
    else if neg { *out.last_mut().unwrap()|=0x80; }
    out
}
pub fn is_minimal_scriptnum(vch: &[u8]) -> bool {
    if vch.is_empty() { return true; }
    if vch[vch.len()-1] & 0x7f ==0 && (vch.len()<=1 || (vch[vch.len()-2] & 0x80)==0) { return false; }
    true
}
pub fn decode_scriptnum(v: &[u8], require_minimal: bool, max_len: usize) -> Result<i64, ScriptNumError> {
    if v.len()>max_len { return Err(ScriptNumError::Overflow); }
    if require_minimal &&!is_minimal_scriptnum(v) { return Err(ScriptNumError::NonMinimal); }
    if v.is_empty() { return Ok(0); }
    let mut result: i64=0;
    for (i,&b) in v.iter().enumerate() { result|= (b as i64) << (8*i); }
    if v.last().unwrap() & 0x80!=0 { result &=!(0x80i64 << (8*(v.len()-1))); result = -result; }
    Ok(result)
}
pub fn decode_scriptnum_4(v: &[u8], require_minimal: bool) -> Result<i64, ScriptNumError> { decode_scriptnum(v, require_minimal, 4) }
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn roundtrip_basic() {
        for n in [0,1,-1,2,16,17,127,128,255,256,-255,-1000,0x7fffffff_i64,-0x7fffffff_i64] {
            let enc=encode_scriptnum(n); let dec=decode_scriptnum_4(&enc,true).unwrap(); assert_eq!(dec,n);
        }
    }
    #[test] fn minimality() {
        assert!(is_minimal_scriptnum(&[])); assert!(is_minimal_scriptnum(&[0x01])); assert!(!is_minimal_scriptnum(&[0x01,0x00]));
    }
    #[cfg(miri)] #[test] fn miri_roundtrip() {
        for n in -1000..1000 { let enc=encode_scriptnum(n as i64); if enc.len()<=4 { assert_eq!(decode_scriptnum_4(&enc,true).unwrap(), n as i64); } }
    }
}

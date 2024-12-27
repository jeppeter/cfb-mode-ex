
use std::error::Error;


pub trait Asn1EncryptOp {
	fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>>;
	fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
	fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1DecryptOp {
	fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>>;
	fn decrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
	fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}

// pub trait Asn1EncryptOpClone : Asn1EncryptOp + Clone + Sized {	
// }
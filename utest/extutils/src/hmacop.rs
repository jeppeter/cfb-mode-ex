
use sha1::{Sha1};
//use sha1::digest::{KeyInit};
use hmac::{Hmac,Mac};
use std::error::Error;
use extargsparse_worker::{extargs_error_class,extargs_new_error};

extargs_error_class!{HmacOpError}

type HmacSha1 = Hmac<Sha1>;

pub fn hmac_value_sha(authcode :&[u8],msgcode :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let ores = HmacSha1::new_from_slice(authcode);
	if ores.is_err() {
		let no = ores.err().unwrap();
		extargs_new_error!{HmacOpError,"new sha1 hMac error {:?}",no}	
	}

	let mut mac = ores.unwrap();
	mac.update(msgcode);
	let res = mac.finalize();
	Ok(res.into_bytes().to_vec())
}
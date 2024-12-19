use extargsparse_worker::{extargs_error_class,extargs_new_error};
use std::error::Error;

extargs_error_class!{NetOpError}

pub fn request_url_get_string(url :&str,bcheck :bool) -> Result<(i32,String),Box<dyn Error>> {
	//let client = reqwest::Client::new();
	let oclient :reqwest::Result<reqwest::blocking::Client>;
	if url.starts_with("https:") {
		if !bcheck {
			oclient = reqwest::blocking::ClientBuilder::new().danger_accept_invalid_certs(true).use_rustls_tls().build();	
		} else {
			oclient = reqwest::blocking::ClientBuilder::new().use_rustls_tls().build();
		}		
	} else {
		oclient = reqwest::blocking::ClientBuilder::new().build();
	}

	if oclient.is_err() {
		extargs_new_error!{NetOpError,"can not build client error {:?}",oclient.err().unwrap()}
	}
	let client = oclient.unwrap();
	let ores = client.get(url).send();
	if ores.is_err() {
		extargs_new_error!{NetOpError,"can not get [{}] error {:?}",url, ores.err().unwrap()}
	}
	let resp = ores.unwrap();
	let sts = resp.status().as_u16() as i32;
	let obody = resp.text();
	if obody.is_err() {
		extargs_new_error!{NetOpError,"get [{}] body error {:?}",url,obody.err().unwrap()}
	}
	let rs = obody.unwrap();
	return Ok((sts,rs));
	//Ok(format!(""))
}

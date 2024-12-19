#[allow(unused_imports)]
use extargsparse_codegen::{extargs_load_commandline,ArgSet,extargs_map_function};
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};
#[allow(unused_imports)]
use extargsparse_worker::namespace::{NameSpaceEx};
#[allow(unused_imports)]
use extargsparse_worker::argset::{ArgSetImpl};
use extargsparse_worker::parser::{ExtArgsParser};
use extargsparse_worker::funccall::{ExtArgsParseFunc};
//use asn1obj::asn1impl::Asn1Op;

use std::cell::RefCell;
use std::sync::Arc;
use std::error::Error;
use std::boxed::Box;
#[allow(unused_imports)]
use std::any::Any;

use lazy_static::lazy_static;
use std::collections::HashMap;

#[allow(unused_imports)]
use extlog::{debug_trace,debug_buffer_trace,format_buffer_log,format_str_log};
#[allow(unused_imports)]
use extlog::loglib::{log_get_timestamp,log_output_function};
use extutils::logtrans::{init_log};
use extutils::fileop::*;
use crate::impls::*;
use cfb_mode_ex;
use aes;
use aes::cipher::KeyIvInit;
use aes::cipher::AsyncStreamCipher;


#[derive(Clone)]
pub struct Aes128CfbAlgo {
    iv :Vec<u8>,
    key :Vec<u8>,
}

impl Aes128CfbAlgo {
    pub fn new(iv :&[u8],key :&[u8]) -> Result<Self,Box<dyn Error>> {
        let retv = Self {
            iv : iv.to_vec(),
            key :key.to_vec(),
        };
        Ok(retv)
    }
}

pub type Aes128CfbEnc = cfb_mode_ex::CfbBitsBufEncryptor<aes::Aes128,1>;
pub type Aes128CfbDec = cfb_mode_ex::BufDecryptor<aes::Aes128>;


impl Asn1EncryptOp for Aes128CfbAlgo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() >= 16 {
            self.iv = self.iv[0..16].to_vec();
        }
        if self.key.len() >= 16 {
            self.key = self.key[0..16].to_vec();
        }
        Ok(())
    }
    fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retdata :Vec<u8> = data.to_vec();
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        Aes128CfbEnc::new(ckey.into(),civ.into()).encrypt(&mut retdata);
        Ok(retdata)
    }
    fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}

impl Asn1DecryptOp for Aes128CfbAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.key = key.to_vec();
        self.iv = iv.to_vec();
        Ok(())
    }
    fn decrypt_update(&mut self, encdata :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retdata :Vec<u8> = encdata.to_vec();
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        Aes128CfbDec::new(ckey.into(),civ.into()).decrypt(&mut retdata);
        Ok(retdata)
    }
    fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}



extargs_error_class!{TstAesError}

fn aes128cbfenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 3 {
		extargs_new_error!{TstAesError,"need keyfile initfile infile"}
	}
	let keyfile = format!("{}",sarr[0]);
	let initfile = format!("{}",sarr[1]);
	let infile = format!("{}",sarr[2]);
	let mut outfile = format!("");
	if sarr.len() > 3 {
		outfile =format!("{}",sarr[3]);
	}

	let key = read_file_bytes(&keyfile)?;
	let iv = read_file_bytes(&initfile)?;
	let indata = read_file_bytes(&infile)?;

	let mut encobj :Aes128CfbAlgo = Aes128CfbAlgo::new(&key,&iv)?;
	encobj.init_encrypt(&key,&iv)?;
	let mut outdata = encobj.encrypt_update(&indata)?;
	outdata.extend(encobj.encrypt_final()?);
	if outfile.len() > 0 {
		write_file_bytes(&outfile,&outdata)?;
	} else {
		debug_buffer_trace!(indata.as_ptr(),indata.len(),"indata");
		debug_buffer_trace!(outdata.as_ptr(),outdata.len(),"outdata");
	}




	Ok(())
}


#[extargs_map_function(aes128cbfenc_handler)]
pub fn load_aes_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"aes128cbfenc<aes128cbfenc_handler>##keyfile initfile infile [outfile] to encrypt to outfile default stdout##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}
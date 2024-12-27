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
use extutils::strop::*;
use crate::impls::*;
use cfb_mode_ex;
use aes;
use aes::cipher::KeyIvInit;
//use aes::cipher::AsyncStreamCipher;

pub type Aes128CfbEnc = cfb_mode_ex::CfbBitsBufEncryptor<aes::Aes128,128>;
pub type Aes128CfbDec = cfb_mode_ex::CfbBitsBufDecryptor<aes::Aes128,128>;


#[derive(Clone)]
pub struct Aes128CfbAlgo {
    iv :Vec<u8>,
    key :Vec<u8>,
    innerenc :Aes128CfbEnc,
    innerdec :Aes128CfbDec,
    encinit :bool,
    decinit :bool,
}

impl Aes128CfbAlgo {
    pub fn new(iv :&[u8],key :&[u8]) -> Result<Self,Box<dyn Error>> {
        let mut niv :Vec<u8> = iv.to_vec().clone();
        let mut nkey :Vec<u8> = key.to_vec().clone();
        if niv.len() >= 16 {
            niv = niv[0..16].to_vec();
        }
        if nkey.len() >= 16 {
            nkey = nkey[0..16].to_vec();
        }
        let ckey :&[u8] = &nkey;
        let civ :&[u8] = &niv;
        let retv = Self {
            iv : niv.clone(),
            key :nkey.clone(),
            innerenc : Aes128CfbEnc::new(ckey.into(),civ.into()),
            innerdec : Aes128CfbDec::new(ckey.into(),civ.into()),
            encinit : false,
            decinit : false,
        };
        Ok(retv)
    }
}



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
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.decinit = false;
        self.innerenc = Aes128CfbEnc::new(ckey.into(),civ.into());
        self.encinit = true;
        Ok(())
    }
    fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retdata :Vec<u8> = data.to_vec();
        if !self.encinit {
            extargs_new_error!{TstAesError,"not init encrypt"}
        }
        self.innerenc.encrypt(&mut retdata);
        Ok(retdata)
    }
    fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        if !self.encinit {
            extargs_new_error!{TstAesError,"not init encrypt"}
        }
        Ok(vec![])
    }
}

impl Asn1DecryptOp for Aes128CfbAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() >= 16 {
            self.iv = self.iv[0..16].to_vec();
        }
        if self.key.len() >= 16 {
            self.key = self.key[0..16].to_vec();
        }
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.decinit = true;
        self.innerdec = Aes128CfbDec::new(ckey.into(),civ.into());
        self.encinit = false;
        Ok(())
    }
    fn decrypt_update(&mut self, encdata :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retdata :Vec<u8> = encdata.to_vec();
        if !self.decinit {
            extargs_new_error!{TstAesError,"not init decrypt"}
        }
        self.innerdec.decrypt(&mut retdata);
        Ok(retdata)
    }
    fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        if !self.decinit {
            extargs_new_error!{TstAesError,"not init decrypt"}
        }
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


fn aes128cbfdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {    
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
    encobj.init_decrypt(&key,&iv)?;
    let mut outdata = encobj.decrypt_update(&indata)?;
    outdata.extend(encobj.decrypt_final()?);
    if outfile.len() > 0 {
        write_file_bytes(&outfile,&outdata)?;
    } else {
        debug_buffer_trace!(indata.as_ptr(),indata.len(),"indata");
        debug_buffer_trace!(outdata.as_ptr(),outdata.len(),"outdata");
    }

    Ok(())
}

fn _get_mask_bits(inbytes :&[u8],bits :usize, offsetbits :usize) -> Vec<u8> {
    let mut idx :usize=0;
    let mut sbidx :usize;
    let mut scuridx :usize;
    let mut srem :usize;
    let mut dbix :usize;
    let mut drem :usize;
    let mut retv :Vec<u8> = vec![0;(bits + 7) >> 3];

    while idx < bits {
        scuridx = offsetbits + idx;
        sbidx = scuridx >> 3 ;
        srem = scuridx % 8;
        dbix = idx >> 3;
        drem = idx % 8;
        if (inbytes[sbidx] & ( 1 << (7 - srem))) != 0 {
            retv[dbix] |= 1 << (7 - drem);
        }
        idx += 1;
    }
    return retv;
}

fn _mask_new_bits(data :&mut [u8],bits :usize, offsetbits :usize, maskbytes :&[u8]) {
    let mut idx :usize=0;
    let mut dbidx :usize;
    let mut dcuridx :usize;
    let mut drem :usize;
    let mut sbix :usize;
    let mut srem :usize;

    while idx < bits {
        dcuridx = offsetbits + idx;
        dbidx = dcuridx  >> 3;
        drem = dcuridx % 8;
        sbix = idx >> 3;
        srem = idx % 8;
        if (maskbytes[sbix] & ( 1 << (7 - srem))) != 0 {
            debug_trace!("[{}]bit set [{}] shift {} [0x{:x}] => [0x{:x}]",idx, dbidx,drem, data[dbidx],data[dbidx] | (1 << (7 - drem)));
            data[dbidx] |= 1 << (7 - drem);
        } else {
            debug_trace!("[{}]bit clear [{}] shift {} [0x{:x}] => [0x{:x}]",idx, dbidx, drem, data[dbidx], data[dbidx] & (!(1 << (7 - drem))));
            data[dbidx] &= !(1 << (7 - drem));
        }
        idx += 1;
    }
    return;

}

fn maskbits_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {    
    let sarr :Vec<String>;
    let bits :usize;
    let offsetbits :usize;
    let mut maskbytes :Vec<u8> = vec![];
    let mut realbytes :Vec<u8> = vec![];
    init_log(ns.clone())?;
    sarr = ns.get_array("subnargs");
    if sarr.len() < 4 {
        extargs_new_error!{TstAesError,"need bits offsetbits masksize... realdata..."}
    }

    bits = parse_u64(&sarr[0])? as usize;
    if bits < 1 || bits > 128 {
        extargs_new_error!{TstAesError,"bits {} < 1 or > 128",bits}
    }

    offsetbits = parse_u64(&sarr[1])? as usize;
    let leastbytes = ((bits + 7) >> 3) + ((bits + offsetbits + 7) >> 3);

    if (sarr.len() - 2) < leastbytes  {
        extargs_new_error!{TstAesError,"need at least {} size", leastbytes + 2}
    }
    let masksize :usize = (bits + 7) >> 3;
    let mut idx :usize = 2;
    /*first to get lea*/
    debug_trace!("masksize {} bits {} bits >> 3 {}",masksize,bits, (bits + 7) >> 3);
    while maskbytes.len() < masksize {
        maskbytes.push(parse_u64(&sarr[idx])? as u8);
        idx += 1;
    }

    while idx < sarr.len() {
        realbytes.push(parse_u64(&sarr[idx])? as u8);
        idx += 1;
    }
    debug_buffer_trace!(realbytes.as_ptr(),realbytes.len(),"realbytes");
    debug_buffer_trace!(maskbytes.as_ptr(),maskbytes.len(),"maskbytes");

    let realmask = _get_mask_bits(&realbytes,bits,offsetbits);
    _mask_new_bits(&mut realbytes,bits,offsetbits,&maskbytes);
    debug_buffer_trace!(realmask.as_ptr(),realmask.len(),"realmask");
    debug_buffer_trace!(realbytes.as_ptr(),realbytes.len(),"after mask");


    Ok(())
}



#[extargs_map_function(aes128cbfenc_handler,aes128cbfdec_handler,maskbits_handler)]
pub fn load_aes_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"aes128cbfenc<aes128cbfenc_handler>##keyfile initfile infile [outfile] to encrypt to outfile default stdout##" : {
			"$" : "+"
		},
        "aes128cbfdec<aes128cbfdec_handler>##keyfile initfile infile [outfile] to encrypt to outfile default stdout##" : {
            "$" : "+"
        },
        "maskbits<maskbits_handler>##bits offsetbits maskbits ... input datas to mask bits##" : {
            "$" : "+"
        }
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}
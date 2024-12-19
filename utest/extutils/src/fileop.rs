
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};

use std::io;
use std::fs;
use std::io::prelude::*;
use std::io::BufReader;

use std::error::Error;
use crate::strop::{os_str_to_str};

extargs_error_class!{FileOpError}

fn _get_dirname(fname :&str) -> String {
	let path = std::path::Path::new(fname);
	let oparent = path.parent();
	if oparent.is_none() {
		return ".".to_string();
	}

	let parent = oparent.unwrap();
	return format!("{}",parent.display());
}

pub fn write_file_bytes(fname :&str, byts :&[u8]) -> Result<(),Box<dyn Error>> {
	let dname = _get_dirname(fname);
	if !exists_dir(&dname) {
		mkdir_safe(&dname)?;
	}


	if fname.len() == 0 {
		let res = io::stdout().write_all(byts);
		if res.is_err() {
			let err = res.err().unwrap();
			extargs_new_error!{FileOpError,"write [stdout] len[{}] error[{:?}]", byts.len(),err}	
		}
	} else {
		let fo  = fs::File::create(fname);
		if fo.is_err() {
			let err = fo.err().unwrap();
			extargs_new_error!{FileOpError,"create [{}] error[{:?}]", fname,err}
		}
		let mut fp :fs::File = fo.unwrap();
		let res = fp.write_all(byts);
		if res.is_err() {
			let err = res.err().unwrap();
			extargs_new_error!{FileOpError,"write [{}] len[{}] error[{:?}]", fname, byts.len(),err}	
		}
	}
	Ok(())
}

pub fn write_file(fname :&str, outs :&str) -> Result<(),Box<dyn Error>> {
	return write_file_bytes(fname,outs.as_bytes());
}


pub fn read_file_bytes(fname :&str) -> Result<Vec<u8>,Box<dyn Error>> {
	if fname.len() == 0 {
		let f = io::stdin();
		let mut reader = BufReader::new(f);
		let mut buf :Vec<u8> = Vec::new();
		let res = reader.read_to_end(&mut buf);
		if res.is_err() {
			let err = res.err().unwrap();
			extargs_new_error!{FileOpError,"read [{}] error [{:?}]", fname,err}
		}
		Ok(buf)
	} else {
		let fo = fs::File::open(fname);
		if fo.is_err() {
			let err = fo.err().unwrap();
			extargs_new_error!{FileOpError,"can not open [{}] error[{:?}]", fname, err}
		}
		let f = fo.unwrap();
		let mut reader = BufReader::new(f);
		let mut buf :Vec<u8> = Vec::new();
		let res = reader.read_to_end(&mut buf);
		if res.is_err() {
			let err = res.err().unwrap();
			extargs_new_error!{FileOpError,"read [{}] error [{:?}]", fname,err}
		}

		Ok(buf)		
	}
}

pub fn read_file(fname :&str) -> Result<String,Box<dyn Error>> {
	if fname.len() == 0 {
		let f = io::stdin();
		let mut reader = BufReader::new(f);
		let mut retv :String = String::new();
		let res = reader.read_to_string(&mut retv);
		if res.is_err() {
			let err = res.err().unwrap();
			extargs_new_error!{FileOpError,"read [{}] error [{:?}]", fname,err}
		}
		Ok(retv)
	} else {
		let fo = fs::File::open(fname);
		if fo.is_err() {
			let err = fo.err().unwrap();
			extargs_new_error!{FileOpError,"can not open [{}] error[{:?}]", fname, err}
		}
		let f = fo.unwrap();
		let mut reader = BufReader::new(f);
		let mut retv :String = String::new();
		let res = reader.read_to_string(&mut retv);
		if res.is_err() {
			let err = res.err().unwrap();
			extargs_new_error!{FileOpError,"read [{}] error [{:?}]", fname,err}
		}

		Ok(retv)		
	}
}

pub fn touch_file(infile :&str) -> Result<(),Box<dyn Error>> {
	let fpath = std::path::Path::new(infile);
	if !fpath.exists() {
		match std::fs::OpenOptions::new().create(true).write(true).open(&fpath) {
			Ok(_) => {
				return Ok(());
			},
			Err(e) => {
				extargs_new_error!{FileOpError,"touch {} error {:?}",infile,e}
			}
		}		
	}
	Ok(())
}


pub fn delete_file(infile :&str) -> Result<(),Box<dyn Error>> {
	let fpath = std::path::Path::new(infile);
	if fpath.exists() {
		let ores = std::fs::remove_file(&fpath);
		if ores.is_err() {
			extargs_new_error!{FileOpError,"remove file [{}] error {:?}",infile,ores.err().unwrap()}
		}
	}
	Ok(())
}

pub fn exists_file(infile :&str) -> bool {
	let fpath = std::path::Path::new(infile);
	if fpath.exists() {
		return true;
	}
	return false;
}

pub fn exists_dir(indir :&str) -> bool {
	let dpath = std::path::Path::new(indir);
	if dpath.exists() {
		let ores = std::fs::metadata(indir);
		if ores.is_ok() {
			let md = ores.unwrap();
			if md.is_dir() {
				return true;
			}
		}
	}
	return false;
}

pub fn mkdir_safe(dname :&str) -> Result<(),Box<dyn Error>> {
	let canres = std::fs::canonicalize(dname);
	let mut canname = format!("{}",dname);
	if canres.is_ok() {
		canname = format!("{}",canres.unwrap().display());
	}
	let bval = std::path::Path::new(&canname).exists();
	if bval {
		/*exists so do not make*/
		return Ok(());
	}

	let mut needcreated :Vec<String> = vec![];
	let mut curdname :String = format!("{}",canname);
	while curdname.len() > 1 {
		needcreated.insert(0,format!("{}",curdname));
		let oparent = std::path::Path::new(&curdname).parent();
		if oparent.is_none() {
			break;
		}
		let parentd = oparent.unwrap();
		if parentd.exists() {
			break;
		}
		curdname = format!("{}",parentd.display());
	}

	let mut idx :usize = 0;
	while idx < needcreated.len() {
		let res = std::fs::create_dir(&needcreated[idx]);
		if res.is_err() {
			extargs_new_error!{FileOpError,"can not create [{}] error {:?}",needcreated[idx],res.err().unwrap()}
		}
		idx += 1;
	}


	Ok(())
}

pub fn get_dir_items(dname :&str) -> Result<(Vec<String>,Vec<String>),Box<dyn Error>> {
	let ores = std::fs::read_dir(dname);
	if ores.is_err() {
		extargs_new_error!{FileOpError,"read {} error {:?}",dname,ores.err().unwrap()}
	}

	let paths = ores.unwrap();
	let mut others :Vec<String> = vec![];
	let mut dirs :Vec<String> = vec![];
	for cp in paths {
		if cp.is_ok() {
			let p = cp.unwrap();
			let ometa = p.metadata();
			if ometa.is_ok() {
				let md = ometa.unwrap();
				if md.is_dir() {
					dirs.push(format!("{}",os_str_to_str(&p.file_name())?));
				} else {
					others.push(format!("{}",os_str_to_str(&p.file_name())?));
				}
			} else {
				others.push(format!("{}",os_str_to_str(&p.file_name())?))
			}
		}
	}
	Ok((dirs,others))
}

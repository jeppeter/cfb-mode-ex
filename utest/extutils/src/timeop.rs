
use chrono::prelude::{DateTime,Utc};
use chrono::{Datelike,Timelike,TimeZone};
use extargsparse_worker::{extargs_error_class,extargs_new_error};
use chrono::Local;
//use extlog::*;
//use extlog::loglib::*;

use std::error::Error;

extargs_error_class!{TimeOpError}

pub fn get_time_utc_str() -> Result<String,Box<dyn Error>> {
	let now = Utc::now();
	Ok(format!("{:04}{:02}{:02}{:02}{:02}{:02}",now.year(),now.month(),now.day(),now.hour(),now.minute(),now.second()))
}

pub fn get_time_local_str() -> Result<String,Box<dyn Error>> {
	let now = Local::now();
	Ok(format!("{:04}{:02}{:02}{:02}{:02}{:02}",now.year(),now.month(),now.day(),now.hour(),now.minute(),now.second()))
}


fn _get_ival_bytes(bs :&[u8],sidx :usize,eidx:usize) -> Result<u32,Box<dyn Error>> {
	if bs.len() < eidx {
		extargs_new_error!{TimeOpError,"inner error for eidx {}",eidx}
	}
	let c = bs[sidx..eidx].to_vec().clone();
	let ores = std::str::from_utf8(&c);
	if ores.is_err() {
		extargs_new_error!{TimeOpError,"sidx {} eidx {} utf8 error {:?}",sidx,eidx,ores.err().unwrap()}
	}
	let s = format!("{}",ores.unwrap());
	match u32::from_str_radix(&s,10) {
		Ok(v) => {
			return Ok(v);
		},
		Err(e) => {
			extargs_new_error!{TimeOpError,"{} error {:?}",s,e}
		}
	}
}


pub fn tran_time_utc_from_str(ins :&str) -> Result<DateTime<Utc>,Box<dyn Error>> {
	let bs = ins.as_bytes().to_vec();
	if bs.len() != 14 {
		extargs_new_error!{TimeOpError,"{} not valid len {}",ins,bs.len()}
	}
	let bs = ins.as_bytes().to_vec();
	let iyear = _get_ival_bytes(&bs,0,4)?;
	let imon = _get_ival_bytes(&bs,4,6)?;
	let iday = _get_ival_bytes(&bs,6,8)?;
	let ihour = _get_ival_bytes(&bs,8,10)?;
	let imin = _get_ival_bytes(&bs,10,12)?;
	let isec = _get_ival_bytes(&bs,12,14)?;
	let odt = Utc.with_ymd_and_hms(iyear as i32,imon,iday,ihour,imin,isec);
	match odt {
		chrono::LocalResult::None => {
			extargs_new_error!{TimeOpError,"{} not valid",ins}
		},
		chrono::LocalResult::Single(e) => {
			return Ok(e);
		},
		chrono::LocalResult::Ambiguous(_b,_b2) => {
			extargs_new_error!{TimeOpError,"{} not valid",ins}
		}
	}
}






#[cfg(target_os = "linux")]
use libc::{clock_gettime,CLOCK_MONOTONIC_COARSE,timespec};

#[cfg(target_os = "windows")]
use winapi::um::sysinfoapi::*;

pub const MAX_U64_VAL :u64 = 0xffffffffffffffff;

#[cfg(target_os = "linux")]
pub fn get_cur_ticks() -> u64 {
	let mut  curtime = timespec {
		tv_sec : 0,
		tv_nsec : 0,
	};
	unsafe {clock_gettime(CLOCK_MONOTONIC_COARSE,&mut curtime);};
	let mut retmills : u64 = 0;
	retmills += (curtime.tv_sec as u64 )  * 1000;
	retmills += ((curtime.tv_nsec as u64) % 1000000000) / 1000000;
	return retmills;
}

#[cfg(target_os = "windows")]
pub fn get_cur_ticks() -> u64 {
	let retv :u64;
	unsafe {
		retv = GetTickCount64() as u64;
	}
	return retv;
}


pub fn time_left(sticks : u64,cticks :u64, leftmills :i32) -> i32 {
	let eticks = sticks + leftmills as u64;
	if cticks < eticks && cticks >= sticks {
		return (eticks - cticks) as i32;
	}

	if (MAX_U64_VAL - sticks) < (leftmills as u64) {
		if cticks > 0 && cticks < (leftmills as u64 - (MAX_U64_VAL - sticks)) {
			return ((leftmills as u64) - (MAX_U64_VAL - sticks) - cticks) as i32;
		}

		if cticks >= sticks && cticks < MAX_U64_VAL {
			return ((leftmills as u64) - (cticks - sticks)) as i32;
		}
	}
	return -1;
}

pub fn utc_time_trans_value(tmval :i64) -> String {
    let rets :String;
    let onative = DateTime::<Utc>::from_timestamp(tmval,0);
    let dt :DateTime<Utc>;

    if onative.is_some() {
        //let native = onative.unwrap();
        //dt = DateTime::<Utc>::from_naive_utc_and_offset(native,Utc);
        dt = onative.unwrap();
    } else {
        dt = chrono::offset::Utc::now();
    }
    

    let newdate = dt.format("%Y-%m-%d %H:%M:%S");
    rets = format!("{}",newdate);
    return rets;
}

pub fn utc_timestamp() -> i64 {
	let dt = chrono::offset::Utc::now();
	return dt.timestamp() as i64;
}


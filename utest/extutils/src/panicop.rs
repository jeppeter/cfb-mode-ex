
use std::panic::{set_hook,PanicInfo};
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};
use extargsparse_codegen::{extargs_load_commandline,extargs_map_function};
use extargsparse_worker::namespace::NameSpaceEx;
use extargsparse_worker::funccall::ExtArgsParseFunc;
use crate::fileop::{mkdir_safe,write_file,exists_dir,get_dir_items,delete_file};
use crate::timeop::{get_time_utc_str};
use extargsparse_worker::parser::{ExtArgsParser};
use lazy_static::lazy_static;
use std::collections::HashMap;
//use std::backtrace::{Backtrace};
use backtrace::{Backtrace};

use std::error::Error;
use extlog::*;
use extlog::loglib::*;
use crate::procop::{get_exec_dir};
use crate::strop::{quote_string};
use std::io::{Write};

extargs_error_class!{PanicOpError}

static mut PANIC_DIR:Option<String> = None;
static mut PANIC_VERBOSE :i32 = 0;
static mut PANIC_STDDERR : bool = false;


fn set_panic_dir(dname :&str) -> Result<(),Box<dyn Error>> {
	unsafe {
		PANIC_DIR = Some(format!("{}",dname));
	}
	Ok(())
}

fn panic_hook_fn(info :&PanicInfo<'_>) {
	let mut outs = "".to_string();
	let mut outok : bool = false;
	let mut verbose :bool = false;
	if unsafe {PANIC_VERBOSE >= 3} {
		verbose= true;
	}
	if verbose {
		let bk = Backtrace::new();
		outs.push_str(&format!("{:?}\n",bk));
	}
	outs.push_str(&format!("{}",info));
	if unsafe {PANIC_DIR.is_some()} {
		let dname :String = unsafe{format!("{}",PANIC_DIR.as_ref().unwrap())};
		if dname.len() > 0 {
			let ores = mkdir_safe(&dname);
			if ores.is_ok() {
				let ores = get_time_utc_str();
				if ores.is_ok() {
					let times = ores.unwrap();
					let fname = format!("{}/panic_{}.log",dname,times);
					let ores = write_file(&fname,&outs);
					if ores.is_ok() {
						outok = true;
					}
				}
			}			
		}
	}
	if !outok || unsafe {PANIC_STDDERR} {
		eprintln!("{}",outs);
		let _ = std::io::stderr().flush();
	}
	return;
}

fn set_panic_hook(dname :&str) -> Result<(),Box<dyn Error>> {
	let _ = set_panic_dir(dname)?;
	set_hook(Box::new(|s| {
		panic_hook_fn(s);
	}));
	Ok(())
}

fn set_panic_verbose(verbse :i32) -> Result<(),Box<dyn Error>> {
	unsafe {
		PANIC_VERBOSE = verbse;
	}
	debug_trace!("PANIC_VERBOSE {}",unsafe{PANIC_VERBOSE});
	Ok(())
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PanicLog {
	idxval :i64,
	fname :String,
}

impl PanicLog {
	fn new(fname :&str, idx :i64) -> Self {
		Self {
			fname : format!("{}",fname),
			idxval : idx,
		}
	}
}


fn _clear_panic_max(dname :&str, maxcnt :i64) -> Result<(),Box<dyn Error>> {
	if dname.len() == 0 || maxcnt == 0 {
		/*nothing to handle*/
		return Ok(());
	}

	if !exists_dir(dname) {
		debug_trace!("no exists_dir [{}]",dname);
		return Ok(());
	}

	let (_,paths) = get_dir_items(dname)?;
	let exprstr :String = format!("^panic_([0-9]+).log$");
	let ores = regex::Regex::new(&exprstr);
	if ores.is_err() {
		extargs_new_error!{PanicOpError,"compile [{}] error [{:?}]",exprstr,ores.err().unwrap()}
	}
	let mexpr = ores.unwrap();
	let mut logs :Vec<PanicLog> = vec![];
	
	for p in paths.iter() {
		debug_trace!("p [{}]",p);
		let ores = mexpr.captures(p);
		if ores.is_some() {
			let v = ores.unwrap();
			if v.len() > 1 {
				let cpn = std::path::Path::new(dname).join(v.get(0).unwrap().as_str());
				let name  = format!("{}",cpn.display());
				let idxs = format!("{}",v.get(1).unwrap().as_str());
				let idx = i64::from_str_radix(&idxs,10)?;
				logs.push(PanicLog::new(&name,idx));
			}
		}
	}

	if logs.len() > maxcnt as usize {
		/*now to sort*/
		logs.sort();
		let mut uidx :usize = 0;
		while uidx < (logs.len() - maxcnt as usize) {
			debug_trace!("delete [{}]",logs[uidx].fname);
			delete_file(&logs[uidx].fname)?;
			uidx += 1;
		}
	}


	Ok(())
}

pub fn init_panicop(ns :NameSpaceEx) -> Result<(),Box<dyn Error>> {
	let dname = ns.get_string("panicdir");
	let enable = ns.get_bool("panicenable");
	let panicstderr = ns.get_bool("panicstderr");
	let maxcnt = ns.get_int("panicmaxcnt");
	if !enable {
		return Ok(());
	}

	debug_trace!("maxcnt {} dname [{}]",maxcnt,dname);

	let _ = _clear_panic_max(&dname,maxcnt);

	unsafe {
		PANIC_STDDERR = panicstderr;
	}

	let _ = set_panic_hook(&dname)?;
	let iv = ns.get_int("panicverbose") as i32;
	let _ = set_panic_verbose(iv)?;
	Ok(())
}

#[extargs_map_function()]
pub fn load_panicop_commandline(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let sdir = quote_string(&get_exec_dir()?)?;
	let cmdline = format!(r#"
	{{
		"panicdir" : {},
		"panicenable##if false will no panic handle##" : true,
		"panicverbose##3 for dump stack##" : 3,
		"panicstderr##to flush output to stderr ##" : false,
		"panicmaxcnt##to specified whether count file to clean##" : 10
	}}
	"#,sdir);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}


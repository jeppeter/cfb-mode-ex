

use extargsparse_worker::{extargs_error_class,extargs_new_error};
use std::error::Error;
use sysinfo;
use std::collections::HashMap;
#[allow(unused_imports)]
use extlog::{debug_trace,format_str_log};
#[allow(unused_imports)]
use extlog::loglib::{log_get_timestamp,log_output_function};

extargs_error_class!{PropOpError}

pub fn get_exec_name() -> Result<String,Box<dyn Error>> {
	let ores = std::env::current_exe();
	if ores.is_err() {
		extargs_new_error!{PropOpError,"can not get current_exe {:?}",ores.err().unwrap()}
	}
	let ename = ores.unwrap();
	Ok(format!("{}",ename.display()))
}

pub fn get_exec_dir() -> Result<String,Box<dyn Error>> {
	let ename = get_exec_name()?;
	let oparent = std::path::Path::new(&ename).parent();
	if oparent.is_none() {
		extargs_new_error!{PropOpError,"can not get parent for [{}]",ename}
	}
	let parentd = oparent.unwrap();
	Ok(format!("{}",parentd.display()))
}

pub fn get_pid_by_exact_name(n :&str) -> Vec<u64> {
	let mut retv :Vec<u64> = vec![];
	let mut system = sysinfo::System::new();
	system.refresh_all();
	let nostr = std::ffi::OsStr::new(n);
	for p in system.processes_by_name(nostr) {
		retv.push(p.pid().as_u32() as u64);
	}

	return retv;
}

pub struct ProcessTree {
	pub pid :u64,
	pub children :Vec<ProcessTree>,
}

impl ProcessTree {
	fn new(pid :u64) -> Self {
		Self {
			pid : pid,
			children : vec![],
		}
	}

	pub fn to_string(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut idx :i32 = 0;
		while idx < tab {
			rets.push_str(&format!("    "));
			idx += 1;
		}
		rets.push_str(&format!("{}\n",self.pid));
		let mut cidx :usize = 0;
		while cidx < self.children.len() {
			rets.push_str(&self.children[cidx].to_string(tab + 1));
			cidx += 1;
		}
		return rets;
	}
}

fn is_search_pid(smap :&HashMap<u64,bool>,pid :u64) -> bool {
	match smap.get(&pid) {
		Some(_v) => {
			return true;
		},
		_ => {
			return false;
		}
	}
}

pub fn get_pid_children_tree(pid :u64) -> ProcessTree {
	let mut system = sysinfo::System::new();
	let mut rettree :ProcessTree;
	system.refresh_all();
	let retmap = system.processes();
	let mut procmap :HashMap<u64,Vec<u64>> = HashMap::new();
	for (k,v) in retmap {
		let op :Option<sysinfo::Pid> = v.parent();
		let mut cv :Vec<u64>;
		if op.is_some() {
			let p = op.unwrap();
			if let Some(ov) = procmap.get(&(p.as_u32() as u64)) {
				cv = ov.clone();
				cv.push(k.as_u32() as u64);
			} else {
				cv = vec![k.as_u32() as u64];
			}
			//debug_trace!("p {} children {:?}",p.as_u32(),cv);
			procmap.insert(p.as_u32() as u64, cv);
		}
	}

	let mut cont :bool = true;
	let mut nextsearch :Vec<*mut ProcessTree> = vec![];
	let mut cursearch :Vec<*mut ProcessTree> ;
	let mut searched :HashMap<u64,bool> = HashMap::new();
	let mut idx :usize;
	let mut jdx :usize;
	let mut kdx :usize;

	rettree = ProcessTree::new(pid);
	nextsearch.push(&mut rettree as * mut ProcessTree);

	while cont {
		cont = false;
		cursearch = vec![];
		kdx = 0;
		jdx = nextsearch.len();
		while kdx < jdx {
			cursearch.push(nextsearch[kdx]);
			kdx += 1;
		}
		nextsearch = vec![];
		idx = 0;
		while idx < cursearch.len() {
			if !is_search_pid(&searched,unsafe{(*cursearch[idx]).pid}) {
				searched.insert(unsafe{(*cursearch[idx]).pid},true);

				/*now get the value*/
				match procmap.get(&(unsafe{(*cursearch[idx]).pid})) {
					Some(v) => {
						cont = true;
						jdx = 0;
						while jdx < v.len() {
							let ctree :ProcessTree = ProcessTree::new(v[jdx]);
							unsafe {(*cursearch[idx]).children.push(ctree)};
							kdx = unsafe{(*cursearch[idx]).children.len()} - 1;
							nextsearch.push(unsafe{&mut (*cursearch[idx]).children[kdx]} as *mut ProcessTree);
							jdx += 1;
						}						
					},
					_ => {

					}
				}
			}
			idx += 1;
		}
	}

	return rettree;

}
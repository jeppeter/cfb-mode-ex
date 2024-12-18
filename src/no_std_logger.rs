






#[allow(dead_code)]
pub fn set_cfb_ex_logger_disable() {
	return;
}

#[allow(dead_code)]
pub fn set_cfb_ex_logger_enable() {
	return ;
}


#[allow(dead_code)]
pub (crate)  fn cfb_ex_debug_out(level :i32, outs :&str) {
	return;
}

#[allow(dead_code)]
pub (crate) fn cfb_ex_log_get_timestamp() -> String {
	return format!("time");
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_log_error {
	($($arg:tt)+) => {
		let mut c :String= format!("[CFB_EX]<ERROR>{}[{}:{}]  ",cfb_ex_log_get_timestamp(),file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		cfb_ex_debug_out(0,&c);
	}
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_log_warn {
	($($arg:tt)+) => {
		let mut c :String= format!("[CFB_EX]<WARN>{}[{}:{}]  ",cfb_ex_log_get_timestamp(),file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		cfb_ex_debug_out(10,&c);
	}
}


#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_log_info {
	($($arg:tt)+) => {
		let mut c :String= format!("[CFB_EX]<INFO>{}[{}:{}]  ",cfb_ex_log_get_timestamp(),file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		cfb_ex_debug_out(20,&c);
	}
}



#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_assert {
	($v:expr , $($arg:tt)+) => {
		if !($v) {
			let mut _c :String= format!("[CFB_EX][{}:{}] ",file!(),line!());
			_c.push_str(&(format!($($arg)+)[..]));
			panic!("{}", _c);
		}
	}
}


#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_format_buffer_log {
	($buf:expr,$len:expr,$info:tt,$iv:expr,$($arg:tt)+) => {
		let mut c :String = format!("[CFB_EX][{}:{}]",file!(),line!());
		c.push_str(&format!("{} ",$info));
		c.push_str(&cfb_ex_log_get_timestamp());
		c.push_str(": ");
		c.push_str(&(format!($($arg)+)[..]));
		let _ptr :*const u8 = $buf as *const u8;
		let  mut _ci :usize;
		let _totallen: usize = $len as usize;
		let mut _lasti :usize = 0;
		let mut _nb :u8;
		c.push_str(&format!(" buffer [{:?}][{}]",_ptr,_totallen));
		_ci = 0;
		while _ci < _totallen {
			if (_ci % 16) == 0 {
				if _ci > 0 {
					c.push_str("    ");
					while _lasti < _ci {
						unsafe{
							_nb = *_ptr.offset(_lasti as isize);	
						}
						
						if _nb >= 0x20 && _nb <= 0x7e {
							c.push(_nb as char);
						} else {
							c.push_str(".");
						}
						_lasti += 1;
					}
				}
				c.push_str(&format!("\n0x{:08x}:", _ci));
			}
			unsafe {_nb = *_ptr.offset(_ci as isize);}			
			c.push_str(&format!(" 0x{:02x}",_nb));
			_ci += 1;
		}

		if _lasti < _ci {
			while (_ci % 16) != 0 {
				c.push_str("     ");
				_ci += 1;
			}

			c.push_str("    ");

			while _lasti < _totallen {
				unsafe {_nb = *_ptr.offset(_lasti as isize);}				
				if _nb >= 0x20 && _nb <= 0x7e {
					c.push(_nb as char);
				} else {
					c.push_str(".");
				}
				_lasti += 1;
			}
			//c.push_str("\n");
		}
		cfb_ex_debug_out($iv,&c);
	}
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_debug_buffer_error {
	($buf:expr,$len:expr,$($arg:tt)+) => {
		cfb_ex_format_buffer_log!($buf,$len,"<ERROR>",0,$($arg)+);
	}
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_debug_buffer_warn {
	($buf:expr,$len:expr,$($arg:tt)+) => {
		cfb_ex_format_buffer_log!($buf,$len,"<WARN>",10,$($arg)+);
	}
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_debug_buffer_info {
	($buf:expr,$len:expr,$($arg:tt)+) => {
		cfb_ex_format_buffer_log!($buf,$len,"<INFO>",20,$($arg)+);
	}
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_debug_buffer_debug {
	($buf:expr,$len:expr,$($arg:tt)+) => {
		cfb_ex_format_buffer_log!($buf,$len,"<DEBUG>",30,$($arg)+);
	}
}



#[macro_export]
#[allow(unused_macros)]
#[cfg(feature="debug_mode")]
macro_rules! cfb_ex_log_trace {
	($($arg:tt)+) => {
		let mut _c :String= format!("[CFB_EX]<TRACE>{}[{}:{}]  ",cfb_ex_log_get_timestamp(),file!(),line!());
		_c.push_str(&(format!($($arg)+)[..]));
		cfb_ex_debug_out(40, &_c);
	}
}

#[macro_export]
#[allow(unused_macros)]
#[cfg(not(feature="debug_mode"))]
macro_rules! cfb_ex_log_trace {
	($($arg:tt)+) => {}
}


#[macro_export]
#[allow(unused_macros)]
#[cfg(feature="debug_mode")]
macro_rules! cfb_ex_debug_buffer_trace {
	($buf:expr,$len:expr,$($arg:tt)+) => {
		cfb_ex_format_buffer_log!($buf,$len,"<TRACE>",40,$($arg)+);
	}
}

#[macro_export]
#[allow(unused_macros)]
#[cfg(not(feature="debug_mode"))]
macro_rules! cfb_ex_debug_buffer_trace {
	($buf:expr,$len:expr,$($arg:tt)+) => {}
}

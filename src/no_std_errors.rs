
/// to define the error class called for cfb_ex_new_error
/// ```
/// cfb_ex_error_class!{ExampleClass}
/// ```
#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_error_class {
	($type:ident) => {
		#[derive(Clone)]
		struct $type {
			msg :String,
			fname :String,
			lineno :u32,
			types :String,
		}

		#[allow(dead_code)]
		impl $type {
			fn create(fname :&str,lineno :u32, types :&str,c :&str) -> $type {
				$type {
					msg : format!("{}",c),
					fname : format!("{}",fname),
					lineno : lineno,
					types : format!("{}",types),
				}
			}
		}

		impl core::fmt::Display for $type {
			fn fmt(&self,f :&mut core::fmt::Formatter) -> core::fmt::Result {
				let mut errdisplay : bool =false;
				match core::env::var("CFB_EX_ERROR_LEVEL") {
					Ok(vs) => {
						match vs.parse::<i32>() {
							Ok(v) => {
								if v >= 3 {
									errdisplay = true;
								}
							},
							Err(_e) => {
							}
						}
					},
					_ => {},
				}
				if errdisplay {
					write!(f,"[{}:{}][{}]{}",self.fname,self.lineno,self.types,self.msg)
				} else {
					write!(f,"{}",self.msg)	
				}
				
			}
		}

		impl core::fmt::Debug for $type {
			fn fmt(&self,f :&mut core::fmt::Formatter) -> core::fmt::Result {
				let mut errdisplay : bool =false;
				match core::env::var("CFB_EX_ERROR_LEVEL") {
					Ok(vs) => {
						match vs.parse::<i32>() {
							Ok(v) => {
								if v >= 3 {
									errdisplay = true;
								}
							},
							Err(_e) => {
							}
						}
					},
					_ => {},
				}
				if errdisplay {
					write!(f,"[{}:{}][{}]{}",self.fname,self.lineno,self.types,self.msg)
				} else {
					write!(f,"{}",self.msg)	
				}				
			}
		}

		impl core::error::Error for $type {}
	};
}

/// to call return Err(Box<dyn Error>)
/// ```
/// cfb_ex_new_error!{ExampleError,"example error call {}","new error"}
/// ```
#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_new_error {
	($type:ty,$($a:expr),*) => {
		{
			let fname = format!("{}",file!());
			let lineno = line!();
			let types = format!("{}",stringify!($type));
			let mut c :String= format!("");
			c.push_str(&(format!($($a),*)[..]));
			return Err(Box::new(<$type>::create(&fname,lineno,&types,c.as_str())));
		}
	};
}


/// to call return Box<dyn Error>
/// ```
/// cfb_ex_error_create!{ExampleError,"example error call {}","new error"}
/// ```
#[macro_export]
#[allow(unused_macros)]
macro_rules! cfb_ex_error_create {
	($type:ty,$($a:expr),*) => {
		{
			let fname = format!("{}",file!());
			let types = format!("{}",stringify!($type));
			let mut c :String= format!("");
			c.push_str(&(format!($($a),*)[..]));
			Box::new(<$type>::create(&fname,line!(),&types,c.as_str()))
		}
	};
}

use rand::Rng;

pub fn get_rand_value(minval :u64, maxval :u64) -> u64 {
	let mut rng = rand::thread_rng();
	let mut nval :u64 = rng.gen::<u64>();
	let sval = maxval - minval;
	nval = nval % sval;
	nval += minval;
	return nval;
}
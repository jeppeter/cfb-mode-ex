/// to make cfb1
#[derive(Clone)]
pub struct CfbBitsBufEncryptor<C,const BITSIZE:u8=8>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
    pos: usize,
}

impl<C,const BITSIZE:u8> CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{

    fn _encrypt_bitsize(&mut self,inbytes :&[u8],outbytes :&mut[u8],ivec :&mut [u8],nbits :usize) {
        let mut ovec :[u8;16*2+1] = [0;16*2+1];
        let num :usize = ((nbits + 7) >> 3) as usize;
        let mut n:usize;
        ovec[0..16].copy_from_slice(&ivec[0..16]);
        self.cipher.encrypt_block_mut(ivec.into());
        n = 0;
        while n<num {
            ovec[16+n] = inbytes[n] ^ ivec[n];
            outbytes[n] = ovec[16+n];
            n += 1;
        }
        let rem = nbits % 8;
        let leftnum = (nbits >> 3) as usize;
        if rem == 0 {
            ivec[0..16].copy_from_slice(&ovec[leftnum..leftnum+16]);
        } else {
            n = 0;
            while n < 16 {
                ivec[n] = ((ovec[n + leftnum] << rem) | (ovec[n + leftnum + 1] >> (8 - rem))) as u8;
                n += 1;
            }
        }
        return;
    }

    fn _encrypt_bits_shift(&mut  self, data :&mut [u8],ivec :&mut [u8],nbits :usize) {
        let mut c:[u8;1] = [0;1];
        let mut d:[u8;1] = [0;1];
        let mut n :usize;
        let mask :u8;
        let topbits :u8;
        topbits = ((1 << nbits) - 1) as u8;
        mask = (topbits << (8 - nbits)) as u8;

        n = 0;
        while n < nbits {
            if (data[n >> 3] & (topbits << ( 7 - n%8))) != 0 {
                c[0] = mask;
            } else {
                c[0] = 0;
            }
            self._encrypt_bitsize(&c,&mut d,ivec,nbits);
            data[n >> 3] = data[n >> 3] & (!(1 << (7 - n % 8 ))) | (( d[0] & mask ) >> (n % 8));
            n += nbits;
        }
        return;
    }

    /// Encrypt a buffer in multiple parts.
    #[allow(unreachable_code)]
    pub fn encrypt(&mut self, mut data: &mut [u8]) {

        if (8 % BITSIZE) != 0 {
            panic!("8 % {} != 0",BITSIZE);
        }
        let mut iv = self.iv.clone();

        self._encrypt_bits_shift(&mut data,&mut iv,BITSIZE as usize);
        self.iv = iv.clone();
        return;

        let bs = C::BlockSize::USIZE;
        let n = data.len();

        cfb_ex_log_trace!("C::BlockSize::USIZE {} bs {} self.pos {}",C::BlockSize::USIZE,bs,self.pos);

        if n < bs - self.pos {
        	cfb_ex_log_trace!("step {}", n);
            xor_set1(data, &mut self.iv[self.pos..self.pos + n]);
            self.pos += n;
            return;
        }

        let (left, right) = { data }.split_at_mut(bs - self.pos);
        data = right;
        let mut iv = self.iv.clone();
        xor_set1(left, &mut iv[self.pos..]);
        self.cipher.encrypt_block_mut(&mut iv);

        let mut chunks = data.chunks_exact_mut(bs);
        for chunk in &mut chunks {
            xor_set1(chunk, iv.as_mut_slice());
            self.cipher.encrypt_block_mut(&mut iv);
        }

        let rem = chunks.into_remainder();
        xor_set1(rem, iv.as_mut_slice());
        self.pos = rem.len();
        self.iv = iv;
    }

    /// Returns the current state (block and position) of the decryptor.
    pub fn get_state(&self) -> (&Block<C>, usize) {
        (&self.iv, self.pos)
    }

    /// Restore from the given state for resumption.
    pub fn from_state(cipher: C, iv: &Block<C>, pos: usize) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            pos,
        }
    }
}

impl<C,const BITSIZE:u8> InnerUser for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C,const BITSIZE:u8> IvSizeUser for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C,const BITSIZE:u8> InnerIvInit for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn inner_iv_init(mut cipher: C, iv: &Iv<Self>) -> Self {
        let mut iv = iv.clone();
        cfb_ex_debug_buffer_trace!(iv.as_ptr(),iv.len(),"iv init");
        cipher.encrypt_block_mut(&mut iv);
        cfb_ex_debug_buffer_trace!(iv.as_ptr(),iv.len(),"encrypt iv");
        Self { cipher, iv, pos: 0 }
    }
}

impl<C,const BITSIZE:u8> AlgorithmName for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::CfbBitsBufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C,const BITSIZE:u8> fmt::Debug for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::CfbBitsBufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher,const BITSIZE:u8> Drop for CfbBitsBufEncryptor<C,BITSIZE> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop,const BITSIZE:u8> ZeroizeOnDrop for CfbBitsBufEncryptor<C,BITSIZE> {}

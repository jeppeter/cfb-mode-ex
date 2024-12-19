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
    /// Encrypt a buffer in multiple parts.
    pub fn encrypt(&mut self, mut data: &mut [u8]) {
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
        cipher.encrypt_block_mut(&mut iv);
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

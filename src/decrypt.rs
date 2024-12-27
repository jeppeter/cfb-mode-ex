use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{ArrayLength, GenericArray},
    inout::InOut,
    AlgorithmName, AsyncStreamCipher, Block, BlockBackend, BlockCipher, BlockClosure, BlockDecrypt,
    BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocks,
    ParBlocksSizeUser, Unsigned,
};
use core::fmt;
#[allow(unused_imports)]
use crate::logger::*;
use crate::*;
use crate::bits::*;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};


include!("bufdec.rs");
include!("bitbufdec.rs");

/// CFB mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
}


impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockDecryptMut for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend_mut(Closure { iv, f })
    }
}

impl<C> AsyncStreamCipher for Decryptor<C> where C: BlockEncryptMut + BlockCipher {}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}


impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}


impl<C> InnerIvInit for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn inner_iv_init(mut cipher: C, iv: &Iv<Self>) -> Self {
        let mut iv = iv.clone();
        cipher.encrypt_block_mut(&mut iv);
        Self { cipher, iv }
    }
}


impl<C> IvState for Decryptor<C>
where
    C: BlockEncryptMut + BlockDecrypt + BlockCipher,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        let mut res = self.iv.clone();
        self.cipher.decrypt_block(&mut res);
        res
    }
}

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}


impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}


#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher> Drop for Decryptor<C> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}


#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for Decryptor<C> {}


struct Closure<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    iv: &'a mut GenericArray<u8, BS>,
    f: BC,
}

impl<'a, BS, BC> BlockSizeUser for Closure<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BC> BlockClosure for Closure<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { iv, f } = self;
        f.call(&mut Backend { iv, backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    iv: &'a mut GenericArray<u8, BS>,
    backend: &'a mut BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type ParBlocksSize = BK::ParBlocksSize;
}

impl<'a, BS, BK> BlockBackend for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut t = block.clone_in();
        block.xor_in2out(self.iv);
        self.backend.proc_block((&mut t).into());
        *self.iv = t;
    }

    #[inline(always)]
    fn proc_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let mut t = ParBlocks::<Self>::default();
        let b = (blocks.get_in(), &mut t).into();
        self.backend.proc_par_blocks(b);

        let n = t.len();
        blocks.get(0).xor_in2out(self.iv);
        for i in 1..n {
            blocks.get(i).xor_in2out(&t[i - 1])
        }
        *self.iv = t[n - 1].clone();
    }
}

#[inline(always)]
fn xor_set2(buf1: &mut [u8], buf2: &mut [u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a;
        *a ^= *b;
        *b = t;
    }
}

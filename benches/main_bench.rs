use criterion::{criterion_group, criterion_main, Criterion};
use wasmtime::*;
use byteorder::ByteOrder;
use rand::Rng;

macro_rules! sha256 {
    ($c:ident, $name:expr, $code:expr) => {
        $c.bench_function($name, |b| {
            let store = Store::default();

            let module = Module::new(store.engine(), $code).unwrap();
            let memory = Memory::new(&store, MemoryType::new(Limits::new(1, None)));

            let k_base = 352;
            let m_base = 640;

            unsafe {
                let mem = memory.data_unchecked_mut();
                let k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
                let mut rng = rand::thread_rng();

                for i in 0..k.len() {
                    byteorder::LE::write_u32(&mut mem[k_base + 4*i.. k_base + 4 * i + 4], k[i]);
                }

                for i in 0..4096 {
                    mem[m_base + i] = rng.gen();
                }
            }

            let instance = Instance::new(&store, &module, &[memory.into()]).unwrap();

            let init = instance.get_func("init").unwrap()
                .get0::<()>().unwrap();
            let update = instance.get_func("update").unwrap()
                .get1::<i32, ()>().unwrap();
            let fin = instance.get_func("final").unwrap()
                .get0::<()>().unwrap();
            
            b.iter(|| {
                init().expect("init failed");
                update(4096).expect("update failed");
                fin().expect("final failed");
            })
        });
    }
}

macro_rules! salsa20 {
    ($c:ident, $name:expr, $code:expr) => {
        $c.bench_function($name, |b| {
            let store = Store::default();

            let module = Module::new(store.engine(), $code).unwrap();
            let memory = Memory::new(&store, MemoryType::new(Limits::new(2, None)));

            let mut k: [u32; 8] = [0; 8];
            let mut nonce: [u32; 2] = [0; 2];
            let bytes = 4096;

            let c_start = 32 * 4;
            let m_start = c_start + bytes;

            unsafe {
                let mem = memory.data_unchecked_mut();
                let mut rng = rand::thread_rng();

                for i in 0..4096 {
                    mem[m_start + i] = rng.gen();
                }

                for i in 0..8 {
                    k[i] = rng.gen();
                }

                for i in 0..2 {
                    nonce[i] = rng.gen();
                }
            }

            let instance = Instance::new(&store, &module, &[memory.into()]).unwrap();

            let keysetup = instance.get_func("keysetup").unwrap()
                .get8::<u32, u32, u32, u32, u32, u32, u32, u32, ()>().unwrap();
            let noncesetup = instance.get_func("noncesetup").unwrap()
                .get2::<u32, u32, ()>().unwrap();
            let encrypt = instance.get_func("encrypt").unwrap()
                .get1::<u32, ()>().unwrap();
            
            b.iter(|| {
                keysetup(k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]).expect("keysetup failed");
                noncesetup(nonce[0], nonce[1]).expect("noncesetup failed");
                encrypt(4096).expect("encrypt failed");
            })
        });
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let sec_sha256 = include_str!("../wasm/sec_sha256.wat"); 
    let pub_sha256 = include_str!("../wasm/pub_sha256.wat");
    let sec_salsa20 = include_str!("../wasm/sec_salsa20.wat"); 
    let pub_salsa20 = include_str!("../wasm/pub_salsa20.wat");
    
    sha256!(c, "sec_sha256", sec_sha256);
    sha256!(c, "pub_sha256", pub_sha256);

    salsa20!(c, "sec_salsa20", sec_salsa20);
    salsa20!(c, "pub_salsa20", pub_salsa20);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
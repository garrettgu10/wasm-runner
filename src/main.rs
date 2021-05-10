use wasmtime::*;
use anyhow::Result;

fn main() -> Result<()> {
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::Speed);

    let store = Store::new(&Engine::new(&config));

    let module = Module::new(store.engine(), include_str!("../wasm/fact_salsa20.wat")).unwrap();
    let sec_memory = Memory::new(&store, MemoryType::new(Limits::new(512, None)));
    let pub_memory = Memory::new(&store, MemoryType::new(Limits::new(512, None)));

    let bytes: usize = 256;
    let m_start = 0;
    let n_start = m_start + bytes;
    let k_start = n_start + 8;
    let k_end = k_start + 32;

    unsafe {
        let secmem = sec_memory.data_unchecked_mut();
        let pubmem = pub_memory.data_unchecked_mut();
        let mut rng = rand::thread_rng();

        for i in 0..bytes {
            secmem[i] = 0;
        }

        for i in n_start..k_start {
            pubmem[i] = 0;
        }

        for i in k_start..k_end {
            secmem[i] = 0;
        }
    }

    let instance = Instance::new(&store, &module, &[sec_memory.into(), pub_memory.into()]).unwrap();

    let crypto_stream = instance.get_func("_crypto_stream_salsa20").unwrap()
        .get4::<u32, u64, u32, u32, u32>().unwrap();

    crypto_stream(
        m_start as u32, 
        bytes as u64, 
        n_start as u32, 
        k_start as u32).expect("crypto stream failed");

    unsafe {
        let secmem = sec_memory.data_unchecked_mut();
        for i in 0..bytes {
            print!("{:02x?}", secmem[i]);
        }
    }

}

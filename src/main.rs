use wasmtime::*;
use anyhow::Result;

fn main1() {
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::Speed);

    let store = Store::new(&Engine::new(&config));

    let module = Module::new(store.engine(), include_str!("../wasm/sec_salsa20.wat")).unwrap();
    let memory = Memory::new(&store, MemoryType::new(Limits::new(2, None)));

    let mut k: [u32; 8] = [0; 8];
    let mut nonce: [u32; 2] = [0; 2];
    let bytes: usize = 64;

    let c_start = 32 * 4;
    let m_start = c_start + bytes;

    unsafe {
        let mem = memory.data_unchecked_mut();
        let mut rng = rand::thread_rng();

        for i in 0..bytes {
            mem[m_start + i] = 1;
        }

        for i in 0..8 {
            k[i] = 0;
        }

        for i in 0..2 {
            nonce[i] = 0;
        }
    }

    let instance = Instance::new(&store, &module, &[memory.clone().into()]).unwrap();

    let keysetup = instance.get_func("keysetup").unwrap()
        .get8::<u32, u32, u32, u32, u32, u32, u32, u32, ()>().unwrap();
    let noncesetup = instance.get_func("noncesetup").unwrap()
        .get2::<u32, u32, ()>().unwrap();
    let encrypt = instance.get_func("encrypt").unwrap()
        .get1::<u32, ()>().unwrap();
    
    keysetup(k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]).expect("keysetup failed");
    noncesetup(nonce[0], nonce[1]).expect("noncesetup failed");
    encrypt(bytes as u32).expect("encrypt failed");

    unsafe {
        let secmem = memory.data_unchecked_mut();
        for i in 0..bytes {
            print!("{:02x?}", secmem[c_start + i]);
        }
    }
}

fn main(){
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::Speed);

    let store = Store::new(&Engine::new(&config));

    let module = Module::new(store.engine(), include_str!("../wasm/fact_salsa20.wat")).unwrap();
    let sec_memory = Memory::new(&store, MemoryType::new(Limits::new(512, None)));
    let pub_memory = Memory::new(&store, MemoryType::new(Limits::new(512, None)));

    let bytes: usize = 64;
    let m_start = 0;
    let n_start = m_start + bytes;
    let k_start = n_start + 8;
    let k_end = k_start + 32;
    let c_start = k_end;

    unsafe {
        let secmem = sec_memory.data_unchecked_mut();
        let pubmem = pub_memory.data_unchecked_mut();
        let mut rng = rand::thread_rng();

        for i in 0..bytes {
            secmem[i] = 1;
        }

        for i in n_start..k_start {
            pubmem[i] = 0;
        }

        for i in k_start..k_end {
            secmem[i] = 0;
        }
    }

    let instance = Instance::new(&store, &module, &[sec_memory.clone().into(), pub_memory.into()]).unwrap();

    let encrypt = instance.get_func("salsa20_encrypt").unwrap()
        .get6::<u32, u64, u32, u64, u32, u32, ()>().unwrap();

    encrypt(
        m_start as u32, 
        bytes as u64, 
        c_start as u32,
        bytes as u64,
        n_start as u32, 
        k_start as u32).expect("crypto stream failed");

    unsafe {
        let secmem = sec_memory.data_unchecked_mut();
        for i in 0..bytes {
            print!("{:02x?}", secmem[c_start + i]);
        }
    }

    println!("");

    main1();
}

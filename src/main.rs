use wasmtime::*;
use anyhow::Result;

fn sha256(secret: bool) {

}

fn main() -> Result<()> {
    // All wasm objects operate within the context of a "store"
    let store = Store::default();

    // Modules can be compiled through either the text or binary format
    let wat = include_str!("../wasm/test.wat");
    let module = Module::new(store.engine(), wat)?;

    // Host functions can be defined which take/return wasm values and
    // execute arbitrary code on the host.
    let host_hello = Func::wrap(&store, |param: i32| {
        println!("Got {} from WebAssembly", param);
    });

    // Instantiation of a module requires specifying its imports and then
    // afterwards we can fetch exports by name, as well as asserting the
    // type signature of the function with `get_typed_func`.
    let instance = Instance::new(&store, &module, &[host_hello.into()])?;
    let hello = instance
        .get_func("hello")
        .ok_or(anyhow::format_err!("failed to find function"))?
        .get0::<()>()?;

    // And finally we can call the wasm as if it were a Rust function!
    hello()?;

    Ok(())
}

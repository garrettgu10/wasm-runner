(module
    (import "" "" (func $host_hello (param i32)))

    (func (export "hello") trusted
        i32.const 3
        call $host_hello)
)
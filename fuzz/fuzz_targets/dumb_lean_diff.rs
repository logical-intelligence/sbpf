#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

use solana_sbpf::{
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    program::{BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::{RequisiteVerifier, Verifier},
};
use test_utils::{create_vm, TestContextObject};

use crate::common::ConfigTemplate;

mod common;
mod grammar_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct DumbFuzzData {
    template: ConfigTemplate,
    prog: Vec<u8>,
    mem: Vec<u8>,
    max_steps: u8,
}

fuzz_target!(|data: DumbFuzzData| {
    let prog = data.prog;
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();
    let syscall_registry = FunctionRegistry::<BuiltinFunction<TestContextObject>>::default();

    if RequisiteVerifier::verify(
        &prog,
        &config,
        SBPFVersion::V3,
        &function_registry,
        &syscall_registry,
    )
    .is_err()
    {
        // verify please
        return;
    }


    let mut mem_rust_vm = data.mem.clone();
    let executable = Executable::<TestContextObject>::from_text_bytes(
        &prog,
        std::sync::Arc::new(BuiltinProgram::new_loader(
            config,
        )),
        SBPFVersion::V3,
        function_registry,
    )
    .unwrap();

    // Run Rust interpreter
    let mem_region = MemoryRegion::new_writable(&mut mem_rust_vm, ebpf::MM_INPUT_START);
    let max_steps = (data.max_steps % 100 + 1) as u64;
    let mut context_object = TestContextObject::new(max_steps);
    create_vm!(
        interp_vm,
        &executable,
        &mut context_object,
        stack,
        heap,
        vec![mem_region],
        None
    );
    let (_interp_ins_count, interp_res, interp_regs) = interp_vm.execute_program_with_regs(&executable, true);

    // Run Lean implementation
    let (code_vaddr, code_bytes) = executable.get_text_bytes();
    let lean_result = unsafe {
        let version_num = match executable.get_sbpf_version() {
            SBPFVersion::V0 => 0,
            SBPFVersion::V1 => 1,
            SBPFVersion::V2 => 2,
            SBPFVersion::V3 => 3,
            SBPFVersion::V4 => 4,
            _ => 5,
        };

        let function_registry_vec = executable.get_function_registry().iter().map(
            |(key, (symbol, address))|
                lean_impl::FunctionRegistryEntry {
                    key,
                    symbol: symbol.to_vec(),
                    address: address.to_string()
                }
        ).collect();

        let loader_function_registry_vec = executable.get_loader().get_function_registry().iter().map(
            |(key, (symbol, fn_ptr))|
                lean_impl::FunctionRegistryEntry {
                    key,
                    symbol: symbol.to_vec(),
                    address: format!("{:p}", fn_ptr)
                }
        ).collect();

        lean_impl::lean_test(
            code_bytes.to_vec(),
            data.mem,
            executable.get_ro_section().to_vec(),
            code_vaddr,
            executable.get_ro_region().vm_addr,
            executable.get_entrypoint_instruction_offset() as u64,
            version_num,
            max_steps,
            executable.get_config().max_call_depth as u64,
            executable.get_config().stack_size() as u64,
            function_registry_vec,
            loader_function_registry_vec
        )
    };

    match lean_result {
        Ok(lean_state) => {
            let rust_result_str = format!("{:?}", interp_res);
            let lean_result_str = lean_state.program_result.to_string();

            if rust_result_str != lean_result_str {
                eprintln!("FUZZER FOUND DIVERGENCE!");
                eprintln!("Rust interpreter result: {}", rust_result_str);
                eprintln!("Lean implementation result: {}", lean_result_str);
                common::eprintln_disassembly(&executable);
                panic!("Rust and Lean implementations diverged!");
            }

            let mut rust_regs = interp_regs.unwrap().clone();
            let mut lean_regs = lean_state.regs.clone();

            rust_regs.remove(10);
            *rust_regs.last_mut().unwrap() *= 8;

            lean_regs.push(lean_state.pc);

            if rust_regs != lean_regs {
                eprintln!("FUZZER FOUND REGISTER MISMATCH!");
                eprintln!("Rust registers: {:?}", rust_regs);
                eprintln!("Lean registers: {:?}", lean_regs);
                common::eprintln_disassembly(&executable);
                panic!("Register values diverged between Rust and Lean!");
            }

            let rust_mem = mem_rust_vm;
            let lean_mem = &lean_state.memory;

            if rust_mem != *lean_mem {
                eprintln!("FUZZER FOUND MEMORY MISMATCH!");
                eprintln!("Rust memory: {:?}", rust_mem);
                eprintln!("Lean memory: {:?}", lean_mem);
                common::eprintln_disassembly(&executable);
                panic!("Memory values diverged between Rust and Lean!");
            }

            drop(black_box((interp_res, lean_state)));
        }
        Err(lean_err) => {
            if interp_res.is_ok() {
                eprintln!("FUZZER FOUND LEAN ERROR!");
                eprintln!("Rust interpreter succeeded: {:?}", interp_res);
                eprintln!("Lean implementation failed: {}", lean_err);
                common::eprintln_disassembly(&executable);
                panic!("Lean failed but Rust succeeded!");
            }

            let rust_err = interp_res.unwrap_err();
            let rust_err_str = format!("{:?}", rust_err);
            let lean_err_str = lean_err.to_string();

            if !lean_err_str.contains(&rust_err_str) && !rust_err_str.contains(&lean_err_str) {
                eprintln!("FUZZER FOUND ERROR MISMATCH!");
                eprintln!("Rust interpreter error: {}", rust_err_str);
                eprintln!("Lean implementation error: {}", lean_err_str);
                common::eprintln_disassembly(&executable);
                panic!("Rust and Lean implementations failed differently!");
            }

            eprintln!("err {lean_err_str} vs {rust_err_str}");

            drop(black_box((rust_err, lean_err)));
        }
    }
});

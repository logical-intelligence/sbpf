use std::mem::size_of;

use arbitrary::{Arbitrary, Unstructured};

use solana_sbpf::{
    vm::Config,
    disassembler,
    ebpf,
    elf::Executable,
};

#[derive(Debug)]
pub struct ConfigTemplate {
    max_call_depth: usize,
    instruction_meter_checkpoint_distance: usize,
    noop_instruction_rate: u32,
    enable_stack_frame_gaps: bool,
    enable_symbol_and_section_labels: bool,
    sanitize_user_provided_values: bool,
    optimize_rodata: bool,
}

impl<'a> Arbitrary<'a> for ConfigTemplate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let bools = u16::arbitrary(u)?;
        Ok(ConfigTemplate {
            max_call_depth: usize::from(u8::arbitrary(u)?) + 1, // larger is unreasonable + must be non-zero
            instruction_meter_checkpoint_distance: usize::from(u16::arbitrary(u)?), // larger is unreasonable
            noop_instruction_rate: u32::from(u16::arbitrary(u)?),
            enable_stack_frame_gaps: bools & (1 << 0) != 0,
            enable_symbol_and_section_labels: bools & (1 << 1) != 0,
            sanitize_user_provided_values: bools & (1 << 3) != 0,
            optimize_rodata: bools & (1 << 9) != 0,
        })
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (
            size_of::<u8>() + size_of::<u16>() + size_of::<f64>() + size_of::<u16>(),
            None,
        )
    }
}

impl From<ConfigTemplate> for Config {
    fn from(template: ConfigTemplate) -> Self {
        match template {
            ConfigTemplate {
                max_call_depth,
                instruction_meter_checkpoint_distance,
                noop_instruction_rate,
                enable_stack_frame_gaps,
                enable_symbol_and_section_labels,
                sanitize_user_provided_values,
                optimize_rodata,
            } => Config {
                max_call_depth,
                enable_stack_frame_gaps,
                instruction_meter_checkpoint_distance,
                enable_symbol_and_section_labels,
                noop_instruction_rate,
                sanitize_user_provided_values,
                optimize_rodata,
                ..Default::default()
            },
        }
    }
}


pub fn eprintln_disassembly<T: solana_sbpf::vm::ContextObject>(executable: &Executable<T>) {
    let (code_vaddr, code_bytes) = executable.get_text_bytes();
    eprintln!("=== DISASSEMBLY ===");
    eprintln!("Code virtual address: 0x{:x}", code_vaddr);
    eprintln!("Code size: {} bytes", code_bytes.len());
    let cfg_nodes = std::collections::BTreeMap::new();
    let mut pc = 0usize;
    while pc < code_bytes.len() {
        if pc + 8 <= code_bytes.len() {
            let insn_bytes = &code_bytes[pc..pc + 8];
            let insn_u64 = u64::from_le_bytes([
                insn_bytes[0], insn_bytes[1], insn_bytes[2], insn_bytes[3],
                insn_bytes[4], insn_bytes[5], insn_bytes[6], insn_bytes[7],
            ]);
            let insn = ebpf::Insn {
                opc: (insn_u64 & 0xff) as u8,
                dst: ((insn_u64 >> 8) & 0xf) as u8,
                src: ((insn_u64 >> 12) & 0xf) as u8,
                off: ((insn_u64 >> 16) & 0xffff) as i16,
                imm: (insn_u64 >> 32) as i64,
                ptr: pc,
            };
            let disassembly = disassembler::disassemble_instruction(
                &insn,
                pc / 8,
                &cfg_nodes,
                executable.get_function_registry(),
                executable.get_loader(),
                executable.get_sbpf_version(),
            );
            eprintln!("0x{:04x}: {}", pc, disassembly);
            pc += 8;
        } else {
            break;
        }
    }
    eprintln!("==================");
}

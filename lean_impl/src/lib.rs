use serde::{ Serialize, Deserialize };

use std::ffi::{ c_void, c_char, CStr, CString };

#[repr(C)]
pub struct lean_object {
    pub m_rc: i32,
    pub m_cs_sz: u16,
    pub m_other: u8,
    pub m_tag: u8,
}

#[repr(C)]
pub struct lean_string_object {
    pub m_header: lean_object,
    pub m_size: usize,
    pub m_capacity: usize,
    pub m_length: usize,
    pub m_data: c_char, // char []
}

const LeanString : i32 = 249;

fn lean_box(n: usize) -> *mut c_void {
    ((n << 1) | 1) as *mut c_void
}

fn lean_io_mk_world() -> *mut c_void {
    lean_box(0)
}

unsafe fn lean_ptr_tag(p: *const c_void) -> u8 {
    unsafe {
        let v = p as *const lean_object;
        (*v).m_tag
    }
}

fn lean_is_scalar(p: *const c_void) -> bool {
    ((p as usize) & 1) == 1
}

unsafe fn lean_is_string(p: *const c_void) -> bool {
    unsafe {
        lean_ptr_tag(p) == LeanString as u8
    }
}

unsafe fn lean_io_result_is_ok(r: *const c_void) -> bool {
    unsafe {
        lean_ptr_tag(r) == 0u8
    }
}

unsafe fn lean_string_cstr(o: *const c_void) -> *const c_char {
    unsafe {
        if !lean_is_string(o) {
            panic!("is not a string")
        }
        let s = o as *const lean_string_object;
        &((*s).m_data)
    }
}

#[link(name = "SbpfEmu")]
#[link(name = "Init_shared")]
#[link(name = "leanshared_1")]
#[link(name = "leanshared")]
unsafe extern "C" {
    fn test_request_response(string: *mut c_void) -> *mut c_void;

    //extern void lean_initialize_runtime_module();
    fn lean_initialize_runtime_module();
    //extern void lean_io_mark_end_initialization();
    fn lean_io_mark_end_initialization();
    //LEAN_EXPORT void lean_io_result_show_error(b_lean_obj_arg r);
    fn lean_io_result_show_error(r: *mut c_void);
    //LEAN_EXPORT void lean_dec_ref_cold(lean_object * o);
    fn lean_dec_ref_cold(o: *mut c_void);
    //LEAN_EXPORT lean_obj_res lean_mk_string(char const * s);
    fn lean_mk_string(s: *const c_char) -> *mut c_void;
    //extern lean_object * initialize_SbpfEmu(uint8_t builtin, lean_object *);
    fn initialize_SbpfEmu(builtin : u8, idk: *mut c_void) -> *mut c_void;
}

unsafe fn lean_dec_ref(p: *mut c_void) {
    unsafe {
        let o = p as *mut lean_object;
        if (*o).m_rc > 1 {
            (*o).m_rc -= 1;
        } else if (*o).m_rc != 0 {
            lean_dec_ref_cold(p);
        }
    }
}

unsafe fn lean_dec(o: *mut c_void) {
    if !lean_is_scalar(o) {
        unsafe {
            lean_dec_ref(o);
        }
    }
}

fn lean_initialize() -> bool {
  unsafe {
    lean_initialize_runtime_module();
    // use same default as for Lean executables
    let builtin : u8 = 1;
    let res = initialize_SbpfEmu(builtin, lean_io_mk_world());
    if lean_io_result_is_ok(res) {
      lean_dec_ref(res);
    } else {
      lean_io_result_show_error(res);
      lean_dec(res);
      return false;  // do not access Lean declarations if initialization failed
    }
    lean_io_mark_end_initialization();
  }
  true
}

use std::sync::Once;

static INIT: Once = Once::new();

pub fn lean_initialize_once() {
    INIT.call_once(|| {
        // Perform one-time global initialization here
        if !lean_initialize() {
            panic!("failed to initialize lean")
        }
    });
}

#[derive(Serialize, Deserialize)]
pub struct FunctionRegistryEntry
{
    pub key: u32,
    pub symbol: Vec<u8>,
    pub address: String,
}

#[derive(Serialize, Deserialize)]
struct Request {
    code: Vec<u8>,
    input: Vec<u8>,
    code_vaddr: String,
    pc: String,
    version: u8,
    remaining_steps: String,
    max_call_depth: String,
    stack_len: String,
    function_registry: Vec<FunctionRegistryEntry>,
    loader_function_registry: Vec<FunctionRegistryEntry>,
}

#[derive(Serialize, Deserialize)]
struct Response {
    status: String,
    regs : Vec<String>,
    pc : String,
    program_result : String,
    halted : bool,
}

pub struct LeanVmState {
    pub input: Vec<u8>,
    pub regs: Vec<u64>,
    pub pc: u64,
    pub halted: bool,
    pub program_result: String,
}

pub unsafe fn lean_test(code: Vec<u8>, input: Vec<u8>, code_vaddr: u64, pc: u64, version: u8, remaining_steps: u64,
                        max_call_depth: u64, stack_len: u64,
                        function_registry: Vec<FunctionRegistryEntry>,  loader_function_registry: Vec<FunctionRegistryEntry>)
                        -> Result<LeanVmState, String> {
    lean_initialize_once();
    let request = Request {
        code: code,
        input: input.clone(),
        code_vaddr: code_vaddr.to_string(),
        pc: pc.to_string(),
        version: version,
        remaining_steps: remaining_steps.to_string(),
        max_call_depth: max_call_depth.to_string(),
        stack_len: stack_len.to_string(),
        function_registry: function_registry,
        loader_function_registry: loader_function_registry,
    };
    match serde_json::to_string(&request) {
        Ok(json_string) => {
            unsafe {
                println!("{}", json_string);
                let request_json = CString::new(json_string).expect("failed to make CString");
                let lean_request_json = lean_mk_string(request_json.as_ptr());
                let lean_response_json = test_request_response(lean_request_json);
                let response_json = CStr::from_ptr(lean_string_cstr(lean_response_json)).to_str().expect("Invalid UTF-8");
                println!("Response.json {}", response_json);
                let response : Response = serde_json::from_str(response_json).expect("failed to json deserialize");
                println!("Response.status = {}", response.status);
                Ok(LeanVmState {
                    input: input,
                    regs: response.regs.iter().map(|s| s.parse::<u64>().unwrap_or_else(|_| 0)).collect(),
                    pc: response.pc.parse::<u64>().unwrap_or_else(|_| 0),
                    halted: response.halted,
                    program_result: response.program_result,
                })
            }
        }
        Err(err) => {
            Err(err.to_string())
        }
    }
}

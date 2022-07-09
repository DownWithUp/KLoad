use std::borrow::Borrow;
use std::ptr;
use std::ffi::CStr;
use std::ffi::CString;

use widestring::WideString;

use clap::Parser;

use winapi::ctypes::*;
use winapi::shared::minwindef::*;
use winapi::shared::ntdef::{NTSTATUS, PUNICODE_STRING, UNICODE_STRING};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::*;
use winapi::um::winreg::*;
use winapi::um::processthreadsapi::{OpenProcessToken, GetCurrentProcess};
use winapi::um::winbase::LookupPrivilegeValueA;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING, GetFinalPathNameByHandleA};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};


// These constant definitions were not in the rust winapi crate
// Found here: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlea
const FILE_NAME_NORMALIZED: u32 = 0x0;
const VOLUME_NAME_NT: u32 = 0x2;

/// A program designed to quickly load and unload kernel drivers via NtLoadDriver API
#[derive(Parser)]
#[clap(about, long_about = None)]
struct Args {
    /// Unload the driver
    #[clap(short, long)]
    unload: bool,
    /// Print extra output while parsing
    #[clap(short, long)]
    verbose: bool,
    /// Path to the driver to be loaded
    #[clap(value_name = "Driver Path")]
    driver_path: String,
}


// Converts the input driver path to an VOLUME_NAME_NT file path. This is done by temporarily opening the file.
fn get_nt_path(driver_path: &CStr, nt_file_path: &mut [CHAR; MAX_PATH]) -> Result<DWORD, DWORD> {
    unsafe {
        let file_handle  = CreateFileA(driver_path.as_ptr() as *const i8, GENERIC_READ, FILE_SHARE_READ, 
            ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut());

        if file_handle == INVALID_HANDLE_VALUE {
            println!("GLE for CreateFile is: {}", GetLastError());
            return Err(GetLastError());
        }

        let return_size = GetFinalPathNameByHandleA(file_handle, nt_file_path.as_ptr() as *mut i8, MAX_PATH as u32, 
        FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
        if return_size == 0 {
            println!("Failed on GetFinalPathNameByHandleA");
            return Err(GetLastError());
        }

        CloseHandle(file_handle);

        return Ok(return_size);
    }
}

// Grants the SeLoadDriverPrivilege to the current process' token
fn get_driver_privilege() -> Option<DWORD>
{
    unsafe {
        let token_handle: HANDLE = 0 as HANDLE;
        
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, 
            &token_handle as *const HANDLE as *mut *mut c_void) == FALSE {
                return Some(GetLastError());
        }

        let priv_name = CString::new("SeLoadDriverPrivilege");
        let mut luid: LUID = std::mem::zeroed();
        if LookupPrivilegeValueA(ptr::null_mut(), priv_name.unwrap().as_ptr(), 
        &luid as *const LUID as *mut LUID) == FALSE {
            return Some(GetLastError());
        }

        let mut token_privs: TOKEN_PRIVILEGES = std::mem::zeroed();
        token_privs.PrivilegeCount = 1;
        token_privs.Privileges[0].Luid = luid;
        token_privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        if AdjustTokenPrivileges(token_handle, FALSE, &token_privs as *const TOKEN_PRIVILEGES as *mut TOKEN_PRIVILEGES, 
            std::mem::size_of_val(&token_privs) as u32, ptr::null_mut(), ptr::null_mut()) == FALSE {
                    return Some(GetLastError());
        }
    }
    None
}

// Creates the needed registry keys to load the driver via NtLoadDriver
fn create_keys(driver_name: &CStr, nt_driver_path: &[CHAR; MAX_PATH], path_length: DWORD) -> Option<DWORD> {

    unsafe {
        let mut key_handle: HKEY = std::mem::zeroed();
        let subkey = format!("SYSTEM\\CurrentControlSet\\Services\\{}", driver_name.to_str().unwrap());

        // Create a key in the under the current machine control set services
        if RegCreateKeyA(HKEY_LOCAL_MACHINE, subkey.as_str().as_ptr() as *const i8, 
        &key_handle as *const HKEY as*mut HKEY) != 0 {
                return Some(GetLastError());
        }

        // Create an image path string value 
        let image_path = CString::new("ImagePath");
        if RegSetValueExA(key_handle, image_path.unwrap().as_ptr(), 0, REG_SZ, 
            nt_driver_path.as_ptr() as *const u8, path_length) != 0 {
                return Some(GetLastError());
        }

        // Create a new type DWORD value
        let type_name = CString::new("Type");
        let type_data: DWORD = 1;
        if RegSetValueExA(key_handle, type_name.unwrap().as_ptr(), 0, REG_DWORD, 
            &type_data as *const DWORD as *mut u8, std::mem::size_of_val(&type_data) as u32) != 0 {
                return Some(GetLastError());
        }
    }
    None
}

// Actually loads the driver by dynamically resolving NtLoadDriver. Returns an NTSTATUS
fn load_driver(driver_name: &CStr) -> NTSTATUS {

    type FnNtLoadDriver = extern "stdcall" fn(PUNICODE_STRING) -> NTSTATUS;
    unsafe {
        // NtLoadDriver must be dynamically imported
        let ntdll_base = GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr());
        let ntloaddriver_address = GetProcAddress(ntdll_base, CString::new("NtLoadDriver").unwrap().as_ptr());
        let ntloaddriver_func = std::mem::transmute::<*const usize, FnNtLoadDriver>(ntloaddriver_address as *const usize);

        let final_reg_path  = format!("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{}", &driver_name.to_str().unwrap());
        let wstr = WideString::from_str(&final_reg_path);
        
        // Build a UNICODE_STRING struct
        let mut driver_reg_path: UNICODE_STRING = std::mem::zeroed();
        driver_reg_path.Buffer = wstr.as_vec().as_ptr() as *mut u16;
        driver_reg_path.Length = (wstr.len() * 2) as u16;
        driver_reg_path.MaximumLength = driver_reg_path.Length + 2;

        let nt_ret = ntloaddriver_func(&driver_reg_path as *const UNICODE_STRING as *mut UNICODE_STRING);
        return nt_ret;
    }
}

// Unloads the driver by dynamically resolving NtUnloadDriver. Returns an NTSTATUS
fn unload_driver(driver_name: &CStr) -> NTSTATUS {
    type FnNtUnloadDriver = extern "stdcall" fn(PUNICODE_STRING) -> NTSTATUS;
    unsafe {
        // NtLoadDriver must be dynamically imported
        let ntdll_base = GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr());
        let ntunloaddriver_address = GetProcAddress(ntdll_base, CString::new("NtUnloadDriver").unwrap().as_ptr());
        let ntunloaddriver_func = std::mem::transmute::<*const usize, FnNtUnloadDriver>(ntunloaddriver_address as *const usize);

        let final_reg_path  = format!("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{}", &driver_name.to_str().unwrap());
        let wstr = WideString::from_str(&final_reg_path);
        
        // Build a UNICODE_STRING struct
        let mut driver_reg_path: UNICODE_STRING = std::mem::zeroed();
        driver_reg_path.Buffer = wstr.as_vec().as_ptr() as *mut u16;
        driver_reg_path.Length = (wstr.len() * 2) as u16;
        driver_reg_path.MaximumLength = driver_reg_path.Length + 2;

        let nt_ret = ntunloaddriver_func(&driver_reg_path as *const UNICODE_STRING as *mut UNICODE_STRING);
        return nt_ret;
    }
}

fn main() {

    let args = Args::parse();

    if let Some(last_error_code) = get_driver_privilege() {
        println!("Failed to set privilegs (SeLoadDriverPrivilege). Make sure you're running as administrator. GetLastError returned: {}", last_error_code);
        return;
    }

    // Get the final name in the path
    let driver_name: Vec<&str> = args.driver_path.split("\\").collect();
    let driver_name = driver_name.last().unwrap();

    if args.unload {
        let mut nt_driver_path: [CHAR; MAX_PATH] = [0; MAX_PATH];
        match get_nt_path(CString::new(args.driver_path.as_str()).unwrap().as_c_str(), &mut nt_driver_path) {
            Err(last_error_code) => {
                println!("Failed to get the path of the driver. GetLastError returned: {}", last_error_code);
                return;
            }
            Ok(buffer_length) => {
                if let Some(last_error_code) =  create_keys(&CString::new(*driver_name).unwrap(), &nt_driver_path, buffer_length) {
                    println!("Failed to create required registry keys. GetLastError returned: {}", last_error_code);
                    return;
                }

                let nt_ret = unload_driver(CString::new(*driver_name).unwrap().as_c_str());
                println!("NtUnloadDriver returned: 0x{:x}", nt_ret);
            }
        }
    } else {
        let mut nt_driver_path: [CHAR; MAX_PATH] = [0; MAX_PATH];
        match get_nt_path(CString::new(args.driver_path.as_str()).unwrap().as_c_str(), &mut nt_driver_path) {
            Err(last_error_code) => {
                println!("Failed to get the path of the driver. GetLastError returned: {}", last_error_code);
                return;
            }
            Ok(buffer_length) => {
                if let Some(last_error_code) =  create_keys(&CString::new(*driver_name).unwrap(), &nt_driver_path, buffer_length) {
                    println!("Failed to create required registry keys. GetLastError returned: {}", last_error_code);
                    return;
                }

                let nt_ret = load_driver(CString::new(*driver_name).unwrap().as_c_str());
                println!("NtLoadDriver returned: 0x{:x}", nt_ret);
            }
        }
    }
}

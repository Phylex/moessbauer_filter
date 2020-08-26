use std::{
    fs::OpenOptions,
    convert::{
        TryInto,
        TryFrom,
    },
    ptr::{
        null_mut,
        read_volatile,
        write_volatile,
    },
    mem::size_of,
    ffi::CString,
    str,
};
use libc::{
    open,
    mmap,
    munmap,
    c_void,
    c_int,
    size_t,
    off_t,
    PROT_READ,
    PROT_WRITE,
    MAP_SHARED,
    O_RDWR,
    O_SYNC,
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

#[derive(Debug)]
pub enum MBFError {
    InvalidState,
    NoParameters,
    FilterHalted,
    FIFOFull,
    InvalidParameterRange,
    MmapCallFailed,
}

pub enum MBFState {
    InvalidParameters,
    FIFOFull,
    Ready,
    Running{frame_count: u32},
    Halted{frame_count: u32},
}

impl TryFrom<u32> for MBFState {
    type Error = MBFError;
    fn try_from(raw_state: u32) -> Result<MBFState, MBFError> {
        const FRAME_COUNT_MASK: u32 = 0xfff;
        let frame_count = raw_state & FRAME_COUNT_MASK;
        let state = raw_state >> 12;
        match state {
            1 => Ok(MBFState::InvalidParameters),
            2 => Ok(MBFState::FIFOFull),
            3 => Ok(MBFState::Ready),
            4 => Ok(MBFState::Running{frame_count}),
            5 => Ok(MBFState::Halted{frame_count}),
            _ => Err(MBFError::InvalidState),
        }
    }
}

pub struct MBConfig {
    k: u32,
    l: u32,
    m: u32,
    pub pthresh: u32,
    pub t_dead: u32
}

impl MBConfig {
    pub fn new(k: u32, l: u32, m: u32, pthresh: u32, t_dead: u32) -> Result<MBConfig, MBFError> {
        const M_WIDTH: u32 = 11;
        const L_WIDTH: u32 = 7;
        const K_WIDTH: u32 = 7;
        if k > (2u32.pow(K_WIDTH)) {
            return Err(MBFError::InvalidParameterRange)
        } else if l > 2u32.pow(L_WIDTH) {
            return Err(MBFError::InvalidParameterRange)
        } else if m > 2u32.pow(M_WIDTH) {
            return Err(MBFError::InvalidParameterRange)
        } else {
            return Ok(MBConfig { k, l, m, pthresh, t_dead })
        }
    }

    pub fn get_trapezoidal_filter_config(&self) -> u32 {
        const M_MASK: u32 = 0x7ff;
        const M_WIDTH: usize = 11;
        const L_MASK: u32 = 0x7f;
        const L_WIDTH: usize = 7;
        const K_MASK: u32 = 0x7f;
        ((self.k & K_MASK) << (L_WIDTH + M_WIDTH)) |  ((self.l & L_MASK) << M_WIDTH) | (self.m & M_MASK)
    }
}

pub struct MBFilter {
    filter_registers: *mut u32,
}

impl MBFilter {
    pub fn new () -> Result<MBFilter, MBFError> {
        const MBFILTER_BASE_ADDR: off_t = 0x42000000;
        const MBFILTER_MAP_SIZE: size_t = 4096;
        unsafe {
            let path = CString::new(b"/dev/mem" as &[u8]).unwrap();
            let file = open(path.as_ptr(), O_RDWR | O_SYNC);
            if file == 0 {
                Err(MBFError::MmapCallFailed)
            } else {
                let addr: *mut c_void = null_mut();
                let map = mmap(addr, MBFILTER_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, file, MBFILTER_BASE_ADDR) as *mut u32;
                Ok(MBFilter { filter_registers: map })
            }
        }
    }

    pub fn state(&self) -> MBFState {
        unsafe {
            const STATUS_ADDR: isize = 0x0c;
            let raw_state = read_volatile(self.filter_registers.offset(STATUS_ADDR/4));
            raw_state.try_into().unwrap()
        }
    }

    pub fn configure(&self, config: MBConfig) {
        unsafe {
            const CONFIG_BASE_ADDR: isize = 0x10;
            write_volatile(self.filter_registers.offset(CONFIG_BASE_ADDR/4), config.t_dead);
            write_volatile(self.filter_registers.offset((CONFIG_BASE_ADDR+4)/4), config.pthresh);
            write_volatile(self.filter_registers.offset((CONFIG_BASE_ADDR+8)/4), config.get_trapezoidal_filter_config());
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, MBFError> {
        Err(MBFError::FilterHalted)
    }
}

impl Drop for MBFilter {
    fn drop(&mut self) {
    }
}

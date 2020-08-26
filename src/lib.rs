use memmap::{
    MmapOptions,
    MmapMut,
};
use std::{
    fs::OpenOptions,
    convert::{
        TryInto,
        TryFrom,
    },
    ptr::{
        read_volatile,
        write_volatile,
    },
    mem::size_of,
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
    filter_registers: MmapMut,
}

impl MBFilter {
    pub fn new () -> Result<MBFilter, std::io::Error> {
        const MBFILTER_BASE_ADDR: u64 = 0x42000000;
        let file = OpenOptions::new().read(true).write(true).open("/dev/mem")?;
        let mmap = unsafe {
            MmapOptions::new()
                .offset(MBFILTER_BASE_ADDR)
                .len(4096)
                .map_mut(&file)?
        };
        Ok(MBFilter { filter_registers : mmap })
    }

    pub fn state(&self) -> MBFState {
        const STATUS_ADDR: usize = 0x0c;
        let raw_state = u32::from_ne_bytes(self.filter_registers[STATUS_ADDR..STATUS_ADDR+4].try_into().unwrap());
        raw_state.try_into().expect("The Filter hardware seems to be broken => PANIC" )
    }

    pub fn configure(&mut self, config: MBConfig) {
        const CONFIG_BASE_ADDR: usize = 0x10;
        let pthresh_reg: &mut [u8;4] = self.filter_registers[CONFIG_BASE_ADDR..CONFIG_BASE_ADDR+4].try_into().unwrap();
        *pthresh_reg = config.pthresh.to_ne_bytes();
        let mut t_dead_reg: [u8;4] = self.filter_registers[CONFIG_BASE_ADDR+4..2*size_of::<u32>()].try_into().unwrap();
        t_dead_reg = config.t_dead.to_ne_bytes();
    }
}

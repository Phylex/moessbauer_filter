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
    FIFOFull
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

pub struct MBFilter {
    pub filter_registers: MmapMut,
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
}

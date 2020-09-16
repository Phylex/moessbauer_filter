use std::{
    convert::{
        TryInto,
        TryFrom,
    },
    ptr::{
        null_mut,
        read_volatile,
        write_volatile,
    },
    ffi::CString,
};
use libc::{
    open,
    mmap,
    munmap,
    c_void,
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

/// Enum encoding the states of the filter hardware
///
/// Representation of the States of the Filter. The appropriate states also
/// encompas the current amount of frames in the buffer in the enum.
pub enum MBFState {
    /// The filter currently does not have a valid set of configuration
    /// parameters. They fist have to be supplied. This automatically happens
    /// when the MBFilter::new() function is called.
    InvalidParameters,
    /// When the filter is halted using the MBFilter::stop() call and there are
    /// events remaining in the FIFO the Filter enters this state. To exit this
    /// state and to trnsition to ready the remaining frames in the fifo need to
    /// be read out. The state transition happens automatically after the last
    /// frame has been read from the filter.
    FIFOFull{frame_count: u32},
    /// The Filter has a valid configuration and there are no frames are currently
    /// in the FIFO. This is the only state that can accept a new configuration
    /// for the filter parameters. The configure call will return an error if the
    /// Filter is not in this state.
    Ready,
    /// The Filter is currently running and writing detected Frames into the FIFO.
    /// The FIFO can be read during normal operation. This needs to happen as the
    /// FIFO otherwise will be filled in a matter of Milliseconds under normal
    /// operating conditions.
    Running{frame_count: u32},
    /// If the FIFO is filled to capacity and the filter tries to place another event
    /// in the FIFO the filter is halted, as to stop the currently detected Data from
    /// being overwritten. When a filter is halted the Reset Flag must be set so that
    /// the Filter can transition to the
    Halted,
}

impl TryFrom<u32> for MBFState {
    type Error = MBFError;
    fn try_from(raw_state: u32) -> Result<MBFState, MBFError> {
        const FRAME_COUNT_MASK: u32 = 0xfff;
        const FRAME_COUNT_WIDTH: u32 = 12;
        let frame_count = raw_state & FRAME_COUNT_MASK;
        let state = raw_state >> FRAME_COUNT_WIDTH;
        match state {
            1 => Ok(MBFState::InvalidParameters),
            2 => Ok(MBFState::FIFOFull{frame_count}),
            3 => Ok(MBFState::Ready),
            4 => Ok(MBFState::Running{frame_count}),
            5 => Ok(MBFState::Halted),
            _ => {
                println!("current state: {}", state);
                Err(MBFError::InvalidState)
            },
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

    pub fn new_from_str(k: &str, l: &str, m: &str, pthresh:&str, t_dead: &str) -> Result<MBConfig, MBFError> {
        let rval = u32::from_str_radix(k, 10);
        let k: u32;
        match rval {
            Ok(val) => k = val,
            Err(_) => {
                println!("Please enter a whole number value for k");
                return Err(MBFError::NoParameters);
            }
        };
        let rval = u32::from_str_radix(l,10);
        let l: u32;
        match rval {
            Ok(val) => l = val,
            Err(_) => {
                println!("Please enter a whole number value for l");
                return Err(MBFError::NoParameters);
            }
        };
        let rval = u32::from_str_radix(m, 10);
        let m: u32;
        match rval {
            Ok(val) => m = val,
            Err(_) => {
                println!("Please enter a whole number value for l");
                return Err(MBFError::NoParameters);
            }
        };
        let rval = u32::from_str_radix(pthresh, 10);
        let pthresh: u32;
        match rval {
            Ok(val) => pthresh = val,
            Err(_) => {
                println!("Please enter a whole number for the peak threshhold");
                return Err(MBFError::NoParameters);
            }
        };
        let rval = u32::from_str_radix(t_dead, 10);
        let tdead: u32;
        match rval {
            Ok(val) => tdead = val,
            Err(_) => {
                println!("Please enter a whole number for the dead time");
                return Err(MBFError::NoParameters);
            }
        };
        Ok(MBConfig::new(k, l, m, pthresh, tdead)?)
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
        let filter: MBFilter;
        unsafe {
            let path = CString::new(b"/dev/mem" as &[u8]).unwrap();
            let file = open(path.as_ptr(), O_RDWR | O_SYNC);
            if file == 0 {
                return Err(MBFError::MmapCallFailed);
            } else {
                let addr: *mut c_void = null_mut();
                let map = mmap(addr, MBFILTER_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, file, MBFILTER_BASE_ADDR) as *mut u32;
                if map == null_mut() {
                    return Err(MBFError::MmapCallFailed);
                }
                filter = MBFilter { filter_registers: map };
            }
        }
        Ok(filter)
    }

    pub fn state(&self) -> MBFState {
        unsafe {
            const STATUS_ADDR: isize = 0x0c/4;
            let raw_state = read_volatile(self.filter_registers.offset(STATUS_ADDR));
            println!("raw state: {}", raw_state);
            raw_state.try_into().unwrap()
        }
    }

    pub fn configure(&self, config: MBConfig) {
        unsafe {
            const CONFIG_BASE_ADDR: isize = 0x10/4;
            write_volatile(self.filter_registers.offset(CONFIG_BASE_ADDR), config.t_dead);
            write_volatile(self.filter_registers.offset(CONFIG_BASE_ADDR+1), config.pthresh);
            write_volatile(self.filter_registers.offset(CONFIG_BASE_ADDR+2), config.get_trapezoidal_filter_config());
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, MBFError> {
        const FRAME_LEN: usize = 12;
        match self.state() {
            MBFState::InvalidParameters => Err(MBFError::NoParameters),
            MBFState::FIFOFull{frame_count} => {
                let read_frames = self.read_available_frames_to_buf(buf, frame_count as usize);
                Ok(read_frames * FRAME_LEN)
            },
            MBFState::Ready => Ok(0),
            MBFState::Running{frame_count} => {
                let read_frames = self.read_available_frames_to_buf(buf, frame_count as usize);
                Ok(read_frames * FRAME_LEN)
            },
            MBFState::Halted => {
                Err(MBFError::FilterHalted)
            }
        }
    }

    fn read_available_frames_to_buf(&mut self, buf: &mut[u8], n: usize) -> usize{
        const FRAME_LEN: usize = 12;
        let frames_to_read: usize;
        if buf.len()/12 > n as usize {
            frames_to_read = n;
        } else {
            frames_to_read = buf.len()/FRAME_LEN;
        }
        for i in 0..frames_to_read {
            for j in 0..3 {
                let r = unsafe { read_volatile(self.filter_registers.offset(j)).to_ne_bytes()};
                for k in 0..4 {
                    buf[i * FRAME_LEN + j as usize * 4 + k as usize] = r[k as usize];
                }
            }
        }
        frames_to_read
    }

    pub fn stop(&mut self) {
        const START_STOP_REGISTER_OFFSET: isize = 0x1c/4;
        unsafe { write_volatile(self.filter_registers.offset(START_STOP_REGISTER_OFFSET), 1 as u32)};
    }

    pub fn start(&mut self) {
        const START_STOP_REGISTER_OFFSET: isize = 0x1c/4;
        unsafe { write_volatile(self.filter_registers.offset(START_STOP_REGISTER_OFFSET), 1 as u32)};
    }
}

impl Drop for MBFilter {
    fn drop(&mut self) {
        const FRAME_LEN: usize = 12;
        let mut buf: [u8; 2048*FRAME_LEN] = [0; 2048*FRAME_LEN];
        self.stop();
        let _frames_read = self.read(&mut buf);
        unsafe {
            if munmap(self.filter_registers as *mut c_void, 4096) != 0 {
                panic!("Munmap failed");
            }
        }
    }
}

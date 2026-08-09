#![no_std]

/*
        Cross check the implementation reference of the gdt in x86::protected::Descriptor to make sure they correspond
        If not, change the naming convention to not the mode, but the code target...

        GDT Structure

    The GDT at ES:SI must contain 6 descriptors (8 bytes each, total 48 bytes). The BIOS uses these descriptors to define the source and destination memory regions.
    Descriptor	Offset	Purpose
    0	+0	Dummy descriptor (must be 0)
    1	+8	Source region descriptor
    2	+16	Target region descriptor
    3	+24	BIOS code segment descriptor (CS)
    4	+32	BIOS stack segment descriptor (SS)
    5	+40	Reserved (must be 0)

    Descriptor Format (8 bytes):
    Byte	Field	Description
    0–1	Segment Limit	16 bits (max 0xFFFF)
    2–3	Base Address Low	16 bits (bits 0–15)
    4	Base Address Mid	8 bits (bits 16–23)
    5	Access Rights	8 bits (0x93 = data, 0x9B = code)
    6	Granularity	8 bits (0x00 = 16‑bit, 0x80 = 4KB pages)
    7	Base Address High	8 bits (bits 24–31)
*/

/*
GDT Format

    The GDT at ES:SI must contain 8 descriptors (8 bytes each, total 64 bytes). The BIOS uses these descriptors to set up the protected mode environment.
    Descriptor	Offset	Purpose
    0	+0	Dummy (must be zero)
    1	+8	GDT descriptor (points to the GDT itself)
    2	+16	IDT descriptor (points to the IDT)
    3	+24	User's data segment descriptor (DS)
    4	+32	User's extra segment descriptor (ES)
    5	+40	User's stack segment descriptor (SS)
    6	+48	User's code segment descriptor (CS)
    7	+56	BIOS temporary code segment descriptor (used internally)

    The BIOS will load the GDT and IDT from these descriptors, then jump to the user's code segment (descriptor 6) at offset 0.
*/

use x86::word::*;

#[inline(always)]
pub unsafe fn bios_call(vector: u8, registers: &mut registers::Registers) {
    unsafe {
        core::arch::asm!(
            ".code16",
            "mov ax, {0:x}",
            "mov bx, {1:x}",
            "mov cx, {2:x}",
            "mov dx, {3:x}",
            "mov bp, {4:x}",
            "mov si, {5:x}",
            "mov di, {6:x}",
            "mov es, {7:x}",
            "int {8}",
            "mov {0:x}, ax",
            "mov {1:x}, bx",
            "mov {2:x}, cx",
            "mov {3:x}, dx",
            "mov {4:x}, bp",
            "mov {5:x}, si",
            "mov {6:x}, di",
            "mov {7:x}, es",
            "pushf",
            "pop {9:x}",
            inout(reg) registers.ax => registers.ax,
            inout(reg) registers.bx => registers.bx,
            inout(reg) registers.cx => registers.cx,
            inout(reg) registers.dx => registers.dx,
            inout(reg) registers.bp => registers.bp,
            inout(reg) registers.si => registers.si,
            inout(reg) registers.di => registers.di,
            inout(reg) registers.es => registers.es,
            in(reg_byte) vector,
            out(reg) registers.flags,
            options(nostack)
        );
    }
}

#[macro_export]
macro_rules! bios_call {
	($int:expr, $($reg:ident = $val:expr),* $(,)?) => {{
		let mut regs = $crate::registers::Registers::default();
		$(
			regs.$reg = $val;
		)*
		unsafe { $crate::bios_call($int, &mut regs); }
		regs
	}};
}

#[derive(Copy, Clone, Debug)]
pub struct MasterBootRecord {
    pub bootstrap: [u8; 446],
    pub partitions: [PartitionTableEntry; 4],
    pub signature: u16,
}

impl MasterBootRecord {
    pub const PACKED_SIZE: usize = 512;

    pub const SIGNATURE: u16 = 0xAA55;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < Self::PACKED_SIZE {
            return Err("error : missing data, expected at least 512 bytes");
        }

        Ok(Self {
            bootstrap: bytes[0..446].try_into().unwrap(),
            partitions: [
                PartitionTableEntry::from_bytes(&bytes[446..462])?,
                PartitionTableEntry::from_bytes(&bytes[462..478])?,
                PartitionTableEntry::from_bytes(&bytes[478..494])?,
                PartitionTableEntry::from_bytes(&bytes[494..510])?,
            ],
            signature: u16::from_le_bytes(bytes[510..512].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Result<[u8; 512], &'static str> {
        let mut bytes = [0u8; 512];

        bytes[0..446].copy_from_slice(&self.bootstrap);
        for i in 0..4 {
            bytes[446 + PartitionTableEntry::PACKED_SIZE * i
                ..446 + PartitionTableEntry::PACKED_SIZE * (i + 1)]
                .copy_from_slice(&self.partitions[i].to_bytes()?);
        }
        bytes[510..512].copy_from_slice(&self.signature.to_le_bytes());

        Ok(bytes)
    }
}

impl Default for MasterBootRecord {
    fn default() -> Self {
        Self {
            bootstrap: [0u8; 446],
            partitions: [PartitionTableEntry::default(); 4],
            signature: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct PartitionTableEntry {
    pub boot_indicator: u8,
    pub chs_start: [u8; 3],
    pub r#type: u8,
    pub chs_end: [u8; 3],
    pub lba_start: u32,
    pub sector_count: u32,
}

impl PartitionTableEntry {
    pub const PACKED_SIZE: usize = 16;

    pub const BOOT_INDICATOR_INACTIVE: u8 = 0x00;
    pub const BOOT_INDICATOR_ACTIVE: u8 = 0x80;

    pub const TYPE_EMPTY: u8 = 0x00;
    pub const TYPE_FAT12: u8 = 0x01;
    pub const TYPE_FAT16_SMALL: u8 = 0x04;
    pub const TYPE_FAT16: u8 = 0x06;
    pub const TYPE_NTFS: u8 = 0x07;
    pub const TYPE_FAT32_CHS: u8 = 0x0B;
    pub const TYPE_FAT32_LBA: u8 = 0x0C;
    pub const TYPE_FAT16_LBA: u8 = 0x0E;
    pub const TYPE_LINUX_SWAP: u8 = 0x82;
    pub const TYPE_LINUX_EXT: u8 = 0x83;
    pub const TYPE_LINUX_LVM: u8 = 0x8E;
    pub const TYPE_PROTECTIVE_GPT: u8 = 0xEE;
    pub const TYPE_EFI_SYSTEM: u8 = 0xEF;
    pub const TYPE_LINUX_RAID: u8 = 0xFD;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < Self::PACKED_SIZE {
            return Err("error : missing data, expected at least 16 bytes");
        }

        Ok(Self {
            boot_indicator: bytes[0],
            chs_start: bytes[1..4].try_into().unwrap(),
            r#type: bytes[4],
            chs_end: bytes[5..8].try_into().unwrap(),
            lba_start: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            sector_count: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Result<[u8; 16], &'static str> {
        let mut bytes = [0u8; 16];
        bytes[0] = self.boot_indicator;
        bytes[1..4].copy_from_slice(&self.chs_start);
        bytes[4] = self.r#type;
        bytes[5..8].copy_from_slice(&self.chs_end);
        bytes[8..12].copy_from_slice(&self.lba_start.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.sector_count.to_le_bytes());

        Ok(bytes)
    }
}

impl Default for PartitionTableEntry {
    fn default() -> Self {
        Self {
            boot_indicator: 0,
            chs_start: [0, 0, 0],
            r#type: 0,
            chs_end: [0, 0, 0],
            lba_start: 0,
            sector_count: 0,
        }
    }
}

pub const VIDEO_TEXT: FarPtr = FarPtr {
    segment: 0xB800,
    offset: 0,
};
pub const VIDEO_MONO: FarPtr = FarPtr {
    segment: 0xB000,
    offset: 0,
};
pub const VIDEO_GRAPHICS: FarPtr = FarPtr {
    segment: 0xA000,
    offset: 0,
};
pub const BDA: FarPtr = FarPtr {
    segment: 0x40,
    offset: 0,
};
pub const IVT: FarPtr = FarPtr {
    segment: 0,
    offset: 0,
};
pub const BIOS_ROM: FarPtr = FarPtr {
    segment: 0xF000,
    offset: 0,
};
pub const BOOT_SECTOR: FarPtr = FarPtr {
    segment: 0,
    offset: 0x7c00,
};

#[repr(C, packed)]
pub struct BiosDataArea {
    // RS-232 & Printer Port Addresses
    pub com1_addr: u16,
    pub com2_addr: u16,
    pub com3_addr: u16,
    pub com4_addr: u16,
    pub lpt1_addr: u16,
    pub lpt2_addr: u16,
    pub lpt3_addr: u16,
    pub lpt4_addr: u16,

    // Equipment List
    pub equipment: u16,
    pub reserved1: u16,

    // Memory Size (kB)
    pub memory_size: u16,
    pub reserved2: u16,

    // Keyboard Buffers
    pub keyboard_buffer: [u16; 16],
    pub kb_head: u16,
    pub kb_tail: u16,
    pub kb_buffer_start: u16,
    pub kb_buffer_end: u16,

    // Video State
    pub video_mode: u8,
    pub screen_cols: u16,
    pub video_page: u8,
    pub crtc_ports: u16,

    // Other Video Data
    pub cursor_positions: [u16; 8],
    pub cursor_shape: u16,
    pub current_page: u8,
    pub crtc_adjust: u8,
    pub crt_start: u16,
    pub crt_len: u16,

    pub reserved3: [u8; 0x0A],

    // Soft Reset Flag
    pub reset_flag: u16, // 1234h = warm boot

    // Hard Disk Status
    pub fixed_disk_status: u8,
    pub fixed_disk_drive_count: u8,
    pub fixed_disk_control: u8,
    pub fixed_disk_pdi: u8,

    // Timer Data
    pub timer_low: u16,
    pub timer_high: u16,
    pub timer_rolled: u8,
    pub timer_rollover: u8,

    // Diskette Motor Data
    pub diskette_motor_status: u8,
    pub diskette_motor_count: u8,

    // Fixed Disk Data
    pub fixed_disk_errors: u8,
    pub fixed_disk_interrupt: u8,
    pub fixed_disk_control_byte: u8,
    pub reserved4: [u8; 5],
    pub fixed_disk_status_2: u8,
    pub reserved5: [u8; 0x77],
}

pub const INT_PRSCRN: u8 = 0x05;

/// Print Screen (see: p. 5-162)
#[inline(always)]
pub fn print_screen() {
    bios_call!(self::INT_PRSCRN,);
}

pub mod video {

    /// VIDEO I/O, see p. 5-127
    pub const INT_VIDEO: u8 = 0x10;

    /// default
    pub const MODE_TEXT_40X25_BW: u8 = 0;
    pub const MODE_TEXT_40X25_COLOR: u8 = 1;
    pub const MODE_TEXT_80X25_BW: u8 = 2;
    pub const MODE_TEXT_80X25_COLOR: u8 = 3;

    pub const MODE_GRAPHICS_320X200_COLOR: u8 = 4;
    pub const MODE_GRAPHICS_320X200_BW: u8 = 5;
    pub const MODE_GRAPHICS_640X200_BW: u8 = 6;
    pub const MODE_CRT_80X25_BWCARD: u8 = 7;

    /// Set Mode
    #[inline(always)]
    pub fn set_mode(mode: u8) {
        bios_call!(self::INT_VIDEO, ax = mode as u16);
    }

    /// Set Cursor Type
    #[inline(always)]
    pub fn set_cursor_shape(start: u8, end: u8, visible: bool) {
        // Not sure thats the good design tbh
        let mut ch = start & 0x1F;
        if !visible {
            ch |= 0x20;
        }
        let cl = end & 0x1F;

        bios_call!(
            self::INT_VIDEO,
            ax = 0x100,
            cx = ((ch as u16) << 8) | cl as u16
        );
    }

    /// Set Cursor Position
    #[inline(always)]
    pub fn set_cursor(page: u8, row: u8, col: u8) -> () {
        bios_call!(
            self::INT_VIDEO,
            ax = 0x200,
            dx = ((row as u16) << 8) | col as u16,
            bx = page as u16
        );
    }

    /// Read Cursor Position
    #[inline(always)]
    pub fn get_cursor(page: u8) -> (u8, u8, u8, u8) {
        let regs = bios_call!(self::INT_VIDEO, ax = 0x300, bx = page as u16,);

        let row = (regs.dx >> 8) as u8;
        let col = (regs.dx & 0xFF) as u8;
        let start = (regs.cx >> 8) as u8;
        let end = (regs.cx & 0xFF) as u8;

        (row, col, start, end)
    }

    /// Read Light Pen Position
    #[inline(always)]
    pub fn read_light_pen() -> (bool, u8, u8, u8, u16) {
        // Yeah, no : we do not return a LightPen struct
        let regs = bios_call!(self::INT_VIDEO, ax = 0x400);

        let (triggered, row, col, y, x) = (
            (regs.ax >> 8) as u8 != 0,
            (regs.dx >> 8) as u8,
            (regs.dx & 0xFF) as u8,
            (regs.cx >> 8) as u8,
            regs.bx,
        );

        (triggered, row, col, y, x)
    }

    /// Select Active Display Page
    #[inline(always)]
    pub fn set_page(page: u8) {
        bios_call!(self::INT_VIDEO, ax = 0x500 | page as u16);
    }

    /// Scroll Active Page Up
    #[inline(always)]
    pub fn scroll_up(lines: u8, fill: u8, trow: u8, lcol: u8, brow: u8, rcol: u8) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0x600 | lines as u16,
            bx = ((fill as u16) << 8) | trow as u16,
            cx = ((trow as u16) << 8) | lcol as u16,
            dx = ((brow as u16) << 8) | rcol as u16
        );
    }

    /// Scroll Active Page Down
    #[inline(always)]
    pub fn scroll_down(lines: u8, fill: u8, trow: u8, lcol: u8, brow: u8, rcol: u8) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0x700 | lines as u16,
            bx = ((fill as u16) << 8) | trow as u16,
            cx = ((trow as u16) << 8) | lcol as u16,
            dx = ((brow as u16) << 8) | rcol as u16
        );
    }

    /// Read Attribute Character At Current Cursor Position
    #[inline(always)]
    pub fn read_char_attr(page: u8) -> (u8, u8) {
        let regs = bios_call!(self::INT_VIDEO, ax = 0x800, bx = page as u16);

        let attribute = (regs.ax >> 8) as u8;
        let character = regs.ax as u8;

        (attribute, character)
    }

    /// Write Attribute Character At Current Cursor Position
    #[inline(always)]
    pub fn write_char_attr(page: u8, character: u8, atcol: u8, count: u16) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0x900 | (character as u16),
            bx = ((page as u16) << 8) | (atcol as u16),
            cx = count
        );
    }

    /// Write Character Only At Current Cursor Position
    #[inline(always)]
    pub fn write_char(page: u8, character: u8, count: u16) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0xA00 | (character as u16),
            bx = page as u16,
            cx = count
        );
    }

    /// Set Color Palette
    #[inline(always)]
    pub fn set_palette(subfunction: u8, value: u8) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0xB00,
            bx = ((subfunction as u16) << 8) | value as u16
        );
    }

    /// Write Dot
    #[inline(always)]
    pub fn set_pixel(page: u8, x: u16, y: u16, color: u8) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0xC00 | (color as u16),
            bx = page as u16,
            cx = x,
            dx = y,
        );
    }

    /// Read Dot
    #[inline(always)]
    pub fn get_pixel(page: u8, x: u16, y: u16) -> u8 {
        let regs = bios_call!(
            self::INT_VIDEO,
            ax = 0xD00,
            bx = page as u16,
            cx = x,
            dx = y,
        );

        let color = (regs.ax & 0xFF) as u8;

        color
    }

    /// Write Teletype To Active Page
    #[inline(always)]
    pub fn print_char(character: u8, page: u8, color: u8) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0xE00 | (character as u16),
            bx = ((page as u16) << 8) | color as u16
        );
    }

    /// Current Video State
    #[inline(always)]
    pub fn get_video_state() -> (u8, u8, u8) {
        let regs = bios_call!(self::INT_VIDEO, ax = 0xF00,);

        let mode = (regs.ax & 0xFF) as u8;
        let columns = (regs.ax >> 8) as u8;
        let active_page = (regs.bx >> 8) as u8;

        (mode, columns, active_page)
    }

    /// Write String
    #[inline(always)]
    pub fn write_string(
        mode: u8,
        page: u8,
        attr: u8,
        row: u8,
        col: u8,
        buffer: crate::FarPtr,
        len: u16,
    ) {
        bios_call!(
            self::INT_VIDEO,
            ax = 0x1300 | (mode as u16),
            bx = ((page as u16) << 8) | (attr as u16),
            cx = len,
            dx = ((row as u16) << 8) | (col as u16),
            es = buffer.segment,
            bp = buffer.offset,
        );
    }
}

pub const MASK_PARALLEL: u16 = 0xC000;
pub const MASK_SERIAL: u16 = 0x0E00;
pub const MASK_FLOPPY_COUNT: u16 = 0x00C0;
pub const MASK_VIDEO: u16 = 0x0030;
pub const MASK_MATH: u16 = 0x0002;
pub const MASK_FLOPPY_INSTALLED: u16 = 0x0001;

/// EQUIPMENT_1, see p. 5-143
pub const INT_EQUIPMENT: u8 = 0x11;

/// Equipment Determination
#[inline(always)]
pub fn get_equipment() -> u16 {
    let regs = bios_call!(self::INT_EQUIPMENT, ax = 0,);
    let list = regs.ax;
    list
}

/// MEMORY_SIZE_DETERMINE_1, see p. 5-143
pub const INT_MEMSIZE: u8 = 0x12;

/// Memory Size Determination (kB, below 1MB)
#[inline(always)]
pub fn get_memory_size() -> u16 {
    let regs = bios_call!(self::INT_MEMSIZE, ax = 0);
    let conventional = regs.ax; // kB (*1024 B)
    conventional
}

pub mod disk {

    use crate::*;

    /// DISKETTE I/O, see p. 5-89 ; FIXED DISK I/O, see p. 5-103
    pub const INT_DISK: u8 = 0x13;

    /// Success
    pub const STATUS_S: u8 = 0x0;
    /// Invalid Command
    pub const STATUS_C: u8 = 0x1;
    /// Address Mark Not Found
    pub const STATUS_AMNF: u8 = 0x2;
    /// Write Protect (Diskette)
    pub const STATUS_WP: u8 = 0x3;
    /// Sector Not Found
    pub const STATUS_SNF: u8 = 0x4;
    /// Reset Failed
    pub const STATUS_RF: u8 = 0x5;
    /// Diskette Change Line Active
    pub const STATUS_DCLA: u8 = 0x6;
    /// Drive Parameter Activity Failed
    pub const STATUS_DPAF: u8 = 0x7;
    /// DMA Overrun
    pub const STATUS_DO: u8 = 0x8;
    /// Data Boundary Error (DMA beyond 64kB)
    pub const STATUS_DBA: u8 = 0x9;
    /// Bad Sector Flag Detected
    pub const STATUS_BSFD: u8 = 0xA;
    /// Bad Track Detected
    pub const STATUS_BTD: u8 = 0xB;
    /// Unsupported Track
    pub const STATUS_UT: u8 = 0xC;
    /// Bad ECC On Read
    pub const STATUS_BEOR: u8 = 0x10;
    /// Data Corrected (recoverable)
    pub const STATUS_DC: u8 = 0x11;
    /// Controller Failure
    pub const STATUS_CF: u8 = 0x20;
    /// Seek Failed
    pub const STATUS_SF: u8 = 0x40;
    /// Timeout (Drive Not Ready)
    pub const STATUS_T: u8 = 0x80;

    /// Reset Disk System
    #[inline(always)]
    pub fn reset(drive: u8) -> Result<(), u8> {
        let regs = bios_call!(self::INT_DISK, ax = 0, dx = drive as u16,);
        if regs.flags & registers::flags::CF != 0 {
            let status = (regs.ax >> 8) as u8;
            return Err(status);
        }
        Ok(())
    }

    /// Read Status of Last Disk Operation
    #[inline(always)]
    pub fn get_status(drive: u8) -> u8 {
        let regs = bios_call!(self::INT_DISK, ax = 0x100, dx = drive as u16);
        (regs.ax >> 8) as u8
    }

    /// Read Sectors from Disk
    #[inline(always)]
    pub fn read_sectors(
        drive: u8,
        head: u8,
        cylinder: u16,
        sector: u8,
        count: u8,
        buffer: crate::FarPtr,
    ) -> Result<u8, (u8, u8)> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0x200 | count as u16,
            cx = (cylinder << 8) | ((sector as u16) & 0x3F) | ((cylinder >> 2) & 0xc0),
            dx = ((head as u16) << 8) | drive as u16,
            es = buffer.segment,
            bx = buffer.offset,
        );

        let (status, _count) = ((regs.ax >> 8) as u8, regs.ax as u8);

        if regs.flags & registers::flags::CF != 0 {
            return Err((status, _count));
        }

        Ok(_count)
    }

    /// Write Sectors to Disk
    #[inline(always)]
    pub fn write_sectors(
        drive: u8,
        head: u8,
        cylinder: u16,
        sector: u8,
        count: u8,
        buffer: crate::FarPtr,
    ) -> Result<u8, (u8, u8)> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0x300 | count as u16,
            cx = (cylinder << 8) | ((sector as u16) & 0x3F) | ((cylinder >> 2) & 0xc0),
            dx = ((head as u16) << 8) | drive as u16,
            es = buffer.segment,
            bx = buffer.offset,
        );

        let (status, _count) = ((regs.ax >> 8) as u8, regs.ax as u8);

        if regs.flags & registers::flags::CF != 0 {
            return Err((status, _count));
        }

        Ok(_count)
    }

    /// Verify Sectors
    #[inline(always)]
    pub fn verify_sectors(
        drive: u8,
        head: u8,
        cylinder: u16,
        sector: u8,
        count: u8,
    ) -> Result<u8, (u8, u8)> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0x400 | count as u16,
            cx = (cylinder << 8) | ((sector as u16) & 0x3F) | ((cylinder >> 2) & 0xc0),
            dx = ((head as u16) << 8) | drive as u16,
        );

        let (status, _count) = ((regs.ax >> 8) as u8, regs.ax as u8);

        if regs.flags & registers::flags::CF != 0 {
            return Err((status, _count));
        }

        Ok(_count)
    }

    #[repr(C, packed)]
    pub struct FormatTableEntry {
        pub cylinder: u8,
        pub head: u8,
        pub sector: u8,
        pub bytes: u8,
    }

    /// Format Track
    #[inline(always)]
    pub fn format_track(
        drive: u8,
        head: u8,
        cylinder: u16,
        count: u8,
        table: crate::FarPtr,
    ) -> Result<u8, (u8, u8)> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0x500 | count as u16,
            cx = cylinder << 8,
            dx = ((head as u16) << 8) | drive as u16,
            es = table.segment,
            bx = table.offset,
        );

        let (status, _count) = ((regs.ax >> 8) as u8, regs.ax as u8);

        if regs.flags & registers::flags::CF != 0 {
            return Err((status, _count));
        }

        Ok(_count)
    }

    /// Get Drive Parameters
    #[inline(always)]
    pub fn get_parameters(drive: u8) -> Result<(u8, u16, u8, u8), u8> {
        let regs = bios_call!(self::INT_DISK, ax = 0x800, dx = drive as u16,);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        let (max_head, max_cylinder, max_sector, drive_count) = (
            (regs.dx >> 8) as u8,
            (regs.cx & 0xFF) | ((regs.cx << 2) & 0x300),
            (regs.cx & 0x3F) as u8,
            (regs.dx & 0xFF) as u8,
        );

        Ok((max_head, max_cylinder, max_sector, drive_count))
    }

    /// Initialize Drive Pair Characteristics
    #[inline(always)]
    pub fn initialize_drive_pair(
        drive: u8,
        stepping_rate: u8,
        head_settle: u8,
        motor_timer: u8,
    ) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0x900,
            dx = ((((head_settle << 4) | (stepping_rate & 0x0F)) as u16) << 8) | (drive as u16),
            cx = (motor_timer as u16) << 8,
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Read Long (with ECC)
    #[inline(always)]
    pub fn read_long(
        drive: u8,
        head: u8,
        cylinder: u16,
        sector: u8,
        count: u8,
        buffer: crate::FarPtr,
    ) -> Result<u8, (u8, u8)> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0xA00 | count as u16,
            cx = ((cylinder & 0xFF) << 8)
                | ((sector & 0x3F) as u16 | (((cylinder >> 8) & 0x03) << 6)),
            dx = ((head as u16) << 8) | drive as u16,
            es = buffer.segment,
            bx = buffer.offset
        );

        let (status, sectors) = ((regs.ax >> 8) as u8, regs.ax as u8);

        if regs.flags & registers::flags::CF != 0 {
            return Err((status, sectors));
        }

        Ok(sectors)
    }

    /// Write Long (with ECC)
    #[inline(always)]
    pub fn write_long(
        drive: u8,
        head: u8,
        cylinder: u16,
        sector: u8,
        count: u8,
        buffer: crate::FarPtr,
    ) -> Result<u8, (u8, u8)> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0xB00 | count as u16,
            cx = ((cylinder & 0xFF) << 8)
                | ((sector & 0x3F) as u16 | (((cylinder >> 8) & 0x03) << 6)),
            dx = ((head as u16) << 8) | drive as u16,
            es = buffer.segment,
            bx = buffer.offset
        );

        let (status, sectors) = ((regs.ax >> 8) as u8, regs.ax as u8);

        if regs.flags & registers::flags::CF != 0 {
            return Err((status, sectors));
        }

        Ok(sectors)
    }

    /// Seek
    #[inline(always)]
    pub fn seek(cylinder: u16, head: u8, drive: u8) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0xC00,
            cx = ((cylinder & 0xFF) << 8) | ((cylinder >> 2) & 0xc0),
            dx = ((head as u16) << 8) | drive as u16,
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Alternate Disk Reset
    #[inline(always)]
    pub fn alternate_reset(drive: u8) -> Result<(), u8> {
        let regs = bios_call!(self::INT_DISK, ax = 0xD00, dx = drive as u16);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Test Drive Ready
    #[inline(always)]
    pub fn test_ready(drive: u8) -> Result<(), u8> {
        let regs = bios_call!(self::INT_DISK, ax = 0x1000, dx = drive as u16);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Recalibrate
    #[inline(always)]
    pub fn recalibrate(drive: u8) -> Result<(), u8> {
        let regs = bios_call!(self::INT_DISK, ax = 0x1100, dx = drive as u16);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Controller Internal Diagnostic
    #[inline(always)]
    pub fn controller_internal_diagnostic(drive: u8) -> Result<(), u8> {
        let regs = bios_call!(self::INT_DISK, ax = 0x1400, dx = drive as u16);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Read DASD Type Of Disk
    #[inline(always)]
    pub fn read_dasd_type(drive: u8) -> Result<(u8, u32), ()> {
        // DASD = Direct Access Storage Device

        let regs = bios_call!(self::INT_DISK, ax = 0x1500, dx = drive as u16);

        let r#type = (regs.ax >> 8) as u8;
        let sector_count = ((regs.cx as u32) << 16) | (regs.dx as u32);

        if regs.flags & registers::flags::CF != 0 {
            return Err(());
        }

        Ok((r#type, sector_count))
    }

    /// Get Disk Change Status Diskette
    #[inline(always)]
    pub fn get_disk_change_status(drive: u8) -> Result<(), u8> {
        let regs = bios_call!(self::INT_DISK, ax = 0x1600, dx = drive as u16);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    pub const DASD_TYPE_360_IN_360: u8 = 0x01;
    pub const DASD_TYPE_360_IN_12M: u8 = 0x02;
    pub const DASD_TYPE_12M_IN_12M: u8 = 0x03;
    pub const DASD_TYPE_720_IN_720: u8 = 0x04;

    /// Set DASD Type for Disk
    #[inline(always)]
    pub fn set_dasd_type(drive: u8, format: u8) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_DISK,
            ax = 0x1700 | format as u16,
            dx = drive as u16
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }
}

pub mod rs232 {

    /// RS232 I/O, see p. 5-125
    pub const INT_RS232: u8 = 0x14;

    /// Baud Rate Mask
    pub const MASK_BAUD: u8 = 0xe0;
    /// Parity Enable Mask
    pub const MASK_PARITY: u8 = 0x10;
    /// Even Parity Mask
    pub const MASK_EVEN: u8 = 0x8;
    /// Stop Bits Mask
    pub const MASK_STOP: u8 = 0x4;
    /// Word Length Mask
    pub const MASK_WORD: u8 = 0x3;

    pub const PORT_COM1: u8 = 0;
    pub const PORT_COM2: u8 = 1;
    pub const PORT_COM3: u8 = 2;
    pub const PORT_COM4: u8 = 3;

    /// Timeout
    pub const LINE_TIMEOUT: u8 = 0x80;
    /// Transmitter Shift Register Empty
    pub const LINE_SHIFT: u8 = 0x40;
    /// Transmitter Holding Register Empty
    pub const LINE_HOLDING: u8 = 0x20;
    /// Break Detected
    pub const LINE_BREAK: u8 = 0x10;
    /// Framing Error
    pub const LINE_FRAMING: u8 = 0x8;
    /// Parity Error
    pub const LINE_PARITY: u8 = 0x4;
    /// Overrun Error
    pub const LINE_OVERRUN: u8 = 0x2;
    /// Data Ready
    pub const LINE_READY: u8 = 0x1;

    /// Received Line Signal Detect
    pub const MODEM_RLSD: u8 = 0x80;
    /// Ring Indicator
    pub const MODEM_RI: u8 = 0x40;
    /// Data Set Ready
    pub const MODEM_DSR: u8 = 0x20;
    /// Clear To Send
    pub const MODEM_CTS: u8 = 0x10;
    /// Delta Received Line Signal Detect
    pub const MODEM_DELTA_RLSD: u8 = 0x8;
    /// Trailing Edge Ring Indicator
    pub const MODEM_TRAILING_RI: u8 = 0x4;
    /// Delta Data Set Ready
    pub const MODEM_DELTA_DSR: u8 = 0x2;
    /// Delta Clear To Send
    pub const MODEM_DELTA_CTS: u8 = 0x1;

    pub const BAUD_110: u8 = 0x00;
    pub const BAUD_150: u8 = 0x20;
    pub const BAUD_300: u8 = 0x40;
    pub const BAUD_600: u8 = 0x60;
    pub const BAUD_1200: u8 = 0x80;
    pub const BAUD_2400: u8 = 0xA0;
    pub const BAUD_4800: u8 = 0xC0;
    pub const BAUD_9600: u8 = 0xE0;

    pub const PARITY_NONE: u8 = 0x00;
    pub const PARITY_ODD: u8 = 0x08;
    pub const PARITY_EVEN: u8 = 0x18;

    pub const STOP_BITS_1: u8 = 0x00;
    pub const STOP_BITS_2: u8 = 0x04;

    pub const WORD_LEN_5: u8 = 0x00;
    pub const WORD_LEN_6: u8 = 0x01;
    pub const WORD_LEN_7: u8 = 0x02;
    pub const WORD_LEN_8: u8 = 0x03;

    /// Initialize Port
    pub fn init(port: u8, parameters: u8) -> (u8, u8) {
        let regs = bios_call!(self::INT_RS232, ax = parameters as u16, dx = port as u16,);

        let status = ((regs.ax >> 8) as u8, regs.ax as u8); // line, modem

        status
    }

    /// Send Character
    pub fn send_char(port: u8, char: u8) -> u8 {
        let regs = bios_call!(self::INT_RS232, ax = 0x100 | char as u16, dx = port as u16,);

        let status = (regs.ax >> 8) as u8; // line

        status
    }

    /// Receive Character
    pub fn recv_char(port: u8) -> (u8, u8) {
        let regs = bios_call!(self::INT_RS232, ax = 0x200, dx = port as u16);

        let (status, char) = ((regs.ax >> 8) as u8, regs.ax as u8);

        (status, char)
    }

    /// Get Port Status
    pub fn get_status(port: u8) -> (u8, u8) {
        let regs = bios_call!(self::INT_RS232, ax = 0x300, dx = port as u16);

        let status = ((regs.ax >> 8) as u8, regs.ax as u8); // line, modem

        status
    }
}

pub mod system {
    
    use crate::*;

    pub const INT_SYSTEM: u8 = 0x15;

    pub const DEVICE_UNUSED: u16 = 0;
    pub const DEVICE_KEYBOARD: u16 = 0x1;
    pub const DEVICE_DISPLAY: u16 = 0x2;
    pub const DEVICE_SERIAL: u16 = 0x3;
    pub const DEVICE_PARALLEL: u16 = 0x4;
    pub const DEVICE_DISKETTE: u16 = 0x5;
    pub const DEVICE_FIXEDDISK: u16 = 0x6;
    pub const DEVICE_NETWORK: u16 = 0x7;

    /// Device Open
    #[inline(always)]
    pub fn device_open(id: u16, process: u16) -> Result<(), u8> {
        let regs = bios_call!(self::INT_SYSTEM, ax = 0x8000, bx = id, cx = process,);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Device Close
    #[inline(always)]
    pub fn device_close(id: u16, process: u16) -> Result<(), u8> {
        let regs = bios_call!(self::INT_SYSTEM, ax = 0x8100, bx = id, cx = process,);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Program Termination
    #[inline(always)]
    pub fn program_termination(id: u16) -> Result<(), u8> {
        let regs = bios_call!(self::INT_SYSTEM, ax = 0x8200, bx = id,);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Event Wait
    #[inline(always)]
    pub fn event_wait(microseconds: u32, flag: FarPtr, cancel: bool) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_SYSTEM,
            ax = 0x8300 | if cancel { 1 } else { 0 },
            cx = (microseconds >> 16) as u16,
            dx = microseconds as u16,
            es = flag.segment,
            bx = flag.offset,
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    pub const JOYSTICK_SWITCHES: u8 = 0;
    pub const JOYSTICK_INPUTS: u8 = 1;

    /// Joystick
    #[inline(always)]
    pub fn joystick(subfunction: u8) -> (u16, u16, u16, u16) {
        let regs = bios_call!(self::INT_SYSTEM, ax = 0x8400, dx = subfunction as u16);

        (regs.ax, regs.bx, regs.cx, regs.dx)
    }

    pub const SYSREQ_MAKE: u8 = 0;
    pub const SYSREQ_BREAK: u8 = 1;

    /// SysReq Key
    #[inline(always)]
    pub fn sysreq(what: u8) {
        bios_call!(self::INT_SYSTEM, ax = 0x8500 | what as u16,);
    }

    /// Wait
    #[inline(always)]
    pub fn wait(microseconds: u32) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_SYSTEM,
            ax = 0x8600,
            cx = (microseconds >> 16) as u16,
            dx = microseconds as u16,
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    

    /// Move Block
    #[inline(always)]
    pub fn move_block(wcount: u16, gdt: FarPtr) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_SYSTEM,
            ax = 0x8700,
            cx = wcount,
            es = gdt.segment,
            si = gdt.offset,
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Extended Memory Size
    #[inline(always)]
    pub fn extended_memory_size() -> Result<u16, ()> {
        let regs = bios_call!(self::INT_SYSTEM, ax = 0x8800);

        let extended = regs.ax; // kB

        if regs.flags & registers::flags::CF != 0 {
            return Err(());
        }

        Ok(extended)
    }

    
    /// Switch To Protected Mode
    #[inline(always)]
    #[allow(unreachable_code)]
    pub fn switch_protected(gdt: FarPtr, irq0: u8, irq8: u8) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_SYSTEM,
            ax = 0x8900,
            bx = ((irq0 as u16) << 8) | irq8 as u16,
            es = gdt.segment,
            si = gdt.offset,
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        loop {}

        Ok(())
    }

    /// Device Busy Loop
    #[inline(always)]
    pub fn device_busy(r#type: u8, context: FarPtr) -> Result<(), u8> {
        let regs = bios_call!(
            self::INT_SYSTEM,
            ax = 0x9000 | r#type as u16,
            es = context.segment,
            bx = context.offset,
        );

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        Ok(())
    }

    /// Interrupt Complete
    #[inline(always)]
    pub fn interrupt_complete(r#type: u8, context: FarPtr) {
        bios_call!(
            self::INT_SYSTEM,
            ax = 0x9100 | r#type as u16,
            es = context.segment,
            bx = context.offset,
        );
    }

    /// System Configuration Table
    #[repr(C, packed)]
    pub struct ConfigurationTable {
        pub length: u16,
        pub model: u8,
        pub sub_model: u8,
        /// BIOS Revision
        pub revision: u8,
        pub features: u8,
        pub reserved: [u8; 4],
    }

    impl ConfigurationTable {
        pub const FEATURE_DMA_CH3: u8 = 0x80;
        pub const FEATURE_SLAVE_PIC: u8 = 0x40;
        pub const FEATURE_RTC: u8 = 0x20;
        pub const FEATURE_KBD_INTERCEPT: u8 = 0x10;
        pub const FEATURE_WAIT_EXTERNAL: u8 = 0x08;
        pub const FEATURE_EBDA: u8 = 0x04;
        pub const FEATURE_MICRO_CHANNEL: u8 = 0x02;
    }

    /// Get System Configuration
    #[inline(always)]
    pub fn get_configuration() -> Result<FarPtr, u8> {
        let regs = bios_call!(self::INT_SYSTEM, ax = 0xC000,);

        let status = (regs.ax >> 8) as u8;

        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        let sct = FarPtr {
            segment: regs.es,
            offset: regs.bx,
        };

        Ok(sct)
    }

    #[repr(C, packed)]
    pub struct MemoryMapEntry {
        pub base_address: u64,
        pub length: u64,
        pub memory_type: u32,
        pub acpi_attributes: u32, // Only valid if BIOS returns 24 bytes.
    }

    /// Get Memory Map
    #[inline(always)]
    pub fn get_memory_map(
        continuation: u16,
        buffer: FarPtr,
        size: u16,
    ) -> Result<(u16, u16), u8> {
        let regs = bios_call!(
            self::INT_SYSTEM,
            ax = 0xe820,
            bx = continuation,
            cx = size,
            es = buffer.segment,
            di = buffer.offset,
            si = 0x53d4,
            dx = 0x4150
        );

        let status = (regs.ax >> 8) as u8;
        if regs.flags & registers::flags::CF != 0 {
            return Err(status);
        }

        let (_continuation, _size) = (regs.bx, regs.cx);

        Ok((_continuation, _size))
    }
}

pub mod keyboard {

    use crate::*;

    /// KEYBOARD I/O, see p. 5-115
    pub const INT_KEYBOARD: u8 = 0x16;

    /// Read Character (Wait)
    #[inline(always)]
    pub fn read_char() -> (u8, u8) {
        let regs = bios_call!(self::INT_KEYBOARD, ax = 0u16,);

        let (scan, ascii) = ((regs.ax >> 8) as u8, regs.ax as u8);

        (scan, ascii)
    }

    /// Check If Key Available (No Block) (see: p. 5-115)
    #[inline(always)]
    pub fn check_buffer() -> Option<(u8, u8)> {
        let regs = bios_call!(self::INT_KEYBOARD, ax = 0x100,);

        if regs.flags & registers::flags::ZF != 0 {
            return None;
        }

        let (scan, ascii) = ((regs.ax >> 8) as u8, regs.ax as u8);

        Some((scan, ascii))
    }

    /// Right Shift Key Pressed
    pub const FLAGS_SHIFT_RIGHT: u8 = 0x01;
    /// Left Shift Key Pressed
    pub const FLAGS_SHIFT_LEFT: u8 = 0x02;
    /// Ctrl Key Pressed
    pub const FLAGS_CTRL: u8 = 0x04;
    /// Alt Key Pressed
    pub const SHIFT_ALT: u8 = 0x08;
    /// Scroll Lock Toggle
    pub const FLAGS_SCROLL_LOCK: u8 = 0x10;
    /// Num Lock Toggle
    pub const FLAGS_NUM_LOCK: u8 = 0x20;
    /// Caps Lock Toggle
    pub const FLAGS_CAPS_LOCK: u8 = 0x40;
    /// Insert Toggle
    pub const FLAGS_INSERT: u8 = 0x80;

    /// Get Shift Flags (see: p. 5-115)
    #[inline(always)]
    pub fn get_flags() -> u8 {
        let regs = bios_call!(self::INT_KEYBOARD, ax = 0x200,);

        regs.ax as u8
    }
}

pub mod printer {

    /// PRINTER I/O, see p. 5-123
    pub const INT_PRINTER: u8 = 0x17;

    /// Timeout
    pub const STATUS_TIMEOUT: u8 = 0x80;
    /// Printer Selected
    pub const STATUS_SELECTED: u8 = 0x10;
    /// Out Of Paper
    pub const STATUS_OOP: u8 = 0x08;
    /// Acknowledge
    pub const STATUS_ACK: u8 = 0x04;
    /// Printer Busy
    pub const STATUS_BUSY: u8 = 0x01;

    pub const PRINTER_LPT1: u8 = 0;
    pub const PRINTER_LPT2: u8 = 1;
    pub const PRINTER_LPT3: u8 = 2;

    /// Print Character
    #[inline(always)]
    pub fn print_char(printer: u8, char: u8) -> u8 {
        let regs = bios_call!(self::INT_PRINTER, ax = char as u16, dx = printer as u16);

        let status = (regs.ax >> 8) as u8;

        status
    }

    /// Initialize Printer (see: p. 5-123)
    #[inline(always)]
    pub fn init(printer: u8) -> u8 {
        let regs = bios_call!(self::INT_PRINTER, ax = 0x100, dx = printer as u16);

        (regs.ax >> 8) as u8
    }

    /// Get Printer Status (see: p. 5-123)
    #[inline(always)]
    pub fn get_status(printer: u8) -> u8 {
        let regs = bios_call!(self::INT_PRINTER, ax = 0x200, dx = printer as u16);

        let status = (regs.ax >> 8) as u8;

        status
    }
}

pub mod time {

    use crate::*;

    /// TIME OF DAY, see p. 5-159
    pub const INT_TIME: u8 = 0x1A;

    /// Read System Timer Counter
    #[inline(always)]
    pub fn get_stc() -> (u32, bool) {
        let regs = bios_call!(self::INT_TIME, ax = 0);

        let (ticks, rollover) = (((regs.cx as u32) << 16) | regs.dx as u32, regs.ax != 0);

        (ticks, rollover)
    }

    /// Set System Timer Counter
    #[inline(always)]
    pub fn set_stc(ticks: u32) {
        bios_call!(
            self::INT_TIME,
            ax = 0x100,
            cx = (ticks >> 16) as u16,
            dx = ticks as u16
        );
    }

    /// Read Real-Time Clock (RTC)
    #[inline(always)]
    pub fn get_rtc_time() -> (u8, u8, u8, u8) {
        let regs = bios_call!(self::INT_TIME, ax = 0x200,);

        let (hours, minutes, seconds, daylight) = ((regs.cx >> 8) as u8, regs.cx as u8, (regs.dx >> 8) as u8, regs.dx as u8);

        (hours, minutes, seconds, daylight)
    }

    /// Set Real-Time Clock (RTC)
    #[inline(always)]
    pub fn set_rtc_time(hours: u8, minutes: u8, seconds: u8, daylight: u8) {
        bios_call!(
            self::INT_TIME,
            ax = 0x300,
            cx = ((hours as u16) << 8) | minutes as u16,
            dx = ((seconds as u16) << 8) | daylight as u16,
        );
    }

    /// Read Date From RTC
    #[inline(always)]
    pub fn get_rtc_date() -> (u8, u8, u8, u8) {
        let regs = bios_call!(self::INT_TIME, ax = 0x400,);

        let (century, year, month, day) = (
            (regs.cx >> 8) as u8,
            regs.cx as u8,
            (regs.dx >> 8) as u8,
            regs.dx as u8,
        );

        (century, year, month, day)
    }

    /// Set date in RTC
    #[inline(always)]
    pub fn set_rtc_date(century: u8, year: u8, month: u8, day: u8) {
        bios_call!(
            self::INT_TIME,
            cx = ((century as u16) << 8) | year as u16,
            dx = ((month as u16) << 8) | day as u16,
        );
    }

    /// Set Alarm
    #[inline(always)]
    pub fn set_rtc_alarm(hours: u8, minutes: u8, seconds: u8) -> Result<(), ()> {
        let regs = bios_call!(
            self::INT_TIME,
            ax = 0x600,
            cx = ((hours as u16) << 8) | minutes as u16,
            dx = (seconds as u16) << 8,
        );

        if regs.flags & registers::flags::CF != 0 {
            return Err(());
        }
        Ok(())
    }

    /// Reset Alarm
    #[inline(always)]
    pub fn reset_rtc_alarm() {
        bios_call!(self::INT_TIME, ax = 0x700,);
    }
}

/// BOOT STRAP, see p. 5-169
pub const INT_REBOOT: u8 = 0x19;

pub fn reboot() -> ! {
    bios_call!(self::INT_REBOOT,);
    unreachable!();
}

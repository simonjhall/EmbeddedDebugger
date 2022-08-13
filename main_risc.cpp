/*
 * main.cpp
 *
 *  Created on: 29 Aug 2018
 *      Author: simon
 */

#include "uart.h"
#include "common.h"
#include "misc_asm.h"
#include "inter_process.h"
#include "Debugger.h"

#include <string.h>

#include <sys/utsname.h>

static const unsigned int s_userStackSize = 32 * 1024;
unsigned char g_userStack[s_userStackSize];

#if __riscv_xlen == 32
#define CONFIG_32BIT
#elif __riscv_xlen == 64
#define CONFIG_64BIT
#else
#error
#endif

//////////
unsigned long brk_end = 0x10260000;
unsigned long mmap_heap = 0x10290000;
unsigned long mmap_heap_end = 0x10290000;
unsigned long file_pos = 0;

//////////

//demo
void func_in_user_mode(void)
{
	put_string_user("in user mode\n");

	while (1)
		trap0(DEBUGGER_UPDATE);
}

//from elf/elf.h
#define AT_NULL		0		/* End of vector */
#define AT_IGNORE	1		/* Entry should be ignored */
#define AT_EXECFD	2		/* File descriptor of program */
#define AT_PHDR		3		/* Program headers for program */
#define AT_PHENT	4		/* Size of program header entry */
#define AT_PHNUM	5		/* Number of program headers */
#define AT_PAGESZ	6		/* System page size */
#define AT_BASE		7		/* Base address of interpreter */
#define AT_FLAGS	8		/* Flags */
#define AT_ENTRY	9		/* Entry point of program */
#define AT_NOTELF	10		/* Program is not ELF */
#define AT_UID		11		/* Real uid */
#define AT_EUID		12		/* Effective uid */
#define AT_GID		13		/* Real gid */
#define AT_EGID		14		/* Effective gid */
#define AT_CLKTCK	17		/* Frequency of times() */

struct Elf32_auxv_t
{
	uint32_t a_type;		/* Entry type */
	union
	{
		uint32_t a_val;		/* Integer value */
	} a_un;
};


typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;

#define PT_TLS		7		/* Thread-local storage segment */

typedef struct
{
  Elf32_Word	p_type;			/* Segment type */
  Elf32_Off	p_offset;		/* Segment file offset */
  Elf32_Addr	p_vaddr;		/* Segment virtual address */
  Elf32_Addr	p_paddr;		/* Segment physical address */
  Elf32_Word	p_filesz;		/* Segment size in file */
  Elf32_Word	p_memsz;		/* Segment size in memory */
  Elf32_Word	p_flags;		/* Segment flags */
  Elf32_Word	p_align;		/* Segment alignment */
} Elf32_Phdr;


extern "C" void gdb_elf_load(unsigned long ident, unsigned long ecall, void *pStack);

void elf_entry(void)
{
	//the order matters here
#define ARGC_BASE 1
#define ARGC_EXTRAS 3
#define ARGC_NECESSARY 3

	struct the_stack
	{
		int m_argc;
		const char *m_argv[ARGC_BASE + ARGC_EXTRAS + ARGC_NECESSARY];
		Elf32_auxv_t m_auxvec[3];
		Elf32_Phdr m_phdr;
	} stack;
	
	stack.m_argc = ARGC_BASE + ARGC_EXTRAS;
	stack.m_argv[0] = "my_elf";
	stack.m_argv[1] = "-warp";
	stack.m_argv[2] = "1";
	stack.m_argv[3] = "1";
	stack.m_argv[4] = 0;
	stack.m_argv[5] = "environment";
	stack.m_argv[6] = 0;
	
	stack.m_auxvec[0] = {AT_PHNUM, {1}};
	stack.m_auxvec[1] = {AT_PHDR, {(uint32_t)&stack.m_phdr}};
	stack.m_auxvec[2] = {AT_NULL, {0}};
	
	stack.m_phdr.p_type = PT_TLS;
	stack.m_phdr.p_memsz = 0x00000038;
	stack.m_phdr.p_filesz = 0x00000010;
	stack.m_phdr.p_vaddr = 0x101d6c64;
	stack.m_phdr.p_align = 1 << 2;

#ifdef CONFIG_64BIT
#error update me
#endif
	
	//reliant on things being pushed into the structure in the correct order
	gdb_elf_load(0x09000000, DEBUGGER_UPDATE, &stack);
}

//////////

static Cpu g_cpu;
static VirtualMemory g_vMem;
static CpuDebugger g_debugger;

static void Trap(ExceptionState *pState)
{
	bool change_state = true;

	unsigned long a6_call, a7_call;
	unsigned long a0, a1, a2, a3, a4;

	a6_call = pState->regs_int[16];
	a7_call = pState->regs_int[17];
	a0 = pState->regs_int[10];
	a1 = pState->regs_int[11];
	a2 = pState->regs_int[12];
	a3 = pState->regs_int[13];
	a4 = pState->regs_int[14];

	if (a7_call == 0x09000000)
	{
		unsigned long error = 0;
		unsigned long value = 0;

		switch (a6_call)
		{
		case TRAP_PRINT_CHAR:
			g_debugger.put_char_gdb(a0);
			error = 1;
			break;
		case TRAP_PRINT_HEX_NUM:
			g_debugger.put_hex_num_gdb(a0);
			error = 1;
			break;
		case TRAP_PRINT_HEX_BYTE:
			g_debugger.put_hex_byte_gdb(a0);
			error = 1;
			break;
		case TRAP_PRINT_DEC_SHORT_NUM:
			g_debugger.put_dec_short_num_gdb(a0, a1);
			error = 1;
			break;
		case TRAP_PRINT_STRING:
			g_debugger.put_string_gdb((char *)a0);
			error = 1;
			break;
		case DEBUGGER_UPDATE:
			g_cpu.SetState(pState);
			g_debugger.DebuggerUpdate(CpuDebugger::kTrapUpdate);
			change_state = false;
			break;
		default:
			g_debugger.put_string_gdb("unknown a6 ecall\n");
			g_debugger.put_dec_short_num_gdb(a6_call, false);
			g_debugger.put_char_gdb('\n');
			break;
		}

		if (change_state)
		{
			pState->regs_int[10] = error;		//error = true
			pState->regs_int[11] = value;		//value
		}  
	}
	else
	{
		switch (a7_call)
		{
		case 56:			//openat
		{
			int fd = -1;
							
#define AT_FDCWD (unsigned long)-100
			if (a0 == AT_FDCWD)
			{
				if (strcmp((const char *)a1, "./doom1.wad") == 0)
				{
					fd = 10;			//a valid file handle
				}
			}
			
			a0 = fd;
			break;
		}
		case 62:			//lseek
		{
			if (a0 == 10 && a1 == 0)
			{
				volatile uint64_t *pSeek = (uint64_t *)0x1000500;
				file_pos = a2;
				*pSeek = file_pos;
				
				a0 = file_pos;
			}
			else
				a0 = -1;
			break;
		}
		case 63:			//read
		{
			if (a0 == 10)
			{
				unsigned int read_count = 0;
				unsigned char *pBuf = (unsigned char *)a1;
				volatile unsigned char *pData = (unsigned char *)0x1000508;
				
				for (unsigned long count = 0; count < a2; count++)
				{
					*pBuf++ = *pData;
					read_count++;
				}
				
				file_pos += read_count;
				
				a0 = read_count;
			}
			else
				a0 = -1;
			break;
			
		}
		case 64:			//write
		{
			if (a0 == 1 || a0 == 2)		//stdout or stderr
			{
				for (unsigned long count = 0; count < a2; count++)
					g_debugger.put_char_gdb(((const char *)a1)[count]);
				a0 = a2;
			}
			else
				a0 = 0;
			break;
		}
		case 160:			//uname
		{
			utsname *pUts = (utsname *)a0;
			if (pUts)
			{
				strcpy(pUts->sysname, "SYSNAME");
				strcpy(pUts->nodename, "NODENAME");
				strcpy(pUts->release, "10.0.0");
				strcpy(pUts->version, "1");
				strcpy(pUts->machine, "MACHINE");
			}
			a0 = 0;
			break;
		}
		case 174:			//getuid
		{
			a0 = 0;
			break;
		}
		case 175:			//geteuid
		{
			a0 = 0;
			break;
		}
		case 176:			//getgid
		{
			a0 = 0;
			break;
		}
		case 177:			//getegid
		{
			a0 = 0;
			break;
		}
		case 214:			//brk
		{
			//https://elixir.bootlin.com/linux/v5.16-rc1/source/mm/nommu.c#L380
			if (a0 != 0)
			{
				brk_end = a0;
				
				if (brk_end >= mmap_heap)
				{
					g_debugger.put_string_gdb("brk_end exceeding heap beginning\n");
					g_debugger.put_hex_num_gdb(brk_end);
					g_debugger.put_char_gdb(' ');
					g_debugger.put_hex_num_gdb(mmap_heap);
					g_debugger.put_char_gdb('\n');
				}
			}
			a0 = brk_end;
			break;
		}
		case 222:			//mmap
		{
#define MAP_PRIVATE		0x02
#define MAP_ANONYMOUS	0x20
			if ((a0 == 0)							//address == 0
				&& (a3 == (MAP_ANONYMOUS | MAP_PRIVATE))
				&& (a4 == (unsigned long)-1))	//file
			{
				a0 = mmap_heap_end;
				if (a1 >= 0)
					mmap_heap_end += a1;
			}
			else
				a0 = -1;							//MAP_FAILED
			break;
		}
		case 403:			//clock_gettime
		{
			struct timespec
			{
				uint64_t  tv_sec;     /* seconds */
				uint32_t  tv_nsec;    /* and nanoseconds */
			};

			volatile unsigned int *pData = (unsigned int *)0x1000600;
			if (a0 == 0 && a1 != 0)		//CLOCK_REALTIME
			{
				unsigned int time = *pData;
				timespec *pRet = (timespec *)a1;
				
				pRet->tv_sec = time >> 15;
				pRet->tv_nsec = (time & 32767) * 30517;
				a0 = 0;
			}
			else
				a0 = -1;
			break;
		}
		
		default:
			g_debugger.put_string_gdb("unknown a7 ecall\n");
			g_debugger.put_dec_short_num_gdb(a7_call, false);
			g_debugger.put_char_gdb(' ');
			g_debugger.put_hex_num_gdb(a0);
			g_debugger.put_char_gdb(' ');
			g_debugger.put_hex_num_gdb(a1);
			g_debugger.put_char_gdb(' ');
			g_debugger.put_hex_num_gdb(a2);
			g_debugger.put_string_gdb(" from ");
			g_debugger.put_hex_num_gdb(pState->pc);
			g_debugger.put_char_gdb('\n');
			break;
		}
		
		pState->regs_int[10] = a0;
	}
	if (change_state)
		pState->pc += 4;					//next instruction
}

static void DumpAddrBusState(ExceptionState *pState)
{

}

static void DumpExceptionState(ExceptionState *pState)
{

}


static void Interrupt(ExceptionState *pState)
{
	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kInterruptUpdate);
}

static unsigned long get_reg(uint32_t id)
{
	return g_cpu.GetRx(id);
}

#ifdef CONFIG_64BIT
static void set_reg64(uint32_t id, uint64_t val)
{
	g_cpu.GetRx(id) = val;
	if (id == 0)
	{
		//do nothing
	}
	else if (id == 4)
		csr_write(CSR_MSCRATCH, val);
	else
		pRegs[id] = val;
}
#endif

static void set_reg32(uint32_t id, uint32_t _val)
{
	unsigned long val = _val;

#ifdef CONFIG_64BIT
	//sign extend
	if (_val & (1 << 31))
		val |= 0xffffffff00000000ull;
#endif
	
	g_cpu.GetRx(id) = val;
}

#ifdef CONFIG_64BIT
static void set_reg_full(uint32_t id, unsigned long val)
{
	set_reg64(id, val);
}
#else
static void set_reg_full(uint32_t id, unsigned long val)
{
	set_reg32(id, val);
}
#endif

static unsigned long amo_add(unsigned long original, unsigned long incoming)
{
	return original + incoming;
}

static unsigned long amo_and(unsigned long original, unsigned long incoming)
{
	return original & incoming;
}

static unsigned long amo_swap(unsigned long original, unsigned long incoming)
{
	return incoming;
}

static unsigned long amo_or(unsigned long original, unsigned long incoming)
{
	return original | incoming;
}

static unsigned long amo_xor(unsigned long original, unsigned long incoming)
{
	return original ^ incoming;
}

static unsigned long amo_min(unsigned long original, unsigned long incoming)
{
	return (long)original < (long)incoming ? original : incoming;
}

static unsigned long amo_minu(unsigned long original, unsigned long incoming)
{
	return original < incoming ? original : incoming;
}

static unsigned long amo_max(unsigned long original, unsigned long incoming)
{
	return (long)original > (long)incoming ? original : incoming;
}

static unsigned long amo_maxu(unsigned long original, unsigned long incoming)
{
	return original > incoming ? original : incoming;
}

static bool amo_op(unsigned int rd, unsigned int rs1, unsigned int rs2,
	unsigned long (*op)(unsigned long, unsigned long), unsigned int size)
{
	uintptr_t pa;
	//read and write
	pa = get_reg(rs1);

	if (size == 2)		//32-bit
	{
		/* when run on 32-bit
		load a 32-bit value, op takes ulong (32-bit), get_reg returns 32-bit
		result is 32-bit
		set_reg32 sets a 32-bit value

		when run on 64-bit
		load a 32-bit value (zero-extend to 64-bit), op takes 64-bit, get_reg returns 64-bit
		result is 64-bit, but truncated to 32-bit
		set_reg32 sign-extends the truncated 32-bit result to 64-bit
		*/
		uint32_t original_value = *(uint32_t *)pa;
		uint32_t new_value = op(original_value, get_reg(rs2));
		set_reg32(rd, original_value);
		*(uint32_t *)pa = new_value;
	}
	//rv64-only encoding
#ifdef CONFIG_64BIT
	else				//64-bit
	{
		uint64_t original_value = *(uint64_t *)pa;
		uint64_t new_value = op(original_value, get_reg(rs2));
		set_reg_full(rd, original_value);
		*(uint64_t *)pa = new_value;
	}
#endif

	return true;
}

uint64_t reservation_addr_pa;

static void Illegal(ExceptionState *pState)
{
	bool handled = false;
	g_cpu.SetState(pState);
	
	if ((g_cpu.GetPC() & 3) == 0)
	{
		unsigned int tval;
		
		if (g_vMem.Read(false, true, &tval, g_cpu.GetPC(), 4))
		{
			bool fall_through = true;

			unsigned int opcode = tval & 127;
			switch (opcode)
			{
				//system
				case 0b1110011:
				{
					unsigned int rd = (tval >> 7) & 31;
					unsigned int funct3 = (tval >> 12) & 7;
					unsigned int csr = tval >> 20;

					unsigned long rd_value = 0;

					//csrrs
					if (funct3 == 0b010)
					{
						switch (csr)
						{
							//time
							case 0xC01:
							{
								volatile unsigned int *pTime = (volatile unsigned int *)0x1000600;
								rd_value = *pTime;
								fall_through = false;
								break;
							}
#ifdef CONFIG_32BIT
							//timer is only 32 bits wide
							case 0xC81:
								rd_value = 0;
								fall_through = false;
								break;
#endif
							default:
								break;
						}
					}

					if (!fall_through)
						set_reg_full(rd, rd_value);
					break;
				}
#ifdef CONFIG_64BIT
				//op-32
				case 0b0111011:
				{
					unsigned int rd = (tval >> 7) & 31;
					unsigned int funct3 = (tval >> 12) & 7;
					unsigned int rs1 = (tval >> 15) & 31;
					unsigned int rs2 = (tval >> 20) & 31;
					unsigned int funct7 = tval >> 25;

					switch (funct7)
					{
						//muldiv
						case 0b0000001:
						{
							uint32_t rs1_32 = get_reg(rs1) & 0xffffffff;
							uint32_t rs2_32 = get_reg(rs2) & 0xffffffff;

							int s_rs1 = rs1_32;
							int s_rs2 = rs2_32;

							unsigned int u_rs1 = rs1_32;
							unsigned int u_rs2 = rs2_32;

							//outputs are sign-extended to 64-bit

							switch (funct3)
							{
								//divw
								case 0b100:
								{
									set_reg32(rd, s_rs1 / s_rs2);
									fall_through = false;
									break;
								}
								//divuw
								case 0b101:
								{
									set_reg32(rd, u_rs1 / u_rs2);
									fall_through = false;
									break;
								}
								//remw
								case 0b110:
								{
									set_reg32(rd, s_rs1 % s_rs2);
									fall_through = false;
									break;
								}
								//remuw
								case 0b111:
								{
									set_reg32(rd, u_rs1 % u_rs2);
									fall_through = false;
									break;
								}
								default:
									break;	//did not match the instruction
							}
						}
						default:
							break;		//did not decode this major class
					}
					break;				//break from op
				}
#endif
				//op
				case 0b0110011:
				{
					unsigned int rd = (tval >> 7) & 31;
					unsigned int funct3 = (tval >> 12) & 7;
					unsigned int rs1 = (tval >> 15) & 31;
					unsigned int rs2 = (tval >> 20) & 31;
					unsigned int funct7 = tval >> 25;

					switch (funct7)
					{
						//muldiv
						case 0b0000001:
						{
							switch (funct3)
							{
								//div
								case 0b100:
								{
									set_reg_full(rd, (long)get_reg(rs1) / (long)get_reg(rs2));
									fall_through = false;
									break;
								}
								//divu
								case 0b101:
								{
									set_reg_full(rd, (unsigned long)get_reg(rs1) / (unsigned long)get_reg(rs2));
									fall_through = false;
									break;
								}
								//rem
								case 0b110:
								{
									set_reg_full(rd, (long)get_reg(rs1) % (long)get_reg(rs2));
									fall_through = false;
									break;
								}
								//remu
								case 0b111:
								{
									set_reg_full(rd, (unsigned long)get_reg(rs1) % (unsigned long)get_reg(rs2));
									fall_through = false;
									break;
								}
								default:
									break;	//did not match the instruction
							}
						}
						default:
							break;		//did not decode this major class
					}
					break;				//break from op
				}
				//amo
				case 0b0101111:
				{
					unsigned int rd = (tval >> 7) & 31;
					unsigned int funct3 = (tval >> 12) & 3;
					unsigned int rs1 = (tval >> 15) & 31;
					unsigned int rs2 = (tval >> 20) & 31;
					unsigned int funct5 = tval >> 27;

					//These AMO instructions atomically load a data value from the address in rs1,
					//place the value into register rd, apply a binary operator to the loaded value
					//and the original value in rs2, then store the result back to the address in rs1.	
					switch (funct5)
					{
						//AMOSWAP.W/D
						case 0b00001:
						{
							if (amo_op(rd, rs1, rs2, &amo_swap, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOADD.W/D
						case 0b00000:
						{
							if (amo_op(rd, rs1, rs2, &amo_add, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOXOR.W/D
						case 0b00100:
						{
							if (amo_op(rd, rs1, rs2, &amo_xor, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOAND.W/D
						case 0b01100:
						{
							if (amo_op(rd, rs1, rs2, &amo_and, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOOR.W/D
						case 0b01000:
						{
							if (amo_op(rd, rs1, rs2, &amo_or, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOMIN.W/D
						case 0b10000:
						{
							if (amo_op(rd, rs1, rs2, &amo_min, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOMINU.W/D
						case 0b11000:
						{
							if (amo_op(rd, rs1, rs2, &amo_minu, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOMAX.W/D
						case 0b10100:
						{
							if (amo_op(rd, rs1, rs2, &amo_max, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//AMOMAXU.W/D
						case 0b11100:
						{
							if (amo_op(rd, rs1, rs2, &amo_maxu, funct3))
								fall_through = false;

							break;		//break from this instruction
						}
						//LR.W/D
						case 0b00010:
						{
							uintptr_t pa;
							//read only
							pa = get_reg(rs1);

							if (funct3 == 2)		//32-bit
							{
								/* on 32-bit
								load the 32-bit value
								set_reg32 takes 32-bit input
								on 64-bit
								load the 32-bit value
								set_reg32 takes 32-bit input
								sign-extends to 64-bit
								*/
								set_reg32(rd, *(uint32_t *)pa);
							}
#ifdef CONFIG_64BIT
							else					//64-bit
							{
								set_reg_full(rd, *(uint64_t *)pa);
							}
#endif
							reservation_addr_pa = pa;

							fall_through = false;
							break;		//break from this instruction
						}
						//SC.W/D
						case 0b00011:
						{
							uintptr_t pa;
							//write only
							pa = get_reg(rs1);

							//SC.W conditionally writes a word in rs2 to the address in rs1:
							//the SC.W succeeds only if the reservation is still valid and
							//the reservation set contains the bytes being written.
							//If the SC.W succeeds, the instruction writes the word in rs2
							//to memory, and it writes zero to rd. If the SC.W fails,
							//the instruction does not write to memory, and it writes a
							//nonzero value to rd.

							if (pa == reservation_addr_pa)
							{
								//success
								if (funct3 == 2)		//32-bit
								{
									*(uint32_t *)pa = get_reg(rs2);
								}
#ifdef CONFIG_64BIT
								else					//64-bit
								{
									*(uint64_t *)pa = get_reg(rs2);
								}
#endif

								set_reg_full(rd, 0);
							}
							else	//failure
								set_reg_full(rd, 1);

							//token invalidation
							reservation_addr_pa = -1;

							fall_through = false;
							break;		//break from this instruction
						}
						default:
							break;		//did not decode this amo instruction
					}
					break;				//break from amo
				}
				default:
					break;				//did not decode this class
			}

			if (!fall_through)
			{
				//move to next instruction
				handled = true;
			}
		}
	}
	
	if (!handled)
		g_debugger.DebuggerUpdate(CpuDebugger::kIllegalException);
	else
		pState->pc += 4;					//next instruction
}

static void Addr(ExceptionState *pState)
{
	g_debugger.put_string_gdb("ADDR EXCEPTION\n");
	DumpExceptionState(pState);
	DumpAddrBusState(pState);

	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kBusError);
}

static void Bus(ExceptionState *pState)
{
	g_debugger.put_string_gdb("BUS EXCEPTION\n");
	DumpExceptionState(pState);
	DumpAddrBusState(pState);

	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kBusError);
}


extern "C" void _start(void *pLoadPoint)
{
	put_string("in loaded image\n");
	enable_icache(true);
	put_string("instruction cache enabled\n");

	Hooks *pHooks = GetHooks();

	pHooks->EcallFromU = &Trap;
	pHooks->MachTimerInt = &Interrupt;
	
	pHooks->IllegalInst = &Illegal;
	pHooks->Breakpoint = &Illegal;
	
	pHooks->InstAddrMisaligned = &Addr;
	pHooks->InstAddrFault = &Bus;
	
	pHooks->LoadAddrMisaligned = &Addr;
	pHooks->LoadAddrFault = &Bus;
	
	pHooks->StoreAddrMisaligned = &Addr;
	pHooks->StoreAddrFault = &Bus;

	g_vMem.m_inhibitAccess = true;
	g_debugger.Init(&g_cpu, &g_vMem);

	struct FullState
	{
		ExceptionState m_normal;
	} initial;

	for (int count = 0; count < 32; count++)
		initial.m_normal.regs_int[count] = 0;

	initial.m_normal.sp = 0;
	initial.m_normal.pc = 0;
	initial.m_normal.status = 0;			//set mstatus to zero include mpp to "user"

	g_cpu.SetState(&initial.m_normal);

	put_string("first DebuggerUpdate\n");

	g_debugger.DebuggerUpdate(CpuDebugger::kNotRunning);

	int *p = (int *)(&g_userStack[s_userStackSize - 3 * sizeof(long)]);
	p[0] = 0;
	p[1] = 0;
	p[2] = 0;

	put_string("calling user mode\n");

	CallUserModeNoReturn(&elf_entry, 0, &g_userStack[s_userStackSize - 3 * sizeof(long)]);
}

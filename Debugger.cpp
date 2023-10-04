
#define MAX_PACKET_LENGTH 2048

#include "Debugger.h"
#include "uart.h"
#include "misc_asm.h"

#include <string.h>

inline void PRINT_DEBUG( const char*, ... )    {}
inline void PRINT_WARNING( const char*, ... )    {}
inline void PRINT_INFO( const char*, ... )    {}

/* these codes are passed to the debugger */
enum
{
        kSTOP_NOREASON,
        kSTOP_BREAKPOINT,
        kSTOP_INSTR_COUNT,
        kSTOP_STOP_INSTR,
        kSTOP_ILLEGAL_INSTR,
        kSTOP_EXECUTE_DISABLED,
        kSTOP_QUIT,
        kSTOP_IDLE,
};

static void CharToHex(char *pString, unsigned char c)
{
	unsigned int v = c >> 4;
	if (v < 10)
		v += '0';
	else
	{
		v -= 10;
		v += 'a';
	}

	pString[0] = v;

	v = c & 0xf;
	if (v < 10)
		v += '0';
	else
	{
		v -= 10;
		v += 'a';
	}

	pString[1] = v;
	pString[2] = 0;
}

static char *StringToHex(char *pString, unsigned long &rValue)
{
	rValue = 0;
	char c = 0;

	while (1)
	{
		c = *pString++;
		if (c >= '0' && c <= '9')
		{
			c -= '0';
			rValue = rValue << 4;
			rValue = rValue | c;
		}
		else if (c >= 'a' && c <= 'f')
		{
			c -= 'a';
			c += 10;
			rValue = rValue << 4;
			rValue = rValue | c;
		}
		else
		{
			pString--;
			break;
		}
	}

	return pString;
}

static unsigned char StringToHex2c(char *pString)
{
	unsigned char ret = 0;
	char c = 0;

	for (int count = 0; count < 2; count++)
	{
		c = pString[count];

		if (c >= '0' && c <= '9')
		{
			c -= '0';
			ret = ret << 4;
			ret = ret | c;
		}
		else if (c >= 'a' && c <= 'f')
		{
			c -= 'a';
			c += 10;
			ret = ret << 4;
			ret = ret | c;
		}
		else
			break;
	}

	return ret;
}

#ifdef __m68k__

unsigned int &Cpu::GetAx(unsigned int r)
{
	ASSERT(r >= 0 && r < 8);

	if (r == 7)
		return m_pState->usp;
	else
		return m_pState->a[r];
}

unsigned int &Cpu::GetDx(unsigned int r)
{
	ASSERT(r >= 0 && r < 8);

	return m_pState->d[r];
}

unsigned long Cpu::GetSR(void)
{
	return *m_pState->GetSr();
}

void Cpu::SetSR(unsigned long sr)
{
	*m_pState->GetSr() = sr;
}

bool Cpu::IsSupervisorMode(void)
{
	unsigned short sr = *m_pState->GetSr();
	return (sr & (1 << 13)) ? true : false;
}

#elif __riscv

unsigned long &Cpu::GetRx(unsigned int r)
{
	ASSERT(r >= 0 && r < 32);

	if (r == 2)
		return m_pState->sp;

	return m_pState->regs_int[r];
}

bool Cpu::IsSupervisorMode(void)
{
	unsigned long mstatus = *m_pState->GetSr();
	//assuming supervisor = !user
	return ((mstatus >> 11) & 3) != 0;
}

#endif

void Cpu::SetState(ExceptionState *p)
{
	m_pState = p;
}


unsigned long Cpu::GetPC(void)
{
	return *m_pState->GetPc();
}


void Cpu::SetPC(unsigned long pc)
{
	*m_pState->GetPc() = pc;
}

bool VirtualMemory::Write(bool isSupervisor, bool isCode, unsigned long dest, void *pSource, unsigned long size)
{
	ASSERT(!isSupervisor);

	//todo change start point
	if (((dest >= (unsigned long)RAM_BASE) && ((dest + size) <= ((unsigned long)RAM_BASE + (unsigned long)RAM_SIZE)))
#ifdef RAM2_BASE
			|| ((dest >= (unsigned long)RAM2_BASE) && ((dest + size) <= ((unsigned long)RAM2_BASE + (unsigned long)RAM2_SIZE)))
#endif
			|| !m_inhibitAccess)
	{
		memcpy((void *)dest, pSource, size);

		if (isCode)
			invalidate_icache();

		return true;
	}
	else
		return false;
}

bool VirtualMemory::Read(bool isSupervisor, bool isCode, void *pDest, unsigned long source, unsigned long size)
{
	ASSERT(!isSupervisor);

	//todo change start point
	if (((source >= (unsigned long)RAM_BASE) && ((source + size) <= ((unsigned int)RAM_BASE + (unsigned int)RAM_SIZE)))
			|| ((source >= (unsigned long)ROM_BASE) && ((source + size) <= ((unsigned long)ROM_BASE + (unsigned long)ROM_SIZE)))
#ifdef RAM2_BASE
			|| ((source >= (unsigned long)RAM2_BASE) && ((source + size) <= ((unsigned long)RAM2_BASE + (unsigned long)RAM2_SIZE)))
#endif
			|| !m_inhibitAccess)
	{
		memcpy(pDest, (void *)source, size);

		return true;
	}
	else
		return false;
}

void CpuDebugger::Init(Cpu* pCpu, VirtualMemory *pVmem)
{
	PRINT_DEBUG("Initialising debugger...\n");
	m_pCpu = pCpu;
	m_pVmem = pVmem;

	for (int count = 0; count < MAX_BREAKPOINTS; count++)
		m_breakpoints[count].m_address = (unsigned long)-1;
}

void CpuDebugger::DebuggerUpdate(Reason r)
{
	char packet[MAX_PACKET_LENGTH];
	char response[MAX_PACKET_LENGTH];
	char checksum[3];			//two bytes plus one for null

	bool entered_running = false;

	do
	{
		int length;

		if (r != kNotRunning)
		{
			switch (r)
			{
			case kTrapUpdate:
			case kInterruptUpdate:
				//if there's no message, no need to sighup
				if (!PeekData())
					return;

				//there is something
				//but it might just be an ack
				entered_running = true;
				break;
			case kTraceException:
				strcpy(response, "S01");			//sighup
				break;
			case kIllegalException:
				{
					strcpy(response, "S04");			//sigill

					//check if it's a breakpoint
					unsigned long pc = m_pCpu->GetPC();
					for (unsigned int count = 0; count < MAX_BREAKPOINTS; count++)
						if (m_breakpoints[count].m_address == pc)
						{
							strcpy(response, "S05");			//sigtrap
							break;
						}

					break;
				}
			case kDivZero:
				strcpy(response, "S08");			//sigfpe
				break;
			case kBusError:
				strcpy(response, "S0A");			//sigbus
				break;
			default:
				ASSERT(!"unknown signal");
			}

			//not running now - some reason to stop
			r = kNotRunning;

			//there is a packet pending...go back to the top of the do/while and read it
			if (entered_running)
				continue;
		}
		else
		{
			//blocking read of a message
			do
			{
				length = ReadPacket(packet);
				ASSERT(length > 0);

				if (entered_running && packet[0] == '+')
					return;			//if there is more, then we'll get it on the next update call
			}
			while (packet[0] == '+');			//ack...no-one cares

			entered_running = false;		//only get one go

			if (packet[0] < 10)				//ctrl-c etc
				strcpy(response, "S01");
			else if ((packet[0] == 'k') || (strstr(packet, "vKill") == packet))
			{
				SendResponse("OK");		//not sure what to do now
			}
			else
			{
				//an interesting packet
				//do something...read memory, write breakpoint etc, ack a step/continue
				length = HandlePacket(packet, response);

				bool do_continue = strcmp(response, "CONTINUE") == 0;
				bool do_step = strcmp(response, "STEP ONE") == 0;

				if (do_continue)
				{
					SendResponse("+");			//leave function and continue
					invalidate_icache();
#ifdef __m68k__
					//turn off trace mode for a return
					m_pCpu->SetSR(m_pCpu->GetSR() & ~(1 << 15));
#endif
					break;
				}
				else if (do_step)
				{
					SendResponse("+");
					invalidate_icache();
#ifdef __m68k__
					//turn on trace mode
					m_pCpu->SetSR(m_pCpu->GetSR() | (1 << 15));
#endif
					break;
				}

				//fall out and checksum and send response etc
				//and go round again
			}

		}

		length = (int)strlen(response);

		//finish the packet
		ChecksumPacket(response, length, checksum);

		//and send it
		SendResponse("+$");
		SendResponse(response);
		put_char('#');
		SendResponse(checksum);
	} while (r == kNotRunning);
}

void CpuDebugger::ChecksumPacket(char* packet, int length, char* checksum)
{
	int total = 0;

	for (int count = 0; count < length; count++)
		total += (unsigned char)packet[count];

//	sprintf(checksum, "%02x", total % 256);
	CharToHex(checksum, total % 256);
}

void CpuDebugger::SendResponse(const char* response)
{
	put_string(response);
}

int CpuDebugger::PeekData(void)
{
	if (is_data_available())
		return 1;
	else
		return 0;
}

//blocking read of a packet
//either is a single + or - character
//or starts with a $ and finishes with # and two more characters
//returns characters read
int CpuDebugger::ReadPacket(char* buffer)
{
	int count = 0;
	bool hash_encountered = false;
	int checksum_count = 0;

	char recvbuf[MAX_PACKET_LENGTH];

	while (1)
	{
		unsigned char c = get_char();

		recvbuf[count] = c;
		count++;

		if ((count == 1) && ((c == '+') || (c == '-') || (c < 10)))			//drop out immediately
			break;

		if (hash_encountered)
			checksum_count++;

		if (checksum_count == 2)
			break;

		if (c == '#')
			hash_encountered = true;
	}

	//if a single character reply
	if ((count == 1) && (recvbuf[0] < 10))		//not sure what this is about...rogue '3' characters?
	{
		buffer[0] = recvbuf[0];
		buffer[1] = 0;
		return 1;
	}

	int dollar = 0;
	int hash = count;

	for (int i = 0; i < count; i++)
	{
		if (recvbuf[i] == '$')			//look for dollars
			dollar = i + 1;
		if (recvbuf[i] == '#')			//and for hashes
			hash = i;
	}

	int i = 0;
	for (i = 0; i < hash - dollar; i++)
		buffer[i] = recvbuf[dollar + i];

	buffer[i] = 0;

	return count;
}

int CpuDebugger::HandlePacket(char* packet, char* response)
{
	response[0] = 0;

	if (packet[0] == '?')
		strcpy(response, "S01");

	//read all registers
	if (strcmp(packet, "g") == 0)
	{
		PRINT_DEBUG("reading registers\n");
		char *pRegResponse = response;
#ifdef __m68k__
		for (int count = 0; count < 8; count++)
		{
			unsigned int d = m_pCpu->GetDx(count);

			for (int b = 3; b >= 0; b--)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				CharToHex(pRegResponse, c);
				pRegResponse += 2;
			}
		}
		for (int count = 0; count < 8; count++)
		{
			unsigned int d = m_pCpu->GetAx(count);

			for (int b = 3; b >= 0; b--)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				CharToHex(pRegResponse, c);
				pRegResponse += 2;
			}
		}
		//ps - status register
		{
			for (int b = 3; b >= 0; b--)
			{
				unsigned int sr = m_pCpu->GetSR();
				unsigned char c = (sr >> (b * 8)) & 0xff;

				CharToHex(pRegResponse, c);
				pRegResponse += 2;
			}
		}
		//pc
		{
			unsigned int d = m_pCpu->GetPC();

			for (int b = 3; b >= 0; b--)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				CharToHex(pRegResponse, c);
				pRegResponse += 2;
			}
		}
		//fp registers
		/*for (int count = 0; count < 8; count++)
		{
			FpxStorage fp;
			m_pCpu->GetFpxAs96bBE(count, &fp);

			for (int b = 0; b < 12; b++)
			{
				sprintf(pRegResponse, "%02x", fp.bytes[b]);
				pRegResponse += 2;
			}
		}
		//fp control, it wants 4 bytes but it's only 2 bytes in size
		{
			unsigned int d = m_pCpu->GetFpcr();

			for (int b = 3; b >= 0; b--)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				sprintf(pRegResponse, "%02x", c);
				pRegResponse += 2;
			}
		}
		//fp status
		{
			unsigned int d = m_pCpu->GetFpsr();

			for (int b = 3; b >= 0; b--)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				sprintf(pRegResponse, "%02x", c);
				pRegResponse += 2;
			}
		}
		//fp iar
		{
			unsigned int d = m_pCpu->GetFpiar();

			for (int b = 3; b >= 0; b--)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				sprintf(pRegResponse, "%02x", c);
				pRegResponse += 2;
			}
		}*/
#elif __riscv
		for (int count = 0; count < 32; count++)
		{
			unsigned int d = m_pCpu->GetRx(count);

			for (unsigned int b = 0; b < sizeof(long); b++)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				CharToHex(pRegResponse, c);
				pRegResponse += 2;
			}
		}
		//pc
		{
			unsigned long d = m_pCpu->GetPC();

			for (unsigned int b = 0; b < sizeof(long); b++)
			{
				unsigned char c = (d >> (b * 8)) & 0xff;

				CharToHex(pRegResponse, c);
				pRegResponse += 2;
			}
		}
#endif
	}

	//read memory
	if (packet[0] == 'm')
	{
		unsigned long read_address, read_length;
		StringToHex(StringToHex(packet + 1, read_address) + 1, read_length);		//hopefully no 0x

		PRINT_DEBUG("reading %d bytes from %08x\n", read_length, read_address);

		{
			bool failure = false;

			for (unsigned long count = 0; count < read_length; count++)
			{
				unsigned char b;

				if (!m_pVmem->Read(m_pCpu->IsSupervisorMode(), false, &b, read_address + count, 1))
				{
					failure = true;
					break;
				}

				CharToHex(response + count * 2, b);
			}

			if (failure)
				strcpy(response, "E00");
		}
	}

	//write memory
	if (packet[0] == 'M')
	{
		char* colon = strchr(packet, ':');
		unsigned long write_address, write_length;
		StringToHex(StringToHex(packet + 1, write_address) + 1, write_length);

		PRINT_DEBUG("writing %d bytes to %08x\n", write_length, write_address);

		bool failure = false;

		{
			for (unsigned long count = 0; count < write_length; count++)
			{
				unsigned int data_i;
				data_i = StringToHex2c(colon + 1 + count * 2);

				unsigned char b = data_i;

				if (!m_pVmem->Write(m_pCpu->IsSupervisorMode(), false, write_address + count, &b, 1))
				{
					failure = true;
					break;
				}
			}
		}

		if (failure)
			strcpy(response, "E00");
		else
			strcpy(response, "OK");
	}

	//write memory (binary)
	if (packet[0] == 'X')
	{
		char* colon = strchr(packet, ':');
		unsigned long write_address, write_length;
		StringToHex(StringToHex(packet + 1, write_address) + 1, write_length);

		PRINT_DEBUG("binary writing %d bytes to %08x\n", write_length, write_address);

		bool failure = false;
		bool control = false;
		unsigned int read_pos = 0;

		{
			for (unsigned long count = 0; count < write_length; /* */)
			{
				unsigned int data_i;
				data_i = colon[1 + read_pos++];		//advance read position

				unsigned char b = data_i;

				//The binary data representation uses 7d (ASCII ‘}’) as an escape character. Any escaped byte is transmitted as the escape character followed by the original character XORed with 0x20.
				if (b == 0x7d)
				{
					control = true;
					continue;
				}

				if (control)
				{
					b = b ^ 0x20;
					control = false;
				}

				if (!m_pVmem->Write(m_pCpu->IsSupervisorMode(), false, write_address + count, &b, 1))
				{
					failure = true;
					break;
				}

				//character written - move to next dest byte
				count++;
			}
		}

		if (failure)
			strcpy(response, "E00");
		else
			strcpy(response, "OK");
	}

	//set register
	if (packet[0] == 'P')
	{
		int reg;
		unsigned long b1, b2, b3, b4;
#if __riscv_xlen == 64
		unsigned long b5, b6, b7, b8;
#endif
		unsigned long val;
		reg = StringToHex2c(packet + 1);

		//find the = character...will be either byte 2 or 3
		unsigned int equals;
		if (packet[2] == '=')
			equals = 2;
		else if (packet[3] == '=')
			equals = 3;
		else
			ASSERT(!"= is not where we expect it");

		b1 = StringToHex2c(packet + equals + 1);
		b2 = StringToHex2c(packet + equals + 3);
		b3 = StringToHex2c(packet + equals + 5);
		b4 = StringToHex2c(packet + equals + 7);

#ifdef __m68k__
		val = b4 | (b3 << 8) | (b2 << 16) | (b1 << 24);
#elif __riscv

#if __riscv_xlen == 32
		val = b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
#elif __riscv_xlen == 64
		val = b1 | (b2 << 8) | (b3 << 16) | (b4 << 24)
			 | (b5 << 32) | (b6 << 40) | (b7 << 48) | (b8 << 56);
#else
#error unexpected xlen
#endif
#endif
#ifdef __m68k__
		if (reg == 17)
		{
			PRINT_DEBUG("setting PC to %08x\n", val);
			m_pCpu->SetPC(val);

			strcpy(response, "OK");
		}
		else if (reg == 16)
		{
			PRINT_DEBUG("setting SR to %08x\n", val);
			m_pCpu->SetSR(val);

			strcpy(response, "OK");
		}
		else if (reg < 8)
		{
			PRINT_DEBUG("setting register D%d to 32-bit value\n", reg);
			strcpy(response, "OK");

			m_pCpu->GetDx(reg) = val;
		}
		else if (reg >= 8 && reg < 16)
		{
			PRINT_DEBUG("setting register A%d to 32-bit value\n", reg - 8);
			strcpy(response, "OK");

			m_pCpu->GetAx(reg - 8) = val;
		}
#elif __riscv
		if (reg == 32)
		{
			PRINT_DEBUG("setting PC to %x\n", val);
			m_pCpu->SetPC(val);
			strcpy(response, "OK");
		}
		else if (reg < 32)
		{
			PRINT_DEBUG("setting register D%d to value\n", reg);
			strcpy(response, "OK");

			m_pCpu->GetRx(reg) = val;
		}
#endif
		else
			PRINT_WARNING("unknown register write, %d\n", reg);
	}

	//continue
	if ((strcmp(packet, "C01") == 0) || packet[0] == 'c')
	{
		strcpy(response, "CONTINUE");
	}

	//step
	if (strcmp(packet, "S01") == 0 || strcmp(packet, "s") == 0)
	{
		strcpy(response, "STEP ONE");
	}

	//set breakpoint
	if (strstr(packet, "Z0") == packet)
	{
		unsigned long addr;
		StringToHex(packet + 3, addr);

		PRINT_DEBUG("set breakpoint at %08x\n", addr);

		if (SetBreakpoint(addr))
			strcpy(response, "OK");
		else
		{
			PRINT_WARNING("couldn\'t set breakpoint\n");
			strcpy(response, "E00");
		}
	}

	//remove breakpoint
	if (strstr(packet, "z0") == packet)
	{
		unsigned long addr;
		StringToHex(packet + 3, addr);

		PRINT_DEBUG("clear breakpoint at %08x\n", addr);

		if (ClearBreakpoint(addr))
			strcpy(response, "OK");
		else
		{
			PRINT_WARNING("couldn\'t clear breakpoint\n");
			strcpy(response, "E00");
		}
	}

	//end and close
	if (strstr(packet, "vKill") == packet)
		strcpy(response, "OK");

	return (int)strlen(response);
}

bool CpuDebugger::SetBreakpoint(unsigned long addr)
{
	int slot = -1;
#ifdef __m68k__
	const int length = 2;
	static const unsigned int new_inst = 0b0100100001001000;
#elif __riscv
	const int length = 4;
	static const unsigned int new_inst = 0b00000000000100000000000001110011;
#endif
	//check it's not been set already
	for (int count = 0; count < MAX_BREAKPOINTS; count++)
		if (m_breakpoints[count].m_address == addr)
			return false;

	//find a blank spot
	for (int count = 0; count < MAX_BREAKPOINTS; count++)
		if (m_breakpoints[count].m_address == (unsigned long)-1)
		{
			slot = count;
			break;
		}

	if (slot == -1)
		return false;

	//read the instruction
	unsigned int orig = 0;
	if (m_pVmem->Read(false, true, &orig, addr, length))
	{
		unsigned int n = new_inst;
		if (m_pVmem->Write(false, true, addr, &n, length))
		{
			m_breakpoints[slot].m_address = addr;
			m_breakpoints[slot].m_origInstruction = orig;

			invalidate_icache();
			return true;
		}
	}

	return false;
}

bool CpuDebugger::ClearBreakpoint(unsigned long addr)
{
	int slot = -1;
#ifdef __m68k__
	const int length = 2;
#elif __riscv
	const int length = 4;
#endif
	for (int count = 0; count < MAX_BREAKPOINTS; count++)
		if (m_breakpoints[count].m_address == addr)
		{
			slot = count;
			break;
		}

	if (slot == -1)
		return false;
	if (m_pVmem->Write(false, true, addr, &m_breakpoints[slot].m_origInstruction, length))
	{
		m_breakpoints[slot].m_address = (unsigned long)-1;
		return true;
	}
	else
		return false;
}

int CpuDebugger::NumBreakpoints(void)
{
	int num = 0;

	for (int count = 0; count < MAX_BREAKPOINTS; count++)
		if (m_breakpoints[count].m_address != (unsigned long) -1)
			num++;

	return num;
}

////////////////////
void CpuDebugger::put_char_gdb(char c)
{
	char message[4];				//inc 'O'
	char checksum[3];

	message[0] = 'O';
	CharToHex(message + 1, c);
	ChecksumPacket(message, 3, checksum);

	SendResponse("+$");
	SendResponse(message);
	SendResponse("#");
	SendResponse(checksum);
}

void CpuDebugger::put_hex_num_gdb(unsigned int n)
{
	for (int count = 7; count >= 0; count--)
	{
		unsigned int val = (n >> (count * 4)) & 0xf;
		if (val < 10)
			put_char_gdb('0' + val);
		else
			put_char_gdb('a' + val - 10);
	}
}

void CpuDebugger::put_hex_byte_gdb(unsigned char n)
{
	for (int count = 1; count >= 0; count--)
	{
		unsigned int val = (n >> (count * 4)) & 0xf;
		if (val < 10)
			put_char_gdb('0' + val);
		else
			put_char_gdb('a' + val - 10);
	}
}

void CpuDebugger::put_dec_short_num_gdb(unsigned short i, bool leading)
{
	if (!leading && i == 0)
		put_char_gdb('0');

	bool has_printed = leading;
	for (short count = 4; count >= 0; count--)
	{
		unsigned short divide_by = 1;
		for (short inner = 0; inner < count; inner++)
			divide_by *= 10;

		unsigned short div = i / divide_by;
		i = i % divide_by;

		if (div || has_printed)
		{
			has_printed = true;
			put_char_gdb(div + '0');
		}
	}
}

void CpuDebugger::put_string_gdb(const char *p)
{
	while (*p)
		put_char_gdb(*p++);
}



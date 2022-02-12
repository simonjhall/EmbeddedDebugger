#ifndef DEBUGGER_H_
#define DEBUGGER_H_

#include "inter_process.h"

#ifdef __m68k__
class Cpu
{
public:
	void SetState(ExceptionState *pState);

	unsigned int &GetAx(unsigned int r);
	unsigned int &GetDx(unsigned int r);
	unsigned long GetSR(void);
	unsigned long GetPC(void);

	void SetSR(unsigned long);
	void SetPC(unsigned long);

	bool IsSupervisorMode(void);

private:
	ExceptionState *m_pState;
};

#elif __riscv

class Cpu
{
public:
	void SetState(ExceptionState *pState);

	unsigned long &GetRx(unsigned int r);
	unsigned long GetSR(void);
	unsigned long GetPC(void);

	void SetSR(unsigned long);
	void SetPC(unsigned long);

	bool IsSupervisorMode(void);

private:
	ExceptionState *m_pState;
};

#endif


class VirtualMemory
{
public:
	bool Write(bool isSupervisor, bool isCode, unsigned long dest, void *pSource, unsigned long size);
	bool Read(bool isSupervisor, bool isCode, void *pDest, unsigned long source, unsigned long size);

	bool m_inhibitAccess;
};

//increase this if you want more breakpoints
#define MAX_BREAKPOINTS 20

class CpuDebugger
{
public:
	//make a debugger and pass it our CPU
	void Init(Cpu* pCpu, VirtualMemory *pVmem);
	
	enum Reason
	{
		kNotRunning,
		kTrapUpdate,
		kInterruptUpdate,
		kTraceException,
		kIllegalException,
		kDivZero,
		kBusError,
	};
	void DebuggerUpdate(Reason);
	
	////////////////////
	void put_char_gdb(char c);
	void put_hex_num_gdb(unsigned int n);
	void put_hex_byte_gdb(unsigned char n);
	void put_dec_short_num_gdb(unsigned short i, bool leading);
	void put_string_gdb(const char *p);

private:
	Cpu *m_pCpu;
	VirtualMemory *m_pVmem;
	
	int ReadPacket(char* buffer);
	int HandlePacket(char* packet, char* response);
	void SendResponse(const char* response);
	int PeekData(void);
	void ChecksumPacket(char* packet, int length, char* checksum);

	bool SetBreakpoint(unsigned long addr);
	bool ClearBreakpoint(unsigned long addr);
	int NumBreakpoints(void);
	
	struct Breakpoint
	{
		unsigned long m_address;
		unsigned int m_origInstruction;
	} m_breakpoints[MAX_BREAKPOINTS];
};

#endif /*DEBUGGER_H_*/

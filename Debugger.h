#ifndef DEBUGGER_H_
#define DEBUGGER_H_

#include "inter_process.h"

class Cpu
{
public:
	void SetState(ExceptionState *pState);

	unsigned int &GetAx(unsigned int r);
	unsigned int &GetDx(unsigned int r);
	unsigned int GetSR(void);
	unsigned int GetPC(void);

	void SetSR(unsigned int);
	void SetPC(unsigned int);

	bool IsSupervisorMode(void);

private:
	ExceptionState *m_pState;
};

class VirtualMemory
{
public:
	bool Write(bool isSupervisor, bool isCode, unsigned int dest, void *pSource, unsigned int size);
	bool Read(bool isSupervisor, bool isCode, void *pDest, unsigned int source, unsigned int size);
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

	bool SetBreakpoint(unsigned int addr);
	bool ClearBreakpoint(unsigned int addr);
	int NumBreakpoints(void);
	
	struct Breakpoint
	{
		unsigned int m_address;
		unsigned short m_origInstruction;
	} m_breakpoints[MAX_BREAKPOINTS];
};

#endif /*DEBUGGER_H_*/

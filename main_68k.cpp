/*
 * main.cpp
 *
 *  Created on: 29 Aug 2018
 *      Author: simon
 */

#include "uart.h"
#include "misc_asm.h"
#include "inter_process.h"
#include "Debugger.h"

static const unsigned int s_userStackSize = 6 * 1024;
unsigned char g_userStack[s_userStackSize];


//////////

void func_in_user_mode(void)
{
	put_string_user("in user mode\n");

	while (1)
		trap0(DEBUGGER_UPDATE);
}

//////////

static Cpu g_cpu;
static VirtualMemory g_vMem;
static CpuDebugger g_debugger;

static bool Trap(ExceptionState *pState)
{
	unsigned long call, a0, a1;
_
	call = pState->d[0];
	a0 = pState->d[1];
	a1 = pState->d[2];

	switch (call)
	{
	case TRAP_PRINT_CHAR:
		g_debugger.put_char_gdb(a0);
		break;
	case TRAP_PRINT_HEX_NUM:
		g_debugger.put_hex_num_gdb(a0);
		break;
	case TRAP_PRINT_HEX_BYTE:
		g_debugger.put_hex_byte_gdb(a0);
		break;
	case TRAP_PRINT_DEC_SHORT_NUM:
		g_debugger.put_dec_short_num_gdb(a0, a1);
		break;
	case TRAP_PRINT_STRING:
		g_debugger.put_string_gdb((char *)a0);
		break;
	case DEBUGGER_UPDATE:
		g_cpu.SetState(pState);
		g_debugger.DebuggerUpdate(CpuDebugger::kTrapUpdate);
		break;
	default:
		return false;
		break;
	}

	return true;
}

static void DumpAddrBusState(ExceptionState *pState)
{
	unsigned short *pOurState = (unsigned short *)pState;
	g_debugger.put_string_gdb("function code\t\t"); g_debugger.put_hex_num_gdb(pOurState[32] & 7); g_debugger.put_char_gdb('\n');

	if (pOurState[32] & 8)
		g_debugger.put_string_gdb("instruction\n");
	else
		g_debugger.put_string_gdb("not instruction\n");

	if (pOurState[32] & 16)
		g_debugger.put_string_gdb("read\n");
	else
		g_debugger.put_string_gdb("write\n");

	g_debugger.put_string_gdb("access addr\t\t"); g_debugger.put_hex_num_gdb((pOurState[33] << 16) | pOurState[34]); g_debugger.put_char_gdb('\n');
	g_debugger.put_string_gdb("instruction reg\t\t"); g_debugger.put_hex_num_gdb(pOurState[35]); g_debugger.put_char_gdb('\n');
}

static void DumpExceptionState(ExceptionState *pState)
{
	unsigned int *pOurState = (unsigned int *)pState;

	g_debugger.put_string_gdb("our state\n");

	for (unsigned int count = 0; count < 16; count++)
	{
		g_debugger.put_hex_num_gdb(pOurState[count]);
		g_debugger.put_char_gdb('\n');

		for (volatile int i = 0; i < 1000; i++);
	}

	g_debugger.put_string_gdb("cpu state\n");

	for (unsigned int count = 16; count < 16 + 4; count++)
	{
		g_debugger.put_hex_num_gdb(pOurState[count]);
		g_debugger.put_char_gdb('\n');

		for (volatile int i = 0; i < 1000; i++);
	}
}

static void Trace(ExceptionState *pState)
{
	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kTraceException);
}

static void Interrupt(ExceptionState *pState)
{
	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kInterruptUpdate);
}

static void Illegal(ExceptionState *pState)
{
	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kIllegalException);
}

static void DivZero(ExceptionState *pState)
{
	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kDivZero);
}

//not sure what to do here
static void Misc(ExceptionState *pState)
{
	g_debugger.put_string_gdb("MISC EXCEPTION\n");
	DumpExceptionState(pState);

	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kIllegalException);
}

static void Addr(ExceptionState *pState)
{
	g_debugger.put_string_gdb("ADDR EXCEPTION\n");
	DumpExceptionState(pState);
	DumpAddrBusState(pState);

	//move the state to where we expect it
	*pState->GetSr() = *pState->GetGroup0Sr();
	*pState->GetPc() = *pState->GetGroup0Pc();

	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kBusError);
}

static void Bus(ExceptionState *pState)
{
	g_debugger.put_string_gdb("BUS EXCEPTION\n");
	DumpExceptionState(pState);
	DumpAddrBusState(pState);

	//move the state to where we expect it
	*pState->GetSr() = *pState->GetGroup0Sr();
	*pState->GetPc() = *pState->GetGroup0Pc();

	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kBusError);
}

extern "C" void _start(void *pLoadPoint)
{
	put_string("in loaded image\n");
	enable_icache(true);
	put_string("instruction cache enabled\n");

	Hooks *pHooks = GetHooks();

	pHooks->Trap = &Trap;
	pHooks->Trace = &Trace;
	pHooks->Auto1 = &Interrupt;
	pHooks->IllegalInst = &Illegal;
	pHooks->DivZero = &DivZero;

	//not sure
	pHooks->MiscTrap = &Misc;
	pHooks->AddrError = &Addr;
	pHooks->BusError = &Bus;

	g_vMem.m_inhibitAccess = true;
	g_debugger.Init(&g_cpu, &g_vMem);

	struct FullState
	{
		ExceptionState m_normal;
		unsigned short m_sr;
		unsigned int m_pc;
	} initial;

	static_assert(sizeof(initial) == (sizeof(ExceptionState) + 6), "size change");

	for (int count = 0; count < 8; count++)
		initial.m_normal.d[count] = 0;
	for (int count = 0; count < 7; count++)
		initial.m_normal.a[count] = 0;

	initial.m_normal.usp = 0;
	initial.m_sr = 0;
	initial.m_pc = 0;

	g_cpu.SetState(&initial.m_normal);

	put_string("first DebuggerUpdate\n");

	g_debugger.DebuggerUpdate(CpuDebugger::kNotRunning);

	int *p = (int *)(&g_userStack[s_userStackSize - 12]);
	p[0] = 0;
	p[1] = 0;
	p[2] = 0;

	put_string("calling user mode\n");

	CallUserModeNoReturn(&func_in_user_mode, read_sr() & ~(1 << 13), &g_userStack[s_userStackSize - 12]);
}

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

static const unsigned int s_userStackSize = 4096;
unsigned char g_userStack[s_userStackSize];

//////////////

static void DebuggerUpdate_User(void)
{
	trap0(DEBUGGER_UPDATE);
}

//////////

static int f(int n)
{
	DebuggerUpdate_User();

	if ( n == 0 )
		return 0;
	else if ( n == 1 )
		return 1;
	else
		return ( f(n-1) + f(n-2) );
}

static const int max_fib = 0x30;

static void do_fib(void)
{
	int n, i = 0, c;

	n = max_fib;

	for ( c = 1 ; c <= n ; c++ )
	{
		put_hex_num_user(c);
		put_char_user(' ');
		put_hex_num_user(f(i));
		i++;

		put_char_user('\n');
	}
}

void func_in_user_mode(void)
{
	put_string_user("in user mode\n");

//	do_fib();

	while (1)
		trap0(DEBUGGER_UPDATE);
}

//////////



static Cpu g_cpu;
static VirtualMemory g_vMem;
static CpuDebugger g_debugger;

static bool Trap(ExceptionState *pState)
{
	switch (pState->d[0])
	{
	case TRAP_PRINT_CHAR:
		g_debugger.put_char_gdb(pState->d[1]);
		break;
	case TRAP_PRINT_HEX_NUM:
		g_debugger.put_hex_num_gdb(pState->d[1]);
		break;
	case TRAP_PRINT_HEX_BYTE:
		g_debugger.put_hex_byte_gdb(pState->d[1]);
		break;
	case TRAP_PRINT_DEC_SHORT_NUM:
		g_debugger.put_dec_short_num_gdb(pState->d[1], pState->d[2]);
		break;
	case TRAP_PRINT_STRING:
		g_debugger.put_string_gdb((char *)pState->d[1]);
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

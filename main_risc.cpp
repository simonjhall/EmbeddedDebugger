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

static void Trap(ExceptionState *pState)
{
	unsigned long call, a0, a1;

	call = pState->regs_int[16];
	a0 = pState->regs_int[10];
	a1 = pState->regs_int[11];

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
		pState->regs_int[10] = 0;
		break;
	}

	pState->regs_int[10] = 1;			//error = true
	pState->regs_int[11] = 0;			//value
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

static void Illegal(ExceptionState *pState)
{
	g_cpu.SetState(pState);
	g_debugger.DebuggerUpdate(CpuDebugger::kIllegalException);
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
		unsigned long m_pc;
	} initial;

	for (int count = 0; count < 32; count++)
		initial.m_normal.regs_int[count] = 0;

	initial.m_normal.sp = 0;
	initial.m_pc = 0;

	g_cpu.SetState(&initial.m_normal);

	put_string("first DebuggerUpdate\n");

	g_debugger.DebuggerUpdate(CpuDebugger::kNotRunning);

	int *p = (int *)(&g_userStack[s_userStackSize - 3 * sizeof(long)]);
	p[0] = 0;
	p[1] = 0;
	p[2] = 0;

	put_string("calling user mode\n");

	CallUserModeNoReturn(&func_in_user_mode, 0, &g_userStack[s_userStackSize - 3 * sizeof(long)]);
}

#include <exec/execbase.h>
#include <exec/memory.h>
#include <exec/semaphores.h>
#include <exec/resident.h>
#include <exec/io.h>
#include <dos/dosextens.h>
#include <dos/dos.h>
#include <stdio.h>
#include <stddef.h>
#define O(s,f) printf("\t%s_%s = %d\n", #s, #f, (int)offsetof(struct s,f))
#define S(s) printf("\tSizeof%s = %d\n", #s, (int)sizeof(struct s))
int main(void){
 printf("// Code generated from the NDK 3.2 headers by tools/offsets; DO NOT EDIT.\n\npackage amiga\n\nconst (\n");
 O(Node,ln_Succ);O(Node,ln_Pred);O(Node,ln_Type);O(Node,ln_Pri);O(Node,ln_Name);S(Node);
 O(List,lh_Head);O(List,lh_Tail);O(List,lh_TailPred);O(List,lh_Type);S(List);
 O(Library,lib_Flags);O(Library,lib_NegSize);O(Library,lib_PosSize);O(Library,lib_Version);O(Library,lib_Revision);O(Library,lib_IdString);O(Library,lib_Sum);O(Library,lib_OpenCnt);S(Library);
 O(ExecBase,SoftVer);O(ExecBase,ThisTask);O(ExecBase,IDNestCnt);O(ExecBase,TDNestCnt);O(ExecBase,AttnFlags);O(ExecBase,MemList);O(ExecBase,ResourceList);O(ExecBase,DeviceList);O(ExecBase,IntrList);O(ExecBase,LibList);O(ExecBase,PortList);O(ExecBase,TaskReady);O(ExecBase,TaskWait);O(ExecBase,SemaphoreList);O(ExecBase,VBlankFrequency);O(ExecBase,PowerSupplyFrequency);O(ExecBase,ex_EClockFrequency);O(ExecBase,ResModules);O(ExecBase,KickTagPtr);S(ExecBase);
 O(MemHeader,mh_Attributes);O(MemHeader,mh_First);O(MemHeader,mh_Lower);O(MemHeader,mh_Upper);O(MemHeader,mh_Free);S(MemHeader);
 O(MemChunk,mc_Next);O(MemChunk,mc_Bytes);S(MemChunk);
 O(SignalSemaphore,ss_NestCount);O(SignalSemaphore,ss_Owner);O(SignalSemaphore,ss_QueueCount);S(SignalSemaphore);
 O(Task,tc_Flags);O(Task,tc_State);O(Task,tc_SigAlloc);O(Task,tc_SigWait);O(Task,tc_SigRecvd);O(Task,tc_SPLower);O(Task,tc_SPUpper);O(Task,tc_SPReg);S(Task);
 O(Process,pr_MsgPort);O(Process,pr_CurrentDir);O(Process,pr_Result2);O(Process,pr_WindowPtr);O(Process,pr_CLI);S(Process);
 O(Resident,rt_MatchWord);O(Resident,rt_MatchTag);O(Resident,rt_EndSkip);O(Resident,rt_Flags);O(Resident,rt_Version);O(Resident,rt_Type);O(Resident,rt_Pri);O(Resident,rt_Name);O(Resident,rt_IdString);O(Resident,rt_Init);S(Resident);
 O(IORequest,io_Device);O(IORequest,io_Unit);O(IORequest,io_Command);O(IORequest,io_Flags);O(IORequest,io_Error);S(IORequest);
 O(FileInfoBlock,fib_DiskKey);O(FileInfoBlock,fib_DirEntryType);O(FileInfoBlock,fib_FileName);O(FileInfoBlock,fib_Protection);O(FileInfoBlock,fib_EntryType);O(FileInfoBlock,fib_Size);O(FileInfoBlock,fib_NumBlocks);O(FileInfoBlock,fib_Date);O(FileInfoBlock,fib_Comment);S(FileInfoBlock);
 printf(")\n");
 return 0;
}

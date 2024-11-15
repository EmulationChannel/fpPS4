unit game_run;

{$mode ObjFPC}{$H+}

interface

uses
 windows,
 Classes,
 SysUtils,
 CharStream,
 Dialogs,
 kern_thr,
 md_sleep,
 md_pipe,
 host_ipc,
 host_ipc_interface,
 md_host_ipc,
 game_info;

type
 TGameRunConfig=record
  hOutput:THandle;
  hError :THandle;

  FConfInfo:TConfigInfo;
  FGameItem:TGameItem;
 end;

 TGameProcessSimple=class(TGameProcess)
  Ftd:p_kthread;
  procedure  suspend; override;
  procedure  resume;  override;
  Destructor Destroy; override;
 end;

function run_item(const cfg:TGameRunConfig):TGameProcess;

implementation

uses
 sys_sysinit,
 kern_param,
 kern_exec,
 vfs_mountroot,
 sys_crt, //<- init writeln redirect
 sys_tty,
 md_exception, //<- install custom

 sys_event,

 kern_proc,
 md_systm,

 md_game_process,

 kern_jit,
 kern_jit_ctx,

 dev_dce,
 display_soft,

 time,
 pm4_me,

 vDevice,

 //internal libs
 ps4_libSceDiscMap,
 ps4_libSceSystemService,
 ps4_libSceUserService,
 ps4_libSceAppContent,
 ps4_libSceIpmi,
 ps4_libSceMbus,
 ps4_libSceDialogs,
 ps4_libSceAvSetting,
 ps4_libSceNpCommon,
 ps4_libSceNpManager,
 ps4_libSceNpTrophy,
 ps4_libSceNpScoreRanking,
 ps4_libSceNpUtility,
 ps4_libSceNpTus,
 ps4_libSceNpGameIntent,
 ps4_libSceNpWebApi,
 ps4_libSceNpWebApi2,
 ps4_libSceScreenShot,
 ps4_libSceSaveData,
 ps4_libSceAudioOut,
 ps4_libSceAudioIn,
 ps4_libSceNetCtl,
 ps4_libSceGameLiveStreaming,
 ps4_libSceVideoRecording,
 ps4_libSceIme,
 ps4_libSceMove,
 ps4_libSceSharePlay,
 ps4_libScePlayGo,
 ps4_libSceAjm,
 //internal libs

 kern_rtld,
 kern_budget,
 kern_authinfo,
 sys_bootparam,
 subr_backtrace;

//

procedure TGameProcessSimple.suspend;
begin
 thread_suspend_all(nil);
end;

procedure TGameProcessSimple.resume;
begin
 thread_resume_all(nil);
end;

Destructor TGameProcessSimple.Destroy;
begin
 thread_dec_ref(Ftd);
 inherited;
end;

procedure re_init_tty; register;
var
 i:Integer;
begin
 For i:=0 to High(std_tty) do
 begin
  //std_tty[i].t_rd_handle:=GetStdHandle(STD_INPUT_HANDLE);
  //std_tty[i].t_wr_handle:=t_wr_handle;
  //std_tty[i].t_update   :=@WakeMainThread;
 end;

 For i:=0 to High(deci_tty) do
 begin
  //deci_tty[i].t_rd_handle:=GetStdHandle(STD_INPUT_HANDLE);
  //deci_tty[i].t_wr_handle:=t_wr_handle;
  //deci_tty[i].t_update   :=@WakeMainThread;
 end;

 //debug_tty.t_wr_handle:=t_wr_handle;
 //debug_tty.t_update   :=@WakeMainThread;
end;

procedure load_config(ConfInfo:TConfigInfo);
begin
 sys_bootparam.set_neo_mode(ConfInfo.BootParamInfo.Neo);

 sys_bootparam.p_halt_on_exit       :=ConfInfo.BootParamInfo.halt_on_exit;
 sys_bootparam.p_print_guest_syscall:=ConfInfo.BootParamInfo.print_guest_syscall;
 sys_bootparam.p_print_pmap         :=ConfInfo.BootParamInfo.print_pmap;
 sys_bootparam.p_print_jit_preload  :=ConfInfo.BootParamInfo.print_jit_preload;
 sys_bootparam.p_print_gpu_ops      :=ConfInfo.BootParamInfo.print_gpu_ops;
 sys_bootparam.p_print_gpu_hint     :=ConfInfo.BootParamInfo.print_gpu_hint;

 //

 kern_jit.print_asm :=ConfInfo.JITInfo.print_asm;
 kern_jit.debug_info:=ConfInfo.JITInfo.debug_info;

 kern_jit_ctx.jit_relative_analize:=ConfInfo.JITInfo.relative_analize;
 kern_jit_ctx.jit_memory_guard    :=ConfInfo.JITInfo.memory_guard;

 //

 time.strict_ps4_freq        :=ConfInfo.MiscInfo.strict_ps4_freq;
 pm4_me.use_renderdoc_capture:=ConfInfo.MiscInfo.renderdoc_capture;

 //

 vDevice.VulkanDeviceGuid:=Default(TGUID);
 TryStringToGUID(ConfInfo.VulkanInfo.device,vDevice.VulkanDeviceGuid);

 vDevice.VulkanAppFlags:=t_vulkan_app_flags(ConfInfo.VulkanInfo.app_flags);
end;

procedure prepare(GameStartupInfo:TGameStartupInfo); SysV_ABI_CDecl;
var
 td:p_kthread;
 err:Integer;
 len:Integer;
 exec:array[0..PATH_MAX] of Char;
 argv:array[0..1] of PChar;
 Item:TGameItem;
begin
 //re_init_tty;
 //init_tty:=@re_init_tty;

 load_config(GameStartupInfo.FConfInfo);

 //init all
 sys_init;

 if (p_host_ipc<>nil) then
 begin
  THostIpcConnect(p_host_ipc).thread_new;
 end;

 //p_cpuid        :=CPUID_NEO_MODE;
 //p_base_ps4_mode:=0;
 //p_neomode      :=1;

 dev_dce.dce_interface:=display_soft.TDisplayHandleSoft;

 Item:=GameStartupInfo.FGameItem;

 g_appinfo.mmap_flags:=1; //is_big_app ???
 g_appinfo.CUSANAME:=Item.FGameInfo.TitleId;
 //g_appinfo.hasParamSfo
 //g_appinfo.debug_level:=1;

 //budget init
 p_proc.p_budget_ptype:=PTYPE_BIG_APP;

 kern_app_state_change(as_start);
 kern_app_state_change(as_begin_game_app_mount);

 kern_reserve_2mb_page(0,M2MB_DEFAULT);
 ///

 Writeln(Item.FGameInfo.Name   );
 Writeln(Item.FGameInfo.TitleId);
 Writeln(Item.FGameInfo.Version);
 Writeln(Item.FGameInfo.Exec   );

 Writeln(Item.FMountList.app0);
 Writeln(Item.FMountList.system);
 Writeln(Item.FMountList.data);



                       //fs  guest     host
 err:=vfs_mount_mkdir('ufs','/app0'  ,pchar(Item.FMountList.app0  ),nil,0);
 if (err<>0) then
 begin
  print_error_td('error mount "'+Item.FMountList.app0+'" to "/app0" code='+IntToStr(err));
 end;

 err:=vfs_mount_mkdir('ufs','/system',pchar(Item.FMountList.system),nil,0);
 if (err<>0) then
 begin
  print_error_td('error mount "'+Item.FMountList.system+'" to "/system" code='+IntToStr(err));
 end;

 err:=vfs_mount_mkdir('ufs','/data'  ,pchar(Item.FMountList.data  ),nil,0);
 if (err<>0) then
 begin
  print_error_td('error mount "'+Item.FMountList.data+'" to "/data" code='+IntToStr(err));
 end;

 ///argv
 FillChar(exec,SizeOf(exec),0);

 len:=Length(Item.FGameInfo.Exec);
 if (len>PATH_MAX) then len:=PATH_MAX;

 Move(pchar(Item.FGameInfo.Exec)^,exec,len);

 argv[0]:=@exec;
 argv[1]:=nil;
 ///argv

 //unset sys mark
 td:=curkthread;
 td^.td_pflags:=td^.td_pflags and (not TDP_KTHREAD);

 Writeln('main_thread:',HexStr(td));

 //
 FreeAndNil(GameStartupInfo);
 //

 err:=main_execve(argv[0],@argv[0],nil);
 if (err<>0) then
 begin
  print_error_td('error execve "'+exec+'" code='+IntToStr(err));
 end;
 //

end;

{
function NtTerminateProcessTrap(ProcessHandle:THANDLE;ExitStatus:DWORD):DWORD; MS_ABI_Default;
begin
 Result:=0;
 Writeln(stderr,'NtTerminateProcess:0x',HexStr(ExitStatus,8));
 print_backtrace(StdErr,Get_pc_addr,get_frame,0);
 print_backtrace_td(StdErr);
 asm
  mov ProcessHandle,%R10
  mov ExitStatus   ,%EDX
  mov $0x2c        ,%EAX
  syscall
 end;
end;

type
 t_jmp_rop=packed record
  cmd:WORD;  //FF 25
  ofs:DWORD; //00 00 00 00
  adr:QWORD;
 end;

Procedure CreateNtTerminateTrap;
var
 rop:t_jmp_rop;
 adr:Pointer;
 num:PTRUINT;
 R:Boolean;
begin
 rop.cmd:=$25FF;
 rop.ofs:=0;
 rop.adr:=QWORD(@NtTerminateProcessTrap);

 adr:=GetProcAddress(GetModuleHandle('ntdll.dll'),'NtTerminateProcess');

 num:=0;
 R:=WriteProcessMemory(GetCurrentProcess,adr,@rop,SizeOf(rop),num);
 Writeln('CreateNtTerminateTrap:0x',HexStr(adr),' ',R,' ',num);
end;
}

procedure fork_process(data:Pointer;size:QWORD); SysV_ABI_CDecl;
var
 td:p_kthread;
 r:Integer;

 pipefd:THandle;
 parent:THandle;

 kipc:THostIpcPipeKERN;

 mem:TPCharStream;
 GameStartupInfo:TGameStartupInfo;
begin
 //while not IsDebuggerPresent do sleep(100);

 mem:=TPCharStream.Create(data,size);

 GameStartupInfo:=TGameStartupInfo.Create(True);
 GameStartupInfo.Deserialize(mem);

 mem.Free;

 //free shared
 md_fork_unshare;

 parent:=md_pidfd_open(md_getppid);

 pipefd:=GameStartupInfo.FPipe;
 pipefd:=md_pidfd_getfd(parent,pipefd);

 kipc:=THostIpcPipeKERN.Create;
 kipc.set_pipe(pipefd);

 p_host_ipc    :=kipc;
 p_host_handler:=THostIpcHandler.Create;
 p_host_ipc    .FHandler:=p_host_handler;

 //CreateNtTerminateTrap;

 td:=nil;
 r:=kthread_add(@prepare,GameStartupInfo,@td,0,'[main]');
 Assert(r=0);

 msleep_td(0);
end;

function run_item(const cfg:TGameRunConfig):TGameProcess;
label
 _error;
var
 r:Integer;

 kern2mgui:array[0..1] of THandle;

 fork_info:t_fork_proc;

 kev:t_kevent;

 p_mgui_ipc:THostIpcPipeMGUI;

 s_kern_ipc:THostIpcSimpleKERN;
 s_mgui_ipc:THostIpcSimpleMGUI;

 GameStartupInfo:TGameStartupInfo;
 mem:TMemoryStream;
begin
 Result:=nil;
 r:=0;

 GameStartupInfo:=TGameStartupInfo.Create(False);
 GameStartupInfo.FConfInfo:=cfg.FConfInfo;
 GameStartupInfo.FGameItem:=cfg.FGameItem;

 SetStdHandle(STD_OUTPUT_HANDLE,cfg.hOutput);
 SetStdHandle(STD_ERROR_HANDLE ,cfg.hError );

 fork_info:=Default(t_fork_proc);

 if cfg.FConfInfo.MainInfo.fork_proc then
 begin
  Result:=TGameProcessPipe.Create;
  Result.g_fork:=True;

  with TGameProcessPipe(Result) do
  begin
   r:=md_pipe2(@kern2mgui,MD_PIPE_ASYNC0 or MD_PIPE_ASYNC1);
   if (r<>0) then goto _error;

   p_mgui_ipc:=THostIpcPipeMGUI.Create;
   p_mgui_ipc.set_pipe(kern2mgui[0]);

   g_ipc:=p_mgui_ipc;
   FChildpip:=kern2mgui[1];
  end;

  //

  mem:=TMemoryStream.Create;

  GameStartupInfo.FPipe:=kern2mgui[1];
  GameStartupInfo.Serialize(mem);
  FreeAndNil(GameStartupInfo);

  fork_info.hInput :=GetStdHandle(STD_INPUT_HANDLE);
  fork_info.hOutput:=cfg.hOutput;
  fork_info.hError :=cfg.hError;

  fork_info.proc:=@fork_process;
  fork_info.data:=mem.Memory;
  fork_info.size:=mem.Size;

  r:=md_fork_process(fork_info);

  mem.Free;
 end else
 begin
  Result:=TGameProcessSimple.Create;
  Result.g_fork:=False;

  with TGameProcessSimple(Result) do
  begin

   s_kern_ipc:=THostIpcSimpleKERN.Create;
   s_mgui_ipc:=THostIpcSimpleMGUI.Create;

   s_kern_ipc.FDest:=s_mgui_ipc;
   s_mgui_ipc.FDest:=s_kern_ipc;

   g_ipc:=s_mgui_ipc;

   p_host_ipc    :=s_kern_ipc;
   p_host_handler:=THostIpcHandler.Create;
   p_host_ipc    .FHandler:=p_host_handler;

   Ftd:=nil;
   r:=kthread_add(@prepare,GameStartupInfo,@Ftd,0,'[main]');

   fork_info.fork_pid:=GetProcessID;
  end;

 end;

 if (r<>0) then
 begin
  _error:
  ShowMessage('error run process code=0x'+HexStr(r,8));
  FreeAndNil(Result);
  Exit;
 end;

 Result.g_proc :=fork_info.hProcess;
 Result.g_p_pid:=fork_info.fork_pid;

 Result.g_ipc.thread_new;

 kev.ident :=fork_info.fork_pid;
 kev.filter:=EVFILT_PROC;
 kev.flags :=EV_ADD;
 kev.fflags:=NOTE_EXIT or NOTE_EXEC;
 kev.data  :=0;
 kev.udata :=nil;

 Result.g_ipc.kevent(@kev,1);

end;



end.




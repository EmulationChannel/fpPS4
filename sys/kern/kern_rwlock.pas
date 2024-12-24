unit kern_rwlock;

{$mode ObjFPC}{$H+}

interface

{$DEFINE ALT_SRW1}
{/$DEFINE ALT_SRW2}

{$IF defined(ALT_SRW1) or defined(ALT_SRW2)}
procedure rw_rlock    (Var SRWLock:Pointer);
procedure rw_runlock  (Var SRWLock:Pointer);
procedure rw_wlock    (Var SRWLock:Pointer);
procedure rw_wunlock  (Var SRWLock:Pointer);
Function  rw_try_rlock(Var SRWLock:Pointer):Boolean;
Function  rw_try_wlock(Var SRWLock:Pointer):Boolean;
procedure rw_unlock   (Var SRWLock:Pointer);
{$ELSE}
procedure rw_rlock    (Var SRWLock:Pointer);         stdcall; external 'kernel32' name 'AcquireSRWLockShared'      ;
procedure rw_runlock  (Var SRWLock:Pointer);         stdcall; external 'kernel32' name 'ReleaseSRWLockShared'      ;
procedure rw_wlock    (Var SRWLock:Pointer);         stdcall; external 'kernel32' name 'AcquireSRWLockExclusive'   ;
procedure rw_wunlock  (Var SRWLock:Pointer);         stdcall; external 'kernel32' name 'ReleaseSRWLockExclusive'   ;
Function  rw_try_rlock(Var SRWLock:Pointer):Boolean; stdcall; external 'kernel32' name 'TryAcquireSRWLockShared'   ;
Function  rw_try_wlock(Var SRWLock:Pointer):Boolean; stdcall; external 'kernel32' name 'TryAcquireSRWLockExclusive';
{$ENDIF}

implementation

{$IF defined(ALT_SRW1) or defined(ALT_SRW2)}
uses
 //mqueue,
 ntapi,
 windows;
{$ENDIF}

//https://github.com/wine-mirror/wine/blob/a581f11e3e536fbef1865f701c0db2444673d096/dlls/ntdll/sync.c

{
type
 p_futex_entry=^futex_entry;
 futex_entry=record
  entry:STAILQ_ENTRY;
  addr :Pointer;
  tid  :DWORD;
 end;

 p_futex_queue=^futex_queue;
 futex_queue=record
  queue:STAILQ_HEAD;
  lock :Pointer;
 end;

var
 futex_queues:array[0..255] of futex_queue;

function get_futex_queue(addr:Pointer):p_futex_queue;
begin
 Result:=@futex_queues[(QWORD(addr) shr 4) mod Length(futex_queues)];
end;

procedure spin_lock(var lock:Pointer);
begin
 while (System.InterlockedCompareExchange(lock,Pointer(-1),nil)<>nil) do
 begin
  NtYieldExecution();
 end;
end;

procedure spin_unlock(var lock:Pointer);
begin
 System.InterlockedExchange(lock,nil);
end;

function compare_addr(addr,cmp:Pointer;size:Integer):Boolean; inline;
begin
 case size of
  1:Result:=(PBYTE(addr)^=PBYTE(cmp)^);
  2:Result:=(PWORD(addr)^=PWORD(cmp)^);
  4:Result:=(PDWORD(addr)^=PDWORD(cmp)^);
  8:Result:=(PQWORD(addr)^=PQWORD(cmp)^);
  else
    Result:=False;
 end;
end;

function RtlWaitOnAddress(addr,cmp:Pointer;size:Integer;timeout:PLARGE_INTEGER):DWORD;
var
 queue:p_futex_queue;
 entry:futex_entry;
begin
 if (addr=nil) or
    (not (size in [1,2,4,8])) then
 begin
  Exit(STATUS_INVALID_PARAMETER);
 end;

 queue:=get_futex_queue(addr);

 entry.addr:=addr;
 entry.tid :=ThreadId;

 spin_lock(queue^.lock);

 if not compare_addr(addr,cmp,size) then
 begin
  spin_unlock(queue^.lock);
  Exit(0);
 end;

 if (queue^.queue.stqh_last=nil) then
 begin
  STAILQ_INIT(@queue^.queue);
 end;

 STAILQ_INSERT_TAIL(@queue^.queue,@entry,@entry.entry);

 spin_unlock(queue^.lock);

 Result:=NtWaitForAlertByThreadId(addr,timeout);

 if (entry.addr<>nil) then
 begin
  spin_lock(queue^.lock);
  //
  if (entry.addr<>nil) then
  begin
   STAILQ_REMOVE(@queue^.queue,@entry,@entry.entry);
  end;
  //
  spin_unlock(queue^.lock);
 end;

 if (Result=STATUS_ALERTED) then
 begin
  Result:=STATUS_SUCCESS;
 end;
end;

procedure RtlWakeAddressAll(addr:Pointer);
var
 queue:p_futex_queue;
 entry,next:p_futex_entry;
 tids:array[0..63] of DWORD;
 i,count:Integer;
begin
 if (addr=nil) then Exit;

 queue:=get_futex_queue(addr);

 count:=0;

 spin_lock(queue^.lock);

 if (queue^.queue.stqh_last=nil) then
 begin
  STAILQ_INIT(@queue^.queue);
 end;

 entry:=STAILQ_FIRST(@queue^.queue);
 while (entry<>nil) do
 begin
  next:=STAILQ_NEXT(entry,@entry^.entry);
  //
  if (entry^.addr=addr) then
  begin
   entry^.addr:=nil;

   STAILQ_REMOVE(@queue^.queue,entry,@entry^.entry);

   if (count<Length(tids)) then
   begin
    tids[count]:=entry^.tid;
    Inc(count);
   end else
   begin
    NtAlertThreadByThreadId(entry^.tid);
   end;
  end;
  //
  entry:=next;
 end;

 spin_unlock(queue^.lock);

 if (count<>0) then
 For i:=0 to count-1 do
 begin
  NtAlertThreadByThreadId(tids[i]);
 end;
end;

procedure RtlWakeAddressSingle(addr:Pointer);
var
 queue:p_futex_queue;
 entry:p_futex_entry;
 tid:DWORD;
begin
 if (addr=nil) then Exit;

 queue:=get_futex_queue(addr);

 tid:=0;

 spin_lock(queue^.lock);

 if (queue^.queue.stqh_last=nil) then
 begin
  STAILQ_INIT(@queue^.queue);
 end;

 entry:=STAILQ_FIRST(@queue^.queue);
 while (entry<>nil) do
 begin
  if (entry^.addr=addr) then
  begin
   tid:=entry^.tid;

   entry^.addr:=nil;

   STAILQ_REMOVE(@queue^.queue,entry,@entry^.entry);
   Break;
  end;
  //
  entry:=STAILQ_NEXT(entry,@entry^.entry);
 end;

 spin_unlock(queue^.lock);

 if (tid<>0) then
 begin
  NtAlertThreadByThreadId(tid);
 end;
end;
}

function  RtlWaitOnAddress    (addr,cmp:Pointer;size:QWORD;timeout:PLARGE_INTEGER):DWORD; stdcall; external 'ntdll';
procedure RtlWakeAddressAll   (addr:Pointer); stdcall; external 'ntdll';
procedure RtlWakeAddressSingle(addr:Pointer); stdcall; external 'ntdll';

{$IFDEF ALT_SRW1}

type
 p_srw_lock=^srw_lock;
 srw_lock=packed record
  exclusive_waiters:Smallint;
  owners           :Word;
 end;

 t_union_1=packed record
  case Byte of
   0:(r:Pointer);
   1:(s:p_srw_lock);
   2:(l:PDWORD);
 end;

 t_union_2=packed record
  case Byte of
   0:(s:srw_lock);
   1:(l:DWORD);
 end;

procedure InterlockedExchangeAdd16(addr:Pointer;New:WORD); assembler; nostackframe; sysv_abi_default;
asm
 lock xadd %si,(%rdi)
end;

procedure rw_wlock(Var SRWLock:Pointer);
var
 u:t_union_1;
 old,new:t_union_2;
 wait:Boolean;
begin
 u.r:=@SRWLock;

 InterlockedExchangeAdd16(@u.s^.exclusive_waiters,2);

 repeat

  repeat
   old.s:=u.s^;
   new:=old;

   if (old.s.owners=0) then
   begin
    new.s.owners:=1;
    Dec(new.s.exclusive_waiters,2);
    new.s.exclusive_waiters:=new.s.exclusive_waiters or 1;
    wait:=FALSE;
   end else
   begin
    wait:=TRUE;
   end;
  until (System.InterlockedCompareExchange(u.l^,new.l,old.l) = old.l);

  if (not wait) then Exit;
  RtlWaitOnAddress(@u.s^.owners,@new.s.owners,sizeof(Smallint),nil);
 until false;
end;

procedure rw_rlock(Var SRWLock:Pointer);
var
 u:t_union_1;
 old,new:t_union_2;
 wait:Boolean;
begin
 u.r:=@SRWLock;

 repeat

  repeat
   old.s:=u.s^;
   new:=old;

   if (old.s.exclusive_waiters=0) then
   begin
    Inc(new.s.owners);
    wait:=FALSE;
   end else
   begin
    wait:=TRUE;
   end;
  until (System.InterlockedCompareExchange(u.l^,new.l,old.l) = old.l);

  if (not wait) then Exit;
  RtlWaitOnAddress(u.s,@new.s,sizeof(srw_lock),nil);
 until false;
end;

function rw_try_wlock(Var SRWLock:Pointer):Boolean;
var
 u:t_union_1;
 old,new:t_union_2;
begin
 u.r:=@SRWLock;

 repeat
  old.s:=u.s^;
  new:=old;

  if (old.s.owners=0) then
  begin
   new.s.owners:=1;
   new.s.exclusive_waiters:=new.s.exclusive_waiters or 1;
   Result:=TRUE;
  end else
  begin
   Result:=FALSE;
  end;
 until (System.InterlockedCompareExchange(u.l^,new.l,old.l) = old.l);
end;

function rw_try_rlock(Var SRWLock:Pointer):Boolean;
var
 u:t_union_1;
 old,new:t_union_2;
begin
 u.r:=@SRWLock;

 repeat
  old.s:=u.s^;
  new:=old;

  if (old.s.exclusive_waiters=0) then
  begin
   Inc(new.s.owners);
   Result:=TRUE;
  end else
  begin
   Result:=FALSE;
  end;
 until (System.InterlockedCompareExchange(u.l^,new.l,old.l) = old.l);
end;

procedure rw_wunlock(Var SRWLock:Pointer);
var
 u:t_union_1;
 old,new:t_union_2;
begin
 u.r:=@SRWLock;

 repeat
  old.s:=u.s^;
  new:=old;

  if ((old.s.exclusive_waiters and 1)=0) then
  begin
   Assert(false,'Lock 0x'+HexStr(@SRWLock)+' is not owned exclusive!');
  end;

  new.s.owners:=0;
  new.s.exclusive_waiters:=new.s.exclusive_waiters and (not 1);
 until (System.InterlockedCompareExchange(u.l^,new.l,old.l) = old.l);

 if (new.s.exclusive_waiters<>0) then
 begin
  RtlWakeAddressSingle(@u.s^.owners);
 end else
 begin
  RtlWakeAddressAll(u.s);
 end;
end;

procedure rw_runlock(Var SRWLock:Pointer);
var
 u:t_union_1;
 old,new:t_union_2;
begin
 u.r:=@SRWLock;

 repeat
  old.s:=u.s^;
  new:=old;

  if ((old.s.exclusive_waiters and 1)<>0) then
  begin
   Assert(false,'Lock 0x'+HexStr(@SRWLock)+' is owned exclusive!');
  end else
  if (old.s.owners=0) then
  begin
   Assert(false,'Lock 0x'+HexStr(@SRWLock)+' is not owned shared!');
  end;

  Dec(new.s.owners);
 until (System.InterlockedCompareExchange(u.l^,new.l,old.l) = old.l);

 if (new.s.owners=0) then
 begin
  RtlWakeAddressSingle(@u.s^.owners);
 end;
end;

procedure rw_unlock(Var SRWLock:Pointer);
var
 u:t_union_1;
 old,new:t_union_2;
 shared:Boolean;
begin
 u.r:=@SRWLock;

 repeat
  old.s:=u.s^;
  new:=old;

  if ((old.s.exclusive_waiters and 1)<>0) then
  begin
   shared:=False;
  end else
  if (old.s.owners=0) then
  begin
   Exit;
  end else
  begin
   shared:=True;
  end;

  if shared then
  begin
   Dec(new.s.owners);
  end else
  begin
   new.s.owners:=0;
   new.s.exclusive_waiters:=new.s.exclusive_waiters and (not 1);
  end;

 until not (System.InterlockedCompareExchange(u.l^,new.l,old.l)<>old.l);

 if shared then
 begin
  if (new.s.owners=0) then
  begin
   RtlWakeAddressSingle(@u.s^.owners);
  end;
 end else
 begin
  if (new.s.exclusive_waiters<>0) then
  begin
   RtlWakeAddressSingle(@u.s^.owners);
  end else
  begin
   RtlWakeAddressAll(u.s);
  end;
 end;
end;

{$ENDIF}

{$IFDEF ALT_SRW2}

Const
 MAX_SPIN=10;

 SRW_MASK_READERS=QWORD($000000007FFFFFFF);
 SRW_FLAG_WRITING=QWORD($0000000080000000);
 SRW_MASK_WAITERS=QWORD($7FFFFFFF00000000);
 SRW_FLAG_READIED=QWORD($8000000000000000);

 SRW_INC_WAITER  =QWORD($0000000100000000);

function ReaderCount(lock:QWORD):DWORD; inline;
begin
 Result:=DWORD(lock and SRW_MASK_READERS);
end;

function SetReaders(lock:QWORD;readers:DWORD):QWORD; inline;
begin
 Result:=(lock and (not SRW_MASK_READERS)) or readers;
end;

function WaitingCount(lock:QWORD):DWORD; inline;
begin
 Result:=DWORD((lock and SRW_MASK_WAITERS) shr 32);
end;

function SetWaiting(lock:QWORD;waiting:DWORD):QWORD; inline;
begin
 Result:=(lock and (not SRW_MASK_WAITERS)) or (QWORD(waiting) shl 32);
end;

function IncWaiting(var lock:QWORD):QWORD; inline;
begin
 Result:=System.InterlockedExchangeAdd64(lock,SRW_INC_WAITER)+SRW_INC_WAITER;
end;

function DecWaiting(var lock:QWORD):QWORD; inline;
begin
 Result:=System.InterlockedExchangeAdd64(lock,QWORD(-SRW_INC_WAITER))+QWORD(-SRW_INC_WAITER);
end;

function Writer(lock:QWORD):Boolean; inline;
begin
 Result:=(lock and SRW_FLAG_WRITING)<>0;
end;

function SetWriter(lock:QWORD;writer:Boolean):QWORD; inline;
begin
 if writer then
  Result:=lock or SRW_FLAG_WRITING
 else
  Result:=lock and (not SRW_FLAG_WRITING);
end;

function AllClear(lock:QWORD):Boolean; inline;
begin
 Result:=(lock and (SRW_MASK_READERS or SRW_FLAG_WRITING))=0;
end;

function Initialized(lock:QWORD):Boolean; inline;
begin
 Result:=(lock and SRW_FLAG_READIED)<>0;
end;

function SetInitialized(lock:QWORD;init:Boolean):QWORD; inline;
begin
 if init then
  Result:=lock or SRW_FLAG_READIED
 else
  Result:=lock and (not SRW_FLAG_READIED);
end;

Procedure rw_rlock(Var SRWLock:Pointer);
label
 _next;
Var
 vLock:QWORD absolute SRWLock;
 i:SizeUInt;
 temp,new:QWORD;
begin
 i:=0;
 repeat
  temp:=vLock;

  if not Writer(temp) then
  begin

   if System.InterlockedCompareExchange64(vLock,SetReaders(temp,ReaderCount(temp) + 1),temp) = temp then
   begin
    Exit;
   end else
   begin
    goto _next;
   end;

  end else
  begin

   if (i<MAX_SPIN) then
   begin
    NtYieldExecution;
    goto _next;
   end;

   new:=IncWaiting(vLock);

   i:=0;
   RtlWaitOnAddress(@SRWLock,@new,sizeof(QWORD),nil);

   DecWaiting(vLock);
  end;

  _next:
  Inc(i);
 until False;
end;

Procedure rw_wlock(Var SRWLock:Pointer);
label
 _next;
Var
 vLock:QWORD absolute SRWLock;
 i:SizeUInt;
 temp,new:QWORD;
begin
 i:=0;
 repeat
  temp:=vLock;

  if AllClear(temp) then
  begin

   if System.InterlockedCompareExchange64(vLock,SetWriter(temp,true),temp) = temp then
   begin
    Exit;
   end else
   begin
    goto _next;
   end;

  end else
  begin

   if (i<MAX_SPIN) then
   begin
    NtYieldExecution;
    goto _next;
   end;

   new:=IncWaiting(vLock);

   i:=0;
   RtlWaitOnAddress(@SRWLock,@new,sizeof(QWORD),nil);

   DecWaiting(vLock);
  end;

  _next:
  Inc(i);
 until False;
end;

procedure rw_wunlock(Var SRWLock:Pointer);
Var
 vLock:QWORD absolute SRWLock;
 temp:QWORD;
begin
 repeat
  temp:=vLock;

  Assert(Writer(temp));

 until System.InterlockedCompareExchange64(vLock,SetWriter(temp,false),temp) = temp;

 RtlWakeAddressAll(@SRWLock);
end;

procedure rw_runlock(Var SRWLock:Pointer);
Var
 vLock:QWORD absolute SRWLock;
 temp:QWORD;
begin
 repeat
  temp:=vLock;

  Assert(ReaderCount(temp) > 0);

 until System.InterlockedCompareExchange64(vLock,SetReaders(temp,ReaderCount(temp) - 1),temp) = temp;

 if (ReaderCount(temp)=1) and (WaitingCount(temp)<>0) then
 begin
  RtlWakeAddressSingle(@SRWLock);
 end;
end;

Procedure rw_unlock(Var SRWLock:Pointer);
Var
 vLock:QWORD absolute SRWLock;
 temp:QWORD;
begin
 repeat

  temp:=vLock;
  if ReaderCount(temp)=0 then
  begin
   //rw_wunlock

   if System.InterlockedCompareExchange64(vLock,SetWriter(temp,false),temp) = temp then
   begin
    RtlWakeAddressAll(@SRWLock);
    Break;
   end;
   //
  end else
  begin
   //rw_runlock

   if System.InterlockedCompareExchange64(vLock,SetReaders(temp,ReaderCount(temp) - 1),temp) = temp then
   begin

    if (ReaderCount(temp)=1) and (WaitingCount(temp)<>0) then
    begin
     RtlWakeAddressSingle(@SRWLock);
    end;

    Break;
   end;
   //
  end;

 until false;
end;

function rw_try_rlock(Var SRWLock:Pointer):Boolean;
Var
 vLock:QWORD absolute SRWLock;
 temp:QWORD;
begin
 Result:=False;
 temp:=vLock;
 if not Writer(temp) then
 begin
  if System.InterlockedCompareExchange64(vLock,SetReaders(temp,ReaderCount(temp) + 1),temp) = temp then
  begin
   Result:=True;
  end;
 end;
end;

function rw_try_wlock(Var SRWLock:Pointer):Boolean;
Var
 vLock:QWORD absolute SRWLock;
 temp:QWORD;
begin
 Result:=False;
 temp:=vLock;
 if AllClear(temp) then
 begin
  if System.InterlockedCompareExchange64(vLock,SetWriter(temp,true),temp) = temp then
  begin
   Result:=True;
  end;
 end;
end;

{$ENDIF}

end.


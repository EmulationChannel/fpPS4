unit ps4_libSceRemoteplay;

{$mode ObjFPC}{$H+}
{$CALLING SysV_ABI_CDecl}

interface

uses
 subr_dynlib;

implementation

const
 SCE_REMOTEPLAY_HEAP_SIZE=6*1024;

function ps4_sceRemoteplayInitialize(pHeap:Pointer;heapSize:QWORD):Integer;
begin
 Writeln('sceRemoteplayInitialize:',heapSize);
 Result:=0;
end;

function ps4_sceRemoteplayApprove:Integer;
begin
 Result:=0;
end;

function ps4_sceRemoteplaySetProhibition:Integer;
begin
 Result:=0;
end;

const
 SCE_REMOTEPLAY_CONNECTION_STATUS_DISCONNECT=0;
 SCE_REMOTEPLAY_CONNECTION_STATUS_CONNECT   =1;

function ps4_sceRemoteplayGetConnectionStatus(userId:Integer;pStatus:PInteger):Integer;
begin
 if (pStatus<>nil) then
 begin
  pStatus^:=SCE_REMOTEPLAY_CONNECTION_STATUS_DISCONNECT;
 end;
 Result:=0;
end;

function ps4_sceRemoteplayProhibit:Integer;
begin
 Result:=0;
end;

function Load_libSceRemoteplay(name:pchar):p_lib_info;
var
 lib:TLIBRARY;
begin
 Result:=obj_new_int('libSceRemoteplay');

 lib:=Result^.add_lib('libSceRemoteplay');
 lib.set_proc($9354B082431238CF,@ps4_sceRemoteplayInitialize);
 lib.set_proc($C50788AF24D7EDD6,@ps4_sceRemoteplayApprove);
 lib.set_proc($8373CD8D8296AA74,@ps4_sceRemoteplayGetConnectionStatus);
 lib.set_proc($45FD1731547BC4FC,@ps4_sceRemoteplaySetProhibition);
 lib.set_proc($9AB361EFCB41A668,@ps4_sceRemoteplayProhibit);
end;

var
 stub:t_int_file;

initialization
 RegisteredInternalFile(stub,'libSceRemoteplay.prx',@Load_libSceRemoteplay);

end.


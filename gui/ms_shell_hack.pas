unit ms_shell_hack;

{$mode ObjFPC}{$H+}

interface

function  RegisterDllHack:Pointer;
Procedure UnregisterDllHack(Cookie:Pointer);

implementation

Uses
 sysutils,
 windows,
 ntapi,
 versionresource,
 versiontypes,
 CharStream;

type
 P_LDR_DLL_NOTIFICATION_DATA=^LDR_DLL_NOTIFICATION_DATA;
 LDR_DLL_NOTIFICATION_DATA=record
  Flags      :ULONG;
  FullDllName:PUNICODE_STRING;
  BaseDllName:PUNICODE_STRING;
  DllBase    :Pointer;
  SizeOfImage:ULONG;
 end;

type
 TLdrDllNotification=procedure(
  NotificationReason:ULONG;
  NotificationData  :P_LDR_DLL_NOTIFICATION_DATA;
  Context           :Pointer
 ); MS_ABI_Default;

function LdrRegisterDllNotification(
          Flags        :ULONG;
          NotifFunction:TLdrDllNotification;
          Context      :Pointer;
          Cookie       :PPointer
         ):DWORD; MS_ABI_Default; external 'ntdll';

function LdrUnregisterDllNotification(
          Cookie:Pointer
         ):DWORD; MS_ABI_Default; external 'ntdll';

function LdrResSearchResource(
          DllBase            :Pointer;
          ResIds             :PULONG_PTR;
          ResIdCount         :ULONG;
          Flags              :ULONG;
          Resource           :PPointer;
          Size               :PULONG_PTR;
          FoundLanguage      :PUSHORT;
          FoundLanguageLength:PULONG
         ):DWORD; MS_ABI_Default; external 'ntdll';

const
 RT_VERSION=16;
 CREATEPROCESS_MANIFEST_RESOURCE_ID=1;

 IdPath:array[0..2] of ULONG_PTR=(
  RT_VERSION,
  CREATEPROCESS_MANIFEST_RESOURCE_ID,
  0
 );

Function GetCompanyName(Data:Pointer;Size:ULONG_PTR):RawByteString;
label
 _exit;
var
 VR:TVersionResource;
 SI:TVersionStringFileInfo;
 ST:TVersionStringTable;
 mem:TPCharStream;

 i,k:Integer;
begin
 Result:='';

 mem:=TPCharStream.Create(Data,Size);

 VR:=TVersionResource.Create;
 VR.SetCustomRawDataStream(mem);
 VR.UpdateRawData;
 SI:=VR.StringFileInfo;

 if (SI.Count<>0) then
 For i:=0 to SI.Count-1 do
 begin
  ST:=SI[i];
  //
  if (ST.Count<>0) then
  begin
   For k:=0 to ST.Count-1 do
   begin
    if (ST.Keys[k]='CompanyName') then
    begin
     Result:=ST.ValuesByIndex[k];
     goto _exit;
    end;
   end;
  end;
  //
 end;

 _exit:

 FreeAndNil(VR);
 FreeAndNil(mem);
end;

procedure LdrDllNotification(
  NotificationReason:ULONG;
  NotificationData  :P_LDR_DLL_NOTIFICATION_DATA;
  Context           :Pointer
 ); MS_ABI_Default;
var
 Data:Pointer;
 Size:ULONG_PTR;
begin
 if (NotificationReason<>1) then Exit;

 Data:=nil;
 Size:=0;

 LdrResSearchResource(
  NotificationData^.DllBase,
  @IdPath,
  3,
  0,
  @Data,
  @Size,
  nil,
  nil
 );

 if (Data=nil) then Exit;

 if (GetCompanyName(Data,Size)='Microsoft Corporation') then Exit;

 DisableThreadLibraryCalls(QWORD(NotificationData^.DllBase));
end;

function RegisterDllHack:Pointer;
begin
 Result:=nil;
 LdrRegisterDllNotification(0,@LdrDllNotification,nil,@Result);
end;

Procedure UnregisterDllHack(Cookie:Pointer);
begin
 LdrUnregisterDllNotification(Cookie);
end;


end.


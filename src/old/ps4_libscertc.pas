unit ps4_libSceRtc;

{$mode ObjFPC}{$H+}

interface

uses
  sys_types,
  ps4_program,
  ps4_libkernel,
  ps4_time,
  Classes,
  SysUtils;

const
 SCE_RTC_ERROR_NOT_INITIALIZED    =-2135621631; // 0x80B50001
 SCE_RTC_ERROR_INVALID_POINTER    =-2135621630; // 0x80B50002
 SCE_RTC_ERROR_INVALID_VALUE      =-2135621629; // 0x80B50003
 SCE_RTC_ERROR_INVALID_ARG        =-2135621628; // 0x80B50004
 SCE_RTC_ERROR_NOT_SUPPORTED      =-2135621627; // 0x80B50005
 SCE_RTC_ERROR_NO_CLOCK           =-2135621626; // 0x80B50006
 SCE_RTC_ERROR_BAD_PARSE          =-2135621625; // 0x80B50007
 SCE_RTC_ERROR_INVALID_YEAR       =-2135621624; // 0x80B50008
 SCE_RTC_ERROR_INVALID_MONTH      =-2135621623; // 0x80B50009
 SCE_RTC_ERROR_INVALID_DAY        =-2135621622; // 0x80B5000A
 SCE_RTC_ERROR_INVALID_HOUR       =-2135621621; // 0x80B5000B
 SCE_RTC_ERROR_INVALID_MINUTE     =-2135621620; // 0x80B5000C
 SCE_RTC_ERROR_INVALID_SECOND     =-2135621619; // 0x80B5000D
 SCE_RTC_ERROR_INVALID_MICROSECOND=-2135621618; // 0x80B5000E

 SCE_RTC_DAYOFWEEK_SUNDAY   =0;
 SCE_RTC_DAYOFWEEK_MONDAY   =1;
 SCE_RTC_DAYOFWEEK_TUESDAY  =2;
 SCE_RTC_DAYOFWEEK_WEDNESDAY=3;
 SCE_RTC_DAYOFWEEK_THURSDAY =4;
 SCE_RTC_DAYOFWEEK_FRIDAY   =5;
 SCE_RTC_DAYOFWEEK_SATURDAY =6;

type
 pSceRtcDateTime=^SceRtcDateTime;
 SceRtcDateTime=packed record
  year  :Word;
  month :Word;
  day   :Word;
  hour  :Word;
  minute:Word;
  second:Word;
  microsecond:DWORD;
 end;

implementation

uses
 sys_kernel;

function SDK_VERSION:DWORD;
begin
 Result:=sys_kernel.SDK_VERSION;
 if (Result=0) then Result:=$5050031;
end;

function ps4_module_start(args:QWORD;argp:Pointer):Integer; SysV_ABI_CDecl; //BaOKcng8g88
begin
 Result:=0;
end;

function ps4_module_stop(args:QWORD;argp:Pointer):Integer; SysV_ABI_CDecl; //KpDMrPHvt3Q
begin
 Result:=0;
end;

function ps4_sceRtcInit():Integer; SysV_ABI_CDecl;
begin
 Result:=0;
end;

function ps4_sceRtcEnd():Integer; SysV_ABI_CDecl;
begin
 Result:=0;
end;

//

function _set_tz(tz_minuteswest,tz_dsttime:Integer):Integer;
var
 tz:timezone;
begin
 tz.tz_minuteswest:=tz_minuteswest;
 tz.tz_dsttime    :=tz_dsttime;
 Result:=ps4_sceKernelSettimeofday(nil,@tz);
end;

function _sceRtcTickSubMicroseconds(pTick0,pTick1:PQWORD;lSub:Int64):Integer;
var
 t1:QWORD;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 if (lSub=0) then
 begin
  pTick0^:=pTick1^;
  Exit(0);
 end;

 t1:=pTick1^;

 if (lSub<0) then
 begin
  if (t1 < QWORD(-lSub)) then Exit(SCE_RTC_ERROR_INVALID_VALUE);
 end else
 begin
  if ((not t1) < QWORD(lSub)) then Exit(SCE_RTC_ERROR_INVALID_VALUE);
 end;

 t1:=t1+lSub;
 pTick0^:=t1;
 Result:=0;
end;

function _sceRtcTickAddMinutes(pTick0,pTick1:PQWORD;lAdd:Int64):Integer;
var
 ladd_mul:QWORD;
 t1:QWORD;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 if (lAdd=0) then
 begin
  pTick0^:=pTick1^;
  Exit(0);
 end;

 ladd_mul:=lAdd*60000000;

 t1:=pTick1^;

 if (lAdd < 0) then
 begin
  if (t1 < QWORD(-ladd_mul)) then Exit(SCE_RTC_ERROR_INVALID_VALUE);
 end else
 begin
  if ((not t1) < QWORD(ladd_mul)) then Exit(SCE_RTC_ERROR_INVALID_VALUE);
 end;

 pTick0^:=t1+ladd_mul;
 Result:=0;
end;


function leap_year(year:Word):Boolean; inline;
begin
 if (year=(((year shr 4) div $19)*400)) then
 begin
  Result:=True;
 end else
 if (year=(((year shr 2) div $19)*100)) then
 begin
  Result:=False;
 end else
 begin
  Result:=(year and 3)=0;
 end;
end;

function _sceRtcCheckValid(pTime:pSceRtcDateTime):Integer; inline;
var
 year:WORD;
 leap:Boolean;
begin
 if (pTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 year:=pTime^.year;

 if (year=0) or (year>9999)                    then Exit(SCE_RTC_ERROR_INVALID_YEAR);
 if (pTime^.month=0) or (pTime^.month>12)      then Exit(SCE_RTC_ERROR_INVALID_MONTH);
 if (pTime^.day=0)                             then Exit(SCE_RTC_ERROR_INVALID_DAY);

 leap:=leap_year(year);
 if (pTime^.day>MonthDays[leap][pTime^.month]) then Exit(SCE_RTC_ERROR_INVALID_DAY);
 if (pTime^.hour>=24)                          then Exit(SCE_RTC_ERROR_INVALID_HOUR);
 if (pTime^.minute>=60)                        then Exit(SCE_RTC_ERROR_INVALID_MINUTE);
 if (pTime^.second>=60)                        then Exit(SCE_RTC_ERROR_INVALID_SECOND);
 if (pTime^.microsecond>=1000000)              then Exit(SCE_RTC_ERROR_INVALID_MICROSECOND);
 Result:=0;
end;

//

function ps4_sceRtcTickAddTicks(pTick0,pTick1:PQWORD;lAdd:Int64):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTick0^:=lAdd+pTick1^;

 Result:=0;
end;

function ps4_sceRtcTickAddMicroseconds(pTick0,pTick1:PQWORD;lAdd:Int64):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTick0^:=lAdd+pTick1^;

 Result:=0;
end;

function ps4_sceRtcTickAddSeconds(pTick0,pTick1:PQWORD;lAdd:Int64):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTick0^:=(lAdd*1000000)+pTick1^;

 Result:=0;
end;

function ps4_sceRtcTickAddMinutes(pTick0,pTick1:PQWORD;lAdd:Int64):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTick0^:=(lAdd*60000000)+pTick1^;

 Result:=0;
end;

function ps4_sceRtcTickAddHours(pTick0,pTick1:PQWORD;lAdd:Integer):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTick0^:=(Int64(lAdd)*3600000000)+pTick1^;

 Result:=0;
end;

function ps4_sceRtcTickAddDays(pTick0,pTick1:PQWORD;lAdd:Integer):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTick0^:=(Int64(lAdd)*86400000000)+pTick1^;

 Result:=0;
end;


function ps4_sceRtcTickAddWeeks(pTick0,pTick1:PQWORD;lAdd:Integer):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTick0^:=(Int64(lAdd)*$8cd0e3a000)+pTick1^;

 Result:=0;
end;

//

function ps4_sceRtcSetConf(param_1,param_2:QWORD;tz_minuteswest,tz_dsttime:Integer):Integer; SysV_ABI_CDecl;
begin
 Result:=_set_tz(tz_minuteswest,tz_dsttime);
end;

function ps4_sceRtcSetCurrentTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 tick:QWORD;
 time:timeval;
begin
 if (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);
 if (pTick^<=$dcbffeff2bbfff) then Exit(SCE_RTC_ERROR_INVALID_VALUE);

 tick:=pTick^+$ff23400100d44000;

 time.tv_sec :=tick div 1000000;
 time.tv_usec:=tick mod 1000000;
 Result:=ps4_sceKernelSettimeofday(@time,nil);
end;

function ps4_sceRtcGetCurrentTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 time:timespec;
begin
 if (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_sceKernelClockGettime(0,@time);

 if (Result>=0) then
 begin
  pTick^:=(time.tv_nsec div 1000) + (time.tv_sec*1000000) + $dcbffeff2bc000;
 end
end;

function ps4_sceRtcSetTick(pTime:pSceRtcDateTime;pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 ly,ld,lm,j:cardinal;
 days:qword;
 msec:qword;
begin
 if (pTime=nil) or (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 days:=pTick^ div (3600000*1000*24);
 msec:=pTick^ mod (3600000*1000*24);

 days:=days+307;

 j := pred(days SHL 2);
 ly:= j DIV 146097;
 j:= j - 146097 * cardinal(ly);
 ld := j SHR 2;
 j:=(ld SHL 2 + 3) DIV 1461;
 ld:= (cardinal(ld) SHL 2 + 7 - 1461*j) SHR 2;
 lm:=(5 * ld-3) DIV 153;
 ld:= (5 * ld +2 - 153*lm) DIV 5;
 ly:= 100 * cardinal(ly) + j;
 if lm < 10 then
 begin
  inc(lm,3);
 end else
 begin
  dec(lm,9);
  inc(ly);
 end;

 pTime^.year :=ly;
 pTime^.month:=lm;
 pTime^.day  :=ld;

 pTime^.Hour   := msec div (3600000*1000);
 msec := msec mod (3600000*1000);
 pTime^.Minute := msec div (60000*1000);
 msec := msec mod (60000*1000);
 pTime^.Second := msec div (1000*1000);
 msec := msec mod (1000*1000);
 pTime^.microsecond := msec;
end;

function _sceRtcGetTick(pTime:pSceRtcDateTime;pTick:PQWORD):Integer;
var
 c,ya:cardinal;
 days:qword;
 msec:qword;
begin
 Result:=0;
 if (pTime^.month>2) then
 begin
  Dec(pTime^.month,3);
 end else
 begin
  Inc(pTime^.month,9);
  Dec(pTime^.Year);
 end;
 c:= pTime^.Year DIV 100;
 ya:=pTime^.Year - 100*c;

 days:=(146097*c) SHR 2 + (1461*ya) SHR 2 + (153*cardinal(pTime^.Month)+2) DIV 5 + cardinal(pTime^.Day);
 days:=days-307;
 days:=days*(3600000*1000*24);

 msec:=cardinal(pTime^.Hour)*(3600000*1000)+
       cardinal(pTime^.minute)*(60000*1000)+
       cardinal(pTime^.second)*(1000*1000)+
       pTime^.microsecond;

 pTick^:=days+msec;
end;

function ps4_sceRtcGetTick(pTime:pSceRtcDateTime;pTick:PQWORD):Integer; SysV_ABI_CDecl;
begin
 if (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);
 Result:=_sceRtcCheckValid(pTime);
 if (Result<>0) then Exit;
 Result:=_sceRtcGetTick(pTime,pTick);
end;

function ps4_sceRtcGetCurrentClock(pTime:pSceRtcDateTime;iTimeZone:Integer):Integer; SysV_ABI_CDecl;
var
 tick:QWORD;
 time:timespec;
begin
 if (pTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_sceKernelClockGettime(0,@time);

 if (Result>=0) then
 begin
  tick:=(time.tv_nsec div 1000) + (time.tv_sec * 1000000) + $dcbffeff2bc000;
  ps4_sceRtcTickAddMinutes(@tick,@tick,iTimeZone);
  ps4_sceRtcSetTick(pTime,@tick);
 end;
end;

function ps4_sceRtcGetCurrentClockLocalTime(pTime:pSceRtcDateTime):Integer; SysV_ABI_CDecl;
var
 local_time:time_t;
 _tick,tick:QWORD;
 time:timespec;
 tsec:timesec;
begin
 if (pTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_sceKernelClockGettime(0,@time);

 if (Result>=0) then
 begin
  _tick:= (time.tv_nsec div 1000) + (time.tv_sec * 1000000);
  tick := _tick + $dcbffeff2bc000;

  Result:=ps4_sceKernelConvertUtcToLocaltime(_tick div 1000000,@local_time,@tsec,nil);

  if (Result>=0) then
  begin
   ps4_sceRtcTickAddMinutes(@tick,@tick,(tsec.tz_dstsec + tsec.tz_secwest) div $3c);
   ps4_sceRtcSetTick(pTime,@tick);
  end;

 end;
end;

function ps4_sceRtcConvertUtcToLocalTime(pUtc,pLocalTime:PQWORD):Integer; SysV_ABI_CDecl;
var
 tsec:timesec;
 local_time:time_t;
begin
 if (pUtc=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_sceKernelConvertUtcToLocaltime((pUtc^ + $ff23400100d44000) div 1000000,@local_time,@tsec,nil);

 if (Result>=0) then
 begin
  Result:=_sceRtcTickSubMicroseconds(pLocalTime,pUtc,((tsec.tz_dstsec + tsec.tz_secwest) div $3c) * 60000000);
 end;
end;

function ps4_sceRtcConvertLocalTimeToUtc(pLocalTime,pUtc:PQWORD):Integer; SysV_ABI_CDecl;
var
 tsec:timesec;
 utc_time:time_t;
begin
 if (pLocalTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_sceKernelConvertLocaltimeToUtc((pLocalTime^ + $ff23400100d44000) div 1000000,$ffffffff,@utc_time,@tsec,nil);

 if (Result>=0) then
 begin
  Result:=ps4_sceRtcTickAddMinutes(pUtc,pLocalTime,-((tsec.tz_dstsec + tsec.tz_secwest) div $3c));
 end;
end;


function ps4_sceRtcGetCurrentNetworkTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 perror:Pinteger;
 time:timespec;
begin
 if (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_clock_gettime($10,@time);
 if (Result=0) then
 begin
  pTick^:=(time.tv_nsec div 1000) + (time.tv_sec * 1000000) + $dcbffeff2bc000;
 end else
 begin
  perror:=ps4___error;
  Result:=SCE_RTC_ERROR_NOT_INITIALIZED;
  if (perror^<>5) then
  begin
   Result:=ps4_sceKernelError(perror^);
  end;
 end;
end;

function ps4_sceRtcGetCurrentRawNetworkTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 perror:Pinteger;
 time:timespec;
begin
 if (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_clock_gettime($13,@time);
 if (Result=0) then
 begin
  pTick^:=(time.tv_nsec div 1000) + (time.tv_sec * 1000000) + $dcbffeff2bc000;
 end else
 begin
  perror:=ps4___error;
  Result:=SCE_RTC_ERROR_NOT_INITIALIZED;
  if (perror^<>5) then
  begin
   Result:=ps4_sceKernelError(perror^);
  end;
 end;
end;

function ps4_sceRtcGetCurrentDebugNetworkTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 perror:Pinteger;
 time:timespec;
begin
 if (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_clock_gettime($11,@time);
 if (Result<>0) then
 begin
  perror:=ps4___error;
  Result:=SCE_RTC_ERROR_NOT_INITIALIZED;

  if (perror^<>5) then
  begin
   Result:=ps4_sceKernelError(perror^);
   if (Result<>SCE_RTC_ERROR_NOT_INITIALIZED) then Exit;
  end;
  Result:=ps4_clock_gettime($10,@time);

  Result:=SCE_RTC_ERROR_NOT_INITIALIZED;
  if (perror^<>5) then
  begin
   Result:=ps4_sceKernelError(perror^);
  end;

  Exit;
 end;

 pTick^:=(time.tv_nsec div 1000) + (time.tv_sec * 1000000) + $dcbffeff2bc000;
 Result:=0;
end;

function ps4_sceRtcGetCurrentAdNetworkTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 perror:Pinteger;
 time:timespec;
begin
 if (pTick=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 Result:=ps4_clock_gettime($12,@time);
 if (Result<>0) then
 begin
  perror:=ps4___error;
  Result:=SCE_RTC_ERROR_NOT_INITIALIZED;

  if (perror^<>5) then
  begin
   Result:=ps4_sceKernelError(perror^);
   if (Result<>SCE_RTC_ERROR_NOT_INITIALIZED) then Exit;
  end;
  Result:=ps4_clock_gettime($10,@time);

  Result:=SCE_RTC_ERROR_NOT_INITIALIZED;
  if (perror^<>5) then
  begin
   Result:=ps4_sceKernelError(perror^);
  end;

  Exit;
 end;

 pTick^:=(time.tv_nsec div 1000) + (time.tv_sec * 1000000) + $dcbffeff2bc000;
 Result:=0;
end;

function ps4_sceRtcSetCurrentNetworkTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 perror:Pinteger;
 tick:QWORD;
 ptime:ptimespec;
 time:timespec;
begin
 if (pTick=nil) then
 begin
  ptime:=nil;
 end else
 begin
  if (pTick^<$dcbffeff2bc000) then Exit(SCE_RTC_ERROR_INVALID_VALUE);
  ptime:=@time;
  tick:=pTick^+$ff23400100d44000;
  time.tv_sec :=(tick div 1000000);
  time.tv_nsec:=(tick mod 1000000)*1000;
 end;

 Result:=ps4_clock_settime($10,ptime);
 if (Result<>0) then
 begin
  perror:=ps4___error;
  Result:=ps4_sceKernelError(perror^);
 end;
end;

function ps4_sceRtcSetCurrentDebugNetworkTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 perror:Pinteger;
 tick:QWORD;
 ptime:ptimespec;
 time:timespec;
begin
 if (pTick=nil) then
 begin
  ptime:=nil;
 end else
 begin
  if (pTick^<$dcbffeff2bc000) then Exit(SCE_RTC_ERROR_INVALID_VALUE);
  ptime:=@time;
  tick:=pTick^+$ff23400100d44000;
  time.tv_sec :=(tick div 1000000);
  time.tv_nsec:=(tick mod 1000000)*1000;
 end;

 Result:=ps4_clock_settime($11,ptime);
 if (Result<>0) then
 begin
  perror:=ps4___error;
  Result:=ps4_sceKernelError(perror^);
 end;
end;

function ps4_sceRtcSetCurrentAdNetworkTick(pTick:PQWORD):Integer; SysV_ABI_CDecl;
var
 perror:Pinteger;
 tick:QWORD;
 ptime:ptimespec;
 time:timespec;
begin
 if (pTick=nil) then
 begin
  ptime:=nil;
 end else
 begin
  if (pTick^<$dcbffeff2bc000) then Exit(SCE_RTC_ERROR_INVALID_VALUE);
  ptime:=@time;
  tick:=pTick^+$ff23400100d44000;
  time.tv_sec :=(tick div 1000000);
  time.tv_nsec:=(tick mod 1000000)*1000;
 end;

 Result:=ps4_clock_settime($12,ptime);
 if (Result<>0) then
 begin
  perror:=ps4___error;
  Result:=ps4_sceKernelError(perror^);
 end;
end;

function ps4_sceRtcGetTickResolution:Integer; SysV_ABI_CDecl;
begin
 Result:=1000000;
end;

function ps4_sceRtcIsLeapYear(year:Integer):Integer; SysV_ABI_CDecl;
begin
 if (year<1) then
 begin
  Exit(SCE_RTC_ERROR_INVALID_YEAR);
 end;
 if (year<>(year div 400)*400) then
 begin
  if (year<>(year div 100)*100) then
  begin
   Exit(Integer((year and 3)=0));
  end;
  Result:=0;
 end;
 Result:=1;
end;

function ps4_sceRtcGetDaysInMonth(year,month:Integer):Integer; SysV_ABI_CDecl;
var
 leap:Boolean;
begin
 if (year<=0)  then Exit(SCE_RTC_ERROR_INVALID_YEAR);
 if (month<=0) then Exit(SCE_RTC_ERROR_INVALID_MONTH);
 if (month>12) then Exit(SCE_RTC_ERROR_INVALID_MONTH);

 leap:=leap_year(year);
 Result:=MonthDays[leap][month];
end;

function ps4_sceRtcGetDayOfWeek(year,month,day:Integer):Integer; SysV_ABI_CDecl;
var
 days:Byte;
 leap:Boolean;
begin

 if (SDK_VERSION < $3000000) then
 begin
  if (year<1)    then Exit(SCE_RTC_ERROR_INVALID_YEAR);
  if (month<=0)  then Exit(SCE_RTC_ERROR_INVALID_MONTH);
  if (month>12)  then Exit(SCE_RTC_ERROR_INVALID_MONTH);
 end else
 begin
  if (month<=0)  then Exit(SCE_RTC_ERROR_INVALID_MONTH);
  if (month>12)  then Exit(SCE_RTC_ERROR_INVALID_MONTH);
  if (year<1)    then Exit(SCE_RTC_ERROR_INVALID_YEAR);
  if (year>9999) then Exit(SCE_RTC_ERROR_INVALID_YEAR);
 end;

 leap:=leap_year(year);
 days:=MonthDays[leap][month];

 if ((day <= 0) or (day > days)) then Exit(SCE_RTC_ERROR_INVALID_DAY);

 if ((month-1)<2) then
 begin
  month:=month+12;
  year :=year -1;
 end;

 Result := Integer( (13 * month + 8) div 5
                     - (year div 100)
                     + year + (year div 4) + (year div 400)
                     + day)
                    mod 7;

end;

function ps4_sceRtcCheckValid(pTime:pSceRtcDateTime):Integer; SysV_ABI_CDecl;
begin
 Result:=_sceRtcCheckValid(pTime);
end;

function ps4_sceRtcSetDosTime(pTime:pSceRtcDateTime;uiDosTime:DWORD):Integer; SysV_ABI_CDecl;
var
 days:Word;
begin
 if (pTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 pTime^.microsecond:= 0;
 pTime^.second     := (uiDosTime shl 1) and $3e;
 pTime^.minute     := (uiDosTime shr 5) and $3f;
 pTime^.hour       := (uiDosTime and $f800) shr $b;

 days := uiDosTime shr $10;

 pTime^.day        := (days and $1f);
 pTime^.month      := (days shr 5) and $f;
 pTime^.year       := (days shr 9) + $7bc;

 Result:=0
end;

function ps4_sceRtcGetDosTime(pTime:pSceRtcDateTime;puiDosTime:PDWORD):Integer; SysV_ABI_CDecl;
var
 days:Word;
 year:Word;
 month:Word;
begin
 if (puiDosTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);
 Result:=_sceRtcCheckValid(pTime);
 if (Result<>0) then Exit;

 year := pTime^.year;

 month := pTime^.month;

 days := pTime^.day;

 if (year < 1980) then
 begin
  puiDosTime^ := 0;
 end else
 begin
  if (year < 2108) then
  begin
   puiDosTime^ := ((pTime^.second shr 1) and $1f) or
                  ((pTime^.minute and $3f) shl 5) or
                  ((pTime^.hour and $1f) shl $b) or
                  (((month and $f) * $20 + $8800 + (year * $200) or (days and $1f)) shl $10);
   Exit(0);
  end;
  puiDosTime^ := $ff9fbf7d;
 end;
 Result := SCE_RTC_ERROR_INVALID_YEAR;

end;

function ps4_sceRtcSetWin32FileTime(pTime:pSceRtcDateTime;ulWin32Time:QWORD):Integer; SysV_ABI_CDecl;
var
 tick:QWORD;
begin
 if (pTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 tick:=(ulWin32Time div 10) + $b36168b6a58000;
 ps4_sceRtcSetTick(pTime,@tick);

 Result:=0;
end;

function ps4_sceRtcGetWin32FileTime(pTime:pSceRtcDateTime;pulWin32Time:PQWORD):Integer; SysV_ABI_CDecl;
var
 tick:qword;
begin
 if (pulWin32Time=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);
 Result:=_sceRtcCheckValid(pTime);
 if (Result<>0) then Exit;

 Result:=_sceRtcGetTick(pTime,@tick);

 if (tick < $b36168b6a58000) then
 begin
  pulWin32Time^:=0;
  Result:=(-Integer(pTime^.year<1601)*5)+(SCE_RTC_ERROR_INVALID_VALUE);
 end else
 begin
  pulWin32Time^:=tick*10+-$701ce1722770000;
 end;
end;

function ps4_sceRtcSetTime_t(pTime:pSceRtcDateTime;iTime:Int64):Integer; SysV_ABI_CDecl;
var
 tick:QWORD;
begin
 if (SDK_VERSION<$3000000) then
 begin
  iTime:=iTime and $ffffffff;
 end else
 if (iTime<0) then
 begin
  Exit(SCE_RTC_ERROR_INVALID_VALUE);
 end;

 if (pTime=nil) then
 begin
  Exit(SCE_RTC_ERROR_INVALID_POINTER);
 end else
 begin
  tick:=iTime*1000000+$dcbffeff2bc000;
  ps4_sceRtcSetTick(pTime,@tick);
  Result:=0;
 end;
end;

function ps4_sceRtcGetTime_t(pTime:pSceRtcDateTime;piTime:PInt64):Integer; SysV_ABI_CDecl;
var
 tick:QWORD;
begin
 if (piTime=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);
 Result:=_sceRtcCheckValid(pTime);
 if (Result<>0) then Exit;

 Result:=_sceRtcGetTick(pTime,@tick);

 if (tick < $dcbffeff2bc000) then
 begin
  piTime^:=0;
  Result :=(-Integer(pTime^.year<1970)*5)+(SCE_RTC_ERROR_INVALID_VALUE);
 end else
 begin
  piTime^:=(tick+$ff23400100d44000) div 1000000;
 end

end;

function ps4_sceRtcCompareTick(pTick0,pTick1:PQWORD):Integer; SysV_ABI_CDecl;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);
 Result:=-1;
 if (pTick1^<=pTick0^) then
 begin
  Result:=(-Integer(pTick1^<pTick0^)) and 1;
 end;
end;

function ps4_sceRtcTickAddMonths(pTick0,pTick1:PQWORD;iAdd:Integer):Integer; SysV_ABI_CDecl;
var
 Time:SceRtcDateTime;
 TempMonth,S:Integer;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 if (iAdd=0) then
 begin
  pTick0^:=pTick1^;
  Exit(0);
 end;

 ps4_sceRtcSetTick(@Time,pTick1);

 If (iAdd>=0) then
 begin
  s:=1
 end else
 begin
  s:=-1;
 end;

 inc(Time.Year,(iAdd div 12));
 TempMonth:=Time.Month+(iAdd mod 12)-1;

 if (TempMonth>11) or
    (TempMonth<0) then
 begin
  Dec(TempMonth,S*12);
  Inc(Time.Year,S);
 end;

 Time.Month:=TempMonth+1;

 If (Time.Day>MonthDays[leap_year(Time.Year)][Time.Month]) then
 begin
  Time.Day:=MonthDays[leap_year(Time.Year)][Time.Month];
 end;

 Result:=_sceRtcCheckValid(@Time);
 if (Result<>0) then Exit;

 Result:=_sceRtcGetTick(@Time,pTick0);
end;

function ps4_sceRtcTickAddYears(pTick0,pTick1:PQWORD;iAdd:Integer):Integer; SysV_ABI_CDecl;
var
 Time:SceRtcDateTime;
begin
 if (pTick0=nil) or (pTick1=nil) then Exit(SCE_RTC_ERROR_INVALID_POINTER);

 if (iAdd=0) then
 begin
  pTick0^:=pTick1^;
  Exit(0);
 end;

 ps4_sceRtcSetTick(@Time,pTick1);

 Inc(Time.Year,iAdd);

 Result:=_sceRtcCheckValid(@Time);
 if (Result<>0) then Exit;

 Result:=_sceRtcGetTick(@Time,pTick0);
end;

//

function ps4_sceRtcParseRFC3339(pUtc:PQWORD;pszDateTime:PChar):Integer; SysV_ABI_CDecl;
label
 _next;
var
 ret1:Integer;
 mmul:DWORD;
 gmt :Integer;
 chr:Char;
 pnext:PChar;
 time:SceRtcDateTime;
begin
 ret1:=SCE_RTC_ERROR_INVALID_ARG;
 if (pUtc <> nil) and (pszDateTime <> nil) then
 begin
  time.year:=$ffff;
  if ((ord(pszDateTime[0]) - ord('0')) < 10) then
  begin
   time.year:=$ffff;
   if ((ord(pszDateTime[1]) - ord('0')) < 10) then
   begin
    time.year:=$ffff;
    if ((ord(pszDateTime[2]) - ord('0')) < 10) then
    begin
     time.year:=$ffff;
     if ((ord(pszDateTime[3]) - ord('0')) < 10) then
     begin
      time.year:=ord(pszDateTime[3]) + 12208 +
            ord(pszDateTime[2]) * 10 + ord(pszDateTime[0]) * 1000 + ord(pszDateTime[1]) * 100;
     end;
    end;
   end;
  end;
  ret1:=SCE_RTC_ERROR_INVALID_YEAR;
  if (pszDateTime[4]='-') then
  begin
   time.month:=$ffff;
   if ((ord(pszDateTime[5]) - ord('0')) < 10) then
   begin
    time.month:=$ffff;
    if ((ord(pszDateTime[6]) - ord('0')) < 10) then
    begin
     time.month:=ord(pszDateTime[5]) * 10 - 528 + ord(pszDateTime[6]);
    end;
   end;
   ret1:=SCE_RTC_ERROR_INVALID_MONTH;
   if (pszDateTime[7]='-') then
   begin
    time.day:=$ffff;
    if ((ord(pszDateTime[8]) - ord('0')) < 10) then
    begin
     time.day:=$ffff;
     if ((ord(pszDateTime[9]) - ord('0')) < 10) then
     begin
      time.day:=ord(pszDateTime[8]) * 10 - 528 + ord(pszDateTime[9]);
     end;
    end;
    ret1:=SCE_RTC_ERROR_INVALID_DAY;
    if ((ord(pszDateTime[10]) or $20)=ord('t')) then
    begin
     time.hour:=$ffff;
     if ((ord(pszDateTime[11]) - ord('0')) < 10) then
     begin
      time.hour:=$ffff;
      if ((ord(pszDateTime[12]) - ord('0')) < 10) then
      begin
       time.hour:=ord(pszDateTime[11]) * 10 - 528 + ord(pszDateTime[12]);
      end;
     end;
     ret1:=SCE_RTC_ERROR_INVALID_HOUR;
     if (pszDateTime[13]=':') then
     begin
      time.minute:=$ffff;
      if ((ord(pszDateTime[14]) - ord('0')) < 10) then
      begin
       time.minute:=$ffff;
       if ((ord(pszDateTime[15]) - ord('0')) < 10) then
       begin
        time.minute:=ord(pszDateTime[14]) * 10 - 528 + ord(pszDateTime[15]);
       end;
      end;
      ret1:=SCE_RTC_ERROR_INVALID_MINUTE;
      if (pszDateTime[16]=':') then
      begin
       time.second:=$ffff;
       if ((ord(pszDateTime[17]) - ord('0')) < 10) then
       begin
        time.second:=$ffff;
        if ((ord(pszDateTime[18]) - ord('0')) < 10) then
        begin
         time.second:=ord(pszDateTime[17]) * 10 - 528 + ord(pszDateTime[18]);
        end;
       end;
       chr:=pszDateTime[19];
       if (chr='.') then
       begin
        chr:=pszDateTime[20];
        pnext:=pszDateTime + 20;
        time.microsecond:=0;
        if ((ord(chr) - ord('0')) < 10) then
        begin
         mmul:=100000;
         repeat
          time.microsecond:=(ord(chr) - 48) * mmul + time.microsecond;
          if (mmul < 100000) then
          begin
           if (mmul < 10000) then
           begin
            if (mmul=10) then
            begin
             mmul:=1;
            end else
            if (mmul=100) then
            begin
             mmul:=10;
            end else
            begin
             if (mmul <> 1000) then
             begin
              mmul:=0;
              goto _next;
             end;
             mmul:=100;
            end;
           end else
           begin
            if (mmul <> 10000) then
            begin
             mmul:=0;
             goto _next;
            end;
            mmul:=1000;
           end;
          end else
          begin
           if (mmul <> 100000) then
           begin
            mmul:=0;
            goto _next;
           end;
           mmul:=10000;
          end;
    _next:
          chr:=pnext[1];
          pnext:=pnext + 1;
         until ((ord(chr) - 48) >= 10)
        end;
        chr:=pnext[0];
       end else
       begin
        pnext:=pszDateTime + 19;
        time.microsecond:=0;
       end;
       ret1:=0;
       if (chr < 'z') then
       begin
        if ((chr='+') or (chr='-')) then
        begin
         ret1:=-1;
         gmt:=-1;
         if ((ord(pnext[1]) - ord('0')) < 10) then
         begin
          gmt:=-1;
          if ((ord(pnext[2]) - ord('0')) < 10) then
          begin
           gmt:=ord(pnext[1]) * 10 - 528 + ord(pnext[2]);
          end;
         end;
         if ((ord(pnext[4]) - ord('0')) < 10) then
         begin
          ret1:=-1;
          if ((ord(pnext[5]) - ord('0')) < 10) then
          begin
           ret1:=ord(pnext[4]) * 10 - 528 + ord(pnext[5]);
          end;
         end;
         if (gmt < 0) then
         begin
          Exit(SCE_RTC_ERROR_BAD_PARSE);
         end;
         if (pnext[3] <> ':') then
         begin
          Exit(SCE_RTC_ERROR_BAD_PARSE);
         end;
         if (ret1 < 0) then
         begin
          Exit(SCE_RTC_ERROR_BAD_PARSE);
         end;
         ret1:=ret1 + gmt * 60;
         if (chr='-') then
         begin
          ret1:=-ret1;
         end;
        end else
        begin
         ret1:=0;
         if (chr <> 'Z') then
         begin
          Exit(SCE_RTC_ERROR_BAD_PARSE);
         end;
        end;
       end else
       if (chr <> 'z') then
       begin
        Exit(SCE_RTC_ERROR_BAD_PARSE);
       end;
       ps4_sceRtcGetTick(@time,pUtc);
       ps4_sceRtcTickAddMinutes(pUtc,pUtc,-ret1);
       ret1:=0;
      end;
     end;
    end;
   end;
  end;
 end;
 Result:=ret1;
end;

//

const
 ParseDay_aucDayLen:array[0..6] of Byte=(
  6,6,7,9,
  8,6,8);

 ParseMonth_aucMonthLen:array[0..11] of Byte=(
  7,8,5,5,
  3,4,4,6,
  9,7,8,8);

type
 t_tzinfo=packed record
  p:Byte;
  s:Byte;
  r:SmallInt;
 end;

const
 ParseTimezone_tzinfo:array[0..69] of t_tzinfo=(
  (p:$00;s:$03;r:SmallInt($0000)),
  (p:$03;s:$03;r:SmallInt($fed4)),
  (p:$06;s:$03;r:SmallInt($ff10)),
  (p:$09;s:$03;r:SmallInt($fe98)),
  (p:$0c;s:$03;r:SmallInt($fed4)),
  (p:$0f;s:$03;r:SmallInt($fe5c)),
  (p:$12;s:$03;r:SmallInt($fe98)),
  (p:$15;s:$03;r:SmallInt($fe20)),
  (p:$18;s:$03;r:SmallInt($fe5c)),
  (p:$1b;s:$04;r:SmallInt($030c)),
  (p:$1f;s:$04;r:SmallInt($02d0)),
  (p:$23;s:$04;r:SmallInt($02d0)),
  (p:$27;s:$03;r:SmallInt($02d0)),
  (p:$2a;s:$05;r:SmallInt($0294)),
  (p:$2f;s:$05;r:SmallInt($0276)),
  (p:$34;s:$04;r:SmallInt($0276)),
  (p:$38;s:$04;r:SmallInt($0276)),
  (p:$3c;s:$04;r:SmallInt($0258)),
  (p:$40;s:$04;r:SmallInt($0258)),
  (p:$44;s:$03;r:SmallInt($0258)),
  (p:$47;s:$04;r:SmallInt($0258)),
  (p:$4b;s:$04;r:SmallInt($023a)),
  (p:$4f;s:$04;r:SmallInt($023a)),
  (p:$53;s:$04;r:SmallInt($023a)),
  (p:$57;s:$05;r:SmallInt($021c)),
  (p:$5c;s:$03;r:SmallInt($021c)),
  (p:$5f;s:$03;r:SmallInt($021c)),
  (p:$62;s:$03;r:SmallInt($021c)),
  (p:$65;s:$02;r:SmallInt($01fe)),
  (p:$67;s:$04;r:SmallInt($01e0)),
  (p:$6b;s:$03;r:SmallInt($01e0)),
  (p:$6e;s:$04;r:SmallInt($01e0)),
  (p:$72;s:$03;r:SmallInt($01e0)),
  (p:$75;s:$02;r:SmallInt($01c2)),
  (p:$77;s:$04;r:SmallInt($01a4)),
  (p:$7b;s:$02;r:SmallInt($00d2)),
  (p:$7d;s:$02;r:SmallInt($00b4)),
  (p:$7f;s:$06;r:SmallInt($00b4)),
  (p:$85;s:$03;r:SmallInt($0078)),
  (p:$88;s:$06;r:SmallInt($0078)),
  (p:$8e;s:$03;r:SmallInt($0078)),
  (p:$91;s:$03;r:SmallInt($0078)),
  (p:$94;s:$04;r:SmallInt($0078)),
  (p:$98;s:$06;r:SmallInt($0078)),
  (p:$9e;s:$03;r:SmallInt($0078)),
  (p:$a1;s:$03;r:SmallInt($003c)),
  (p:$a4;s:$03;r:SmallInt($003c)),
  (p:$a7;s:$03;r:SmallInt($003c)),
  (p:$aa;s:$03;r:SmallInt($003c)),
  (p:$ad;s:$03;r:SmallInt($003c)),
  (p:$b0;s:$04;r:SmallInt($003c)),
  (p:$b4;s:$03;r:SmallInt($003c)),
  (p:$b7;s:$03;r:SmallInt($003c)),
  (p:$ba;s:$03;r:SmallInt($003c)),
  (p:$bd;s:$03;r:SmallInt($003c)),
  (p:$c0;s:$06;r:SmallInt($003c)),
  (p:$c6;s:$03;r:SmallInt($0000)),
  (p:$c9;s:$03;r:SmallInt($ffc4)),
  (p:$cc;s:$03;r:SmallInt($ffa6)),
  (p:$cf;s:$03;r:SmallInt($ff4c)),
  (p:$d2;s:$03;r:SmallInt($ff6a)),
  (p:$d5;s:$03;r:SmallInt($ff6a)),
  (p:$d8;s:$03;r:SmallInt($ff10)),
  (p:$db;s:$03;r:SmallInt($fe20)),
  (p:$de;s:$03;r:SmallInt($fde4)),
  (p:$e1;s:$03;r:SmallInt($fde4)),
  (p:$e4;s:$04;r:SmallInt($fda8)),
  (p:$e8;s:$03;r:SmallInt($fda8)),
  (p:$eb;s:$02;r:SmallInt($fd6c)),
  (p:$ed;s:$04;r:SmallInt($fd30))
 );

function ps4_sceRtcParseDateTime(pUtc:PQWORD;pszDateTime:PChar):Integer; SysV_ABI_CDecl;
label
 _prev_week1,
 _prev_month,
 _next_month1,
 _next_week1,
 _next_week2,
 _next_month2,
 _next_month3,
 _relse,
 _next_tz,
 _end_ret;

var
 pos7:DWORD;
 pos6:Integer;
 ret1:Integer;
 pc1 :Pchar;
 pos3:Int64;
 pos2:QWORD;
 pos5:Int64;
 pstrDay:Pchar;
 pstrTzAbbr:Pchar;
 pos1:Int64;
 chr1:Char;
 chr2:Char;
 chr3:Char;
 pc2 :Pchar;
 pc3 :Pchar;
 pc4 :Pchar;
 pos4:QWORD;
 time:SceRtcDateTime;

begin
 if (pUtc=nil) then
 begin
  Exit(SCE_RTC_ERROR_INVALID_ARG);
 end;
 if (pszDateTime=nil) then
 begin
  Exit(SCE_RTC_ERROR_INVALID_ARG);
 end;
 time:=Default(SceRtcDateTime);
 repeat
  repeat
   pc1:=pszDateTime;
   chr1:=pc1[0];
   pszDateTime:=pc1 + 1;
  until (ord(chr1)<>9);
 until (chr1<>' ');
 pc2:=pc1 + 3;
 if (((((ord(chr1) - ord('0')) < 10) and ((ord(pc1[1]) - ord('0')) < 10)) and ((ord(pc1[2]) - ord('0')) < 10))
   and ((((ord(pc1[3]) - ord('0')) < 10) and
     (ord(pc1[2]) * 10 + ord(chr1) * 1000 + ord(pc1[1]) * 100 + ord(pc1[3]) <> $d04f)))) then
 begin
  Exit(ps4_sceRtcParseRFC3339(pUtc,pc1));
 end;
 pos1:=0;
 pstrDay:='SundayMondayTuesdayWednesdayThursdayFridaySaturday';
 repeat
  if (6 < pos1) then
  begin
   Exit(SCE_RTC_ERROR_BAD_PARSE);
  end;
  pos2:=ParseDay_aucDayLen[pos1];
  pos3:=0;
  pos4:=pos2;
  repeat
   if (int64(pos4) < 1) then
   begin
    pc2:=pc1 + pos2;
    goto _next_month1;
   end;
   if (((ord(pc1[pos3]) xor ord(pstrDay[pos3])) and $df) <> 0) then break;
   pos3:=pos3 + 1;
   pos4:=pos4 - 1;
  until false;
  pos5:=3;
  pos3:=0;
  repeat
   if (int64(pos5) < 1) then goto _next_month1;
   if (((ord(pc1[pos3]) xor ord(pstrDay[pos3])) and $df) <> 0) then break;
   pos3:=pos3 + 1;
   pos5:=pos5 - 1;
  until false;
  pstrDay:=pstrDay + pos2;
  pos1:=pos1 + 1;
 until false;
 _prev_week1:
 pos5:=pos5 + 1;
 pos3:=pos3 - 1;
 goto _next_week1;
_prev_month:
 pc2:=(pc2 + pos2);
 time.month:=time.month + 1;
 pos1:=pos1 + 1;
 goto _next_month2;
_next_month1:
 ret1:=SCE_RTC_ERROR_BAD_PARSE;
 if (pc2 <> nil) then
 begin
  pc1:=pc2 + 1;
  if (pc2[0] <> ',') then
  begin
   pc1:=pc2;
  end;
  repeat
   repeat
    pc2:=pc1;
    pc1:=pc2 + 1;
   until (pc2[0]<>'\t');
  until (pc2[0]<>' ');
  time.month:=1;
  pstrDay:='JanuaryFebruaryMarchAprilMayJuneJulyAugustSeptemberOctoberNovemberDecember';
  For pos1:=0 to 11 do
  begin
   pos2:=ParseMonth_aucMonthLen[pos1];
   pos3:=0;
   pos4:=pos2;
   repeat
    if (int64(pos4) < 1) then
    begin
     pstrDay:=pc2 + pos2;
     goto _next_week2;
    end;
    if (((ord(pc2[pos3]) xor ord(pstrDay[pos3])) and $df) <> 0) then break;
    pos3:=pos3 + 1;
    pos4:=pos4 - 1;
   until false;
   pos5:=0;
   pos3:=3;
_next_week1:
   if (int64(pos3) < 1) then
   begin
    pstrDay:=pc2 + 3;
_next_week2:
    if (pstrDay=nil) then break;
    if (pstrDay[0] <> ' ') then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    chr1:=pstrDay[2];
    ret1:=ord(pstrDay[1]);
    if (ret1=ord(' ')) then
    begin
     ret1:=ord(chr1) - ord('0');
     if (9 < ret1) then
     begin
      Exit(SCE_RTC_ERROR_BAD_PARSE);
     end;
     pstrDay:=pstrDay + 3;
    end else
    begin
     if (9 < (ord(pstrDay[1]) - ord('0'))) then
     begin
      Exit(SCE_RTC_ERROR_BAD_PARSE);
     end;
     if ((ord(chr1) - ord('0')) < 10) then
     begin
      ret1:=ret1 * 10 - 528 + ord(chr1);
      pstrDay:=pstrDay + 3;
     end else
     begin
      pstrDay:=pstrDay + 2;
      ret1:=ret1 - ord('0');
     end;
     if (pstrDay=nil) then
     begin
      Exit(SCE_RTC_ERROR_BAD_PARSE);
     end;
    end;
    time.day:=ret1;
    if (pstrDay[0] <> ' ') then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    chr1:=pstrDay[1];
    if (9 < (ord(chr1) - ord('0'))) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if ((ord(pstrDay[2]) - ord('0')) < 10) then
    begin
     time.hour:=ord(chr1) * 10 - 528 + ord(pstrDay[2]);
     pstrDay:=pstrDay + 3;
    end else
    begin
     pstrDay:=pstrDay + 2;
     time.hour:=ord(chr1) - ord('0');
    end;
    if (pstrDay=nil) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if (pstrDay[0] <> ':') then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    chr1:=pstrDay[1];
    if (9 < (ord(chr1) - ord('0'))) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if ((ord(pstrDay[2]) - ord('0')) < 10) then
    begin
     time.minute:=ord(chr1) * 10 - 528 + ord(pstrDay[2]);
     pstrDay:=pstrDay + 3;
    end else
    begin
     pstrDay:=pstrDay + 2;
     time.minute:=ord(chr1) - ord('0');
    end;
    if (pstrDay=nil) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if (pstrDay[0] <> ':') then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    chr1:=pstrDay[1];
    if (9 < (ord(chr1) - ord('0'))) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if ((ord(pstrDay[2]) - ord('0')) < 10) then
    begin
     time.second:=ord(chr1) * 10 - 528 + ord(pstrDay[2]);
     pstrDay:=pstrDay + 3;
    end else
    begin
     pstrDay:=pstrDay + 2;
     time.second:=ord(chr1) - ord('0');
    end;
    if (pstrDay=nil) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if (pstrDay[0] <> ' ') then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if (9 < (ord(pstrDay[1]) - ord('0'))) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if (9 < (ord(pstrDay[2]) - ord('0'))) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if (9 < (ord(pstrDay[3]) - ord('0'))) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    if (9 < (ord(pstrDay[4]) - ord('0'))) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    ret1:=ord(pstrDay[3]) * 10 + ord(pstrDay[1]) * 1000 + ord(pstrDay[2]) * 100 + ord(pstrDay[4]) - 53328;
    if (ret1 < 0) then
    begin
     Exit(SCE_RTC_ERROR_BAD_PARSE);
    end;
    time.year:=ret1;
    ret1:=0;
    goto _end_ret;
   end;
   if (((ord(pc2[pos5]) xor ord(pstrDay[pos5])) and $df)=0) then goto _next_week1;
   pstrDay:=pstrDay + pos2;
   time.month:=time.month + 1;
  end;
  chr1:=pc2[0];
  ret1:=SCE_RTC_ERROR_BAD_PARSE;
  if ((ord(chr1) - ord('0')) < 10) then
  begin
   if ((ord(pc1[0]) - ord('0')) < 10) then
   begin
    time.day:=ord(chr1) * 10 - 528 + ord(pc1[0]);
    pc1:=pc2 + 2;
   end else
   begin
    time.day:=ord(chr1) - ord('0');
   end;
   ret1:=SCE_RTC_ERROR_BAD_PARSE;
   if (pc1 <> nil) then
   begin
    time.month:=1;
    pc2:='JanuaryFebruaryMarchAprilMayJuneJulyAugustSeptemberOctoberNovemberDecember';
    pos1:=0;
    ret1:=SCE_RTC_ERROR_BAD_PARSE;
    if ((pc1[0]=' ') or (pc1[0]='-')) then
    begin
_next_month2:
     ret1:=SCE_RTC_ERROR_BAD_PARSE;
     if (integer(pos1) < 12) then
     begin
      pos2:=ParseMonth_aucMonthLen[pos1];
      pos4:=pos2;
      pc3:=pc2;
      pc4:=(pc1 + 1);
      repeat
       if (int64(pos4) < 1) then
       begin
        pc1:=pc1 + pos2 + 1;
        goto _next_month3;
       end;
       if (((ord(pc4[0]) xor ord(pc3[0])) and $df) <> 0) then break;
       pos4:=pos4 - 1;
       pc3:=pc3 + 1;
       pc4:=pc4 + 1;
      until false;
      pc3:=(pc1 + 1);
      pc4:=pc2;
      For pos3:=3 downto 1 do
      begin
       if (((ord(pc3[0]) xor ord(pc4[0])) and $df) <> 0) then goto _prev_month;
       pc4:=pc4 + 1;
       pc3:=pc3 + 1;
      end;
      pc1:=pc1 + 4;
_next_month3:
      if (pc1=nil) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      if ((pc1[0] <> ' ') and (pc1[0] <> '-')) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      chr1:=pc1[1];
      if (9 < (ord(chr1) - ord('0'))) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      chr2:=pc1[2];
      if (((((ord(chr2) - ord('0')) < 10) and ((ord(pc1[3]) - ord('0')) < 10)) and
        ((ord(pc1[4]) - ord('0')) < 10)) and
        (-1 < ret1)) then
      begin
       ret1:=ord(pc1[3]) * 10 + ord(chr1) * 1000 + ord(chr2) * 100 + ord(pc1[4]) - 53328;
       if (ret1 >= -1) then goto _relse;
       pc1:=pc1 + 5;
      end else
      begin
_relse:
       if (9 < (ord(chr2) - ord('0'))) then
       begin
        Exit(SCE_RTC_ERROR_BAD_PARSE);
       end;
       pos6:=ord(chr1) * 10 + ord(chr2) - 528;
       if (pos6 < 0) then
       begin
        Exit(SCE_RTC_ERROR_BAD_PARSE);
       end;
       pc1:=pc1 + 3;
       ret1:=1900;
       if (pos6 < 50) then
       begin
        ret1:=2000;
       end;
       ret1:=ret1 + pos6;
      end;
      time.year:=ret1;
      if (pc1[0] <> ' ') then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      chr1:=pc1[1];
      if (9 < (ord(chr1) - ord('0'))) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      if ((ord(pc1[2]) - ord('0')) < 10) then
      begin
       ret1:=ord(chr1) * 10 - 528 + ord(pc1[2]);
       pc1:=pc1 + 3;
      end else
      begin
       pc1:=pc1 + 2;
       ret1:=ord(chr1) - ord('0');
      end;
      if (pc1=nil) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      if (25 < ret1) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      time.hour:=ret1;
      if (pc1[0] <> ':') then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      chr1:=pc1[1];
      if (9 < (ord(chr1) - ord('0'))) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      if ((ord(pc1[2]) - ord('0')) < 10) then
      begin
       time.minute:=ord(chr1) * 10 - 528 + ord(pc1[2]);
       pc1:=pc1 + 3;
      end else
      begin
       pc1:=pc1 + 2;
       time.minute:=ord(chr1) - ord('0');
      end;
      if (pc1=nil) then
      begin
       Exit(SCE_RTC_ERROR_BAD_PARSE);
      end;
      time.second:=0;
      ret1:=0;
      if (pc1[0]=' ') then
      begin
       pc1:=pc1 + 1;
      end else
      begin
       if (pc1[0] <> ':') then
       begin
        Exit(SCE_RTC_ERROR_BAD_PARSE);
       end;
       chr1:=pc1[1];
       if (9 < (ord(chr1) - ord('0'))) then
       begin
        Exit(SCE_RTC_ERROR_BAD_PARSE);
       end;
       if ((ord(pc1[2]) - ord('0')) < 10) then
       begin
        time.second:=ord(chr1) * 10 - 528 + ord(pc1[2]);
        pc1:=pc1 + 3;
       end else
       begin
        pc1:=pc1 + 2;
        time.second:=ord(chr1) - ord('0');
       end;
       if (pc1=nil) then
       begin
        Exit(SCE_RTC_ERROR_BAD_PARSE);
       end;
      end;
      if (pc1[0]=' ') then
      begin
       pc3:=(pc1 + 1);
       chr3:=pc3[0];
       ret1:=0;
       if (chr3 <> 'U') then
       begin
        if ((chr3='-') or (chr3='+')) then
        begin
         ret1:=-1;
         if ((ord(pc1[2]) - ord('0')) < 10) then
         begin
          ret1:=-1;
          if ((ord(pc1[3]) - ord('0')) < 10) then
          begin
           ret1:=-1;
           if ((ord(pc1[4]) - ord('0')) < 10) then
           begin
            ret1:=-1;
            if ((ord(pc1[5]) - ord('0')) < 10) then
            begin
             ret1:=ord(pc1[5]) - 53328 + ord(pc1[4]) * 10 + ord(pc1[2]) * 1000 + ord(pc1[3]) * 100;
            end;
           end;
          end;
         end;
         ret1:=ret1 mod 60 + (ret1 div 100) * 60;
         if (chr3='-') then
         begin
          ret1:=-ret1;
         end;
        end else
        begin
         ret1:=0;
         if (pc1[2] <> 'T') then
         begin
          For pos1:=0 to 69 do
          begin
           pstrTzAbbr:='GMTESTEDTCSTCDTMSTMDTPSTPDTNZDTNZSTIDLENZTAESSTACSSTCADTSADTAEST EASTGSTLIGTACSTSASTCASTAWSSTJSTKSTWDTMTAWSTCCTWADTWSTJTWASTITBTEETDSTEETCETDST FWTISTMESTMETDSTSSTBSTCETDNTFSTMETMEWTMEZNORSETSWTWETDSTWETWATNDTADTNFTNSTASTY DTHDTYSTAHSTCATNTIDLW';
           pstrTzAbbr:=pstrTzAbbr + ParseTimezone_tzinfo[pos1].p;
           pc4:=pc3;
           pos4:=ParseTimezone_tzinfo[pos1].s;
           repeat
            if (int64(pos4) < 1) then
            begin
             if (ptrint(pc1 + ParseTimezone_tzinfo[pos1].s) <> ptrint(-1)) then
             begin
              ret1:=ParseTimezone_tzinfo[pos1].r;
              goto _end_ret;
             end;
             goto _next_tz;
            end;
            if (((ord(pc4[0]) xor ord(pstrTzAbbr[0])) and $df) <> 0) then break;
            pos4:=pos4 - 1;
            pstrTzAbbr:=pstrTzAbbr + 1;
            pc4:=pc4 + 1;
           until false;
          end;
_next_tz:
          pos7:=ord(pc3[0]) and $ffffffdf;
          if ((((ord(pc3[0]) and $df) + $bf) < 9) or
            ((byte(pos7) + $b5) < 3)) then
          begin
           ret1:=pos7 * 60 - 3900;
          end else
          if ((ord(chr1) + $b2) < 12) then
          begin
           ret1:=(78 - pos7) * 60;
          end else
          begin
           ret1:=0;
           if (chr1 <> 'Z') then
           begin
            Exit(SCE_RTC_ERROR_BAD_PARSE);
           end
          end;
         end;
        end;
       end;
      end;
_end_ret:
      time.microsecond:=0;
      ps4_sceRtcGetTick(@time,pUtc);
      ps4_sceRtcTickAddMinutes(pUtc,pUtc,-ret1);
      ret1:=0;
     end;
    end;
   end;
  end;
 end;
 Result:=ret1;
end;

//

function Load_libSceRtc(Const name:RawByteString):TElf_node;
var
 lib:PLIBRARY;
begin
 Result:=TElf_node.Create;
 Result.pFileName:=name;

 lib:=Result._add_lib('libSceRtc');

 lib^.set_proc($05A38A72783C83CF,@ps4_module_start);
 lib^.set_proc($2A90CCACF1EFB774,@ps4_module_stop);
 lib^.set_proc($2E5A1D08C0DB937A,@ps4_sceRtcInit);
 lib^.set_proc($F12963431EA90CFF,@ps4_sceRtcEnd);
 lib^.set_proc($02A54CB2CAF9D917,@ps4_sceRtcTickAddTicks);
 lib^.set_proc($5CF222C39F02F863,@ps4_sceRtcTickAddMicroseconds);
 lib^.set_proc($D3B3B9DB91E0202B,@ps4_sceRtcTickAddSeconds);
 lib^.set_proc($9A7FED7F84221739,@ps4_sceRtcTickAddMinutes);
 lib^.set_proc($30373971DF077C20,@ps4_sceRtcTickAddHours);
 lib^.set_proc($351D49D0DECBDB16,@ps4_sceRtcTickAddDays);
 lib^.set_proc($808E2DD7DE1CD96F,@ps4_sceRtcTickAddWeeks);
 lib^.set_proc($7C52E098D5290A18,@ps4_sceRtcSetConf);
 lib^.set_proc($7787C72C21A663CD,@ps4_sceRtcSetCurrentTick);
 lib^.set_proc($D7C076352D72F545,@ps4_sceRtcGetCurrentTick);
 lib^.set_proc($B9E7A06BABF7194C,@ps4_sceRtcSetTick);
 lib^.set_proc($F30FC7D7D8A9E3C2,@ps4_sceRtcGetTick);
 lib^.set_proc($F257EF9D132AC043,@ps4_sceRtcGetCurrentClock);
 lib^.set_proc($64F0F560E288F8AC,@ps4_sceRtcGetCurrentClockLocalTime);
 lib^.set_proc($3354EF16CB7F8EB3,@ps4_sceRtcConvertUtcToLocalTime);
 lib^.set_proc($F18AF5E37C849D1A,@ps4_sceRtcConvertLocalTimeToUtc);
 lib^.set_proc($CCEF542F7A8820D4,@ps4_sceRtcGetCurrentNetworkTick);
 lib^.set_proc($1D6C4739D6CCFCF8,@ps4_sceRtcGetCurrentRawNetworkTick);
 lib^.set_proc($3ADD431378227FCE,@ps4_sceRtcGetCurrentDebugNetworkTick);
 lib^.set_proc($2CDDD971BEF64347,@ps4_sceRtcGetCurrentAdNetworkTick);
 lib^.set_proc($AA10C1B48A3E6AEC,@ps4_sceRtcSetCurrentNetworkTick);
 lib^.set_proc($54B0D43CA9B0E4BF,@ps4_sceRtcSetCurrentDebugNetworkTick);
 lib^.set_proc($B15DAD2BEC8E8415,@ps4_sceRtcSetCurrentAdNetworkTick);
 lib^.set_proc($8CC370A98AF847F9,@ps4_sceRtcGetTickResolution);
 lib^.set_proc($520F290B042F8747,@ps4_sceRtcIsLeapYear);
 lib^.set_proc($DCEECB9FC02A275A,@ps4_sceRtcGetDaysInMonth);
 lib^.set_proc($0B220AFE2E177604,@ps4_sceRtcGetDayOfWeek);
 lib^.set_proc($94F10161D557D174,@ps4_sceRtcCheckValid);
 lib^.set_proc($6983C27757028728,@ps4_sceRtcSetDosTime);
 lib^.set_proc($13B011E28ECDCBB1,@ps4_sceRtcGetDosTime);
 lib^.set_proc($9F92620095EC6DCB,@ps4_sceRtcSetWin32FileTime);
 lib^.set_proc($8DF44ED2E4E3B730,@ps4_sceRtcGetWin32FileTime);
 lib^.set_proc($6C311554FE1B4E34,@ps4_sceRtcSetTime_t);
 lib^.set_proc($06DAA6A534571E09,@ps4_sceRtcGetTime_t);
 lib^.set_proc($7CD699E036F31C01,@ps4_sceRtcCompareTick);
 lib^.set_proc($08BEB2F6AFD76EE4,@ps4_sceRtcTickAddMonths);
 lib^.set_proc($FF9CB6B89EB6A92F,@ps4_sceRtcTickAddYears);

 lib^.set_proc($F7D6CC1A09455B72,@ps4_sceRtcParseRFC3339);
 lib^.set_proc($371108D4A072BC22,@ps4_sceRtcParseDateTime);

 ps4_module_start(0,nil);
end;

//TODO sceRtcParseDateTime
//TODO sceRtcFormatRFC2822LocalTime
//TODO sceRtcFormatRFC2822
//TODO sceRtcFormatRFC3339LocalTime
//TODO sceRtcFormatRFC3339

initialization
 ps4_app.RegistredPreLoad('libSceRtc.prx',@Load_libSceRtc);

end.


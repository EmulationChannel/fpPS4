
{$mode objfpc}{$H+}

uses
 sysutils,
 elf64 in '..\..\sys\elf64.pas';

type
 p_elf_obj=^elf_obj;
 elf_obj=packed record
  is_encrypted:Integer;
  self:record
   hdr     :p_self_header;
   segs    :p_self_segment;
   elf_hdr :p_elf64_hdr;
   MinSeg  :Int64;
   MaxSeg  :Int64;
  end;
  elf:record
   hdr :p_elf64_hdr;
   size:Int64;
  end;
  size:Int64;
  //
  min_offset:Int64;
  max_offset:Int64;
 end;

procedure free_elf_obj(obj:p_elf_obj);
begin
 if (obj=nil) then Exit;
 FreeMem(obj^.self.hdr);
 FreeMem(obj^.elf.hdr);
 obj^:=Default(elf_obj);
end;

function get_elf_phdr(elf_hdr:p_elf64_hdr):p_elf64_phdr;
begin
 if (elf_hdr=nil) then Exit(nil);
 if (elf_hdr^.e_phoff=0) then
 begin
  Result:=Pointer(elf_hdr+1);
 end else
 begin
  Result:=Pointer(elf_hdr)+elf_hdr^.e_phoff;
 end;
end;

function maxInt64(a,b:Int64):Int64; inline;
begin
 if (a>b) then Result:=a else Result:=b;
end;

function minInt64(a,b:Int64):Int64; inline;
begin
 if (a<b) then Result:=a else Result:=b;
end;

procedure fixup_offset_size(var offset,size:Int64;max:Int64);
var
 s,e:Int64;
begin
 s:=offset;
 e:=s+size;

 s:=MinInt64(s,max);
 e:=MinInt64(e,max);

 offset:=s;
 size  :=(e-s);
end;

function load_self(Const name:RawByteString;obj:p_elf_obj):Integer;
Var
 F:THandle;
 n,s:Int64;
 Magic:DWORD;
 i,count:Integer;
 is_encrypted:Integer;
 self_hdr :p_self_header;
 self_segs:p_self_segment;
 elf_hdr  :p_elf64_hdr;
 elf_phdr :p_elf64_phdr;
 MinSeg   :Int64;
 MaxSeg   :Int64;
 src_ofs  :Int64;
 dst_ofs  :Int64;
 mem_size :Int64;
begin
 Result:=0;

 if (name='') or (obj=nil) then Exit(-1);

 F:=FileOpen(name,fmOpenRead);
 if (F=feInvalidHandle) then Exit(-2);

 n:=FileRead(F,Magic,SizeOf(DWORD));
 if (n<>SizeOf(DWORD)) then
 begin
  FileClose(F);
  Exit(-3);
 end;

 case Magic of
  ELFMAG: //elf64
    begin
      obj^.size:=FileSeek(F,0,fsFromEnd);

      if (obj^.size<=0) then
      begin
       FileClose(F);
       Exit(-4);
      end;

      obj^.elf.hdr :=GetMem(obj^.size);
      obj^.elf.size:=obj^.size;

      FileSeek(F,0,fsFromBeginning);
      n:=FileRead(F,obj^.elf.hdr^,obj^.size);
      FileClose(F);

      if (n<>obj^.size) then
      begin
       FreeMem(obj^.elf.hdr);
       obj^.elf.hdr:=nil;
       Exit(-5);
      end;
    end;
  SELF_MAGIC:
    begin
      obj^.size:=FileSeek(F,0,fsFromEnd);

      if (obj^.size<=0) then
      begin
       FileClose(F);
       Exit(-4);
      end;

      self_hdr:=GetMem(obj^.size);
      obj^.self.hdr:=self_hdr;

      FileSeek(F,0,fsFromBeginning);
      n:=FileRead(F,self_hdr^,obj^.size);
      FileClose(F);

      if (n<>obj^.size) then
      begin
       FreeMem(obj^.self.hdr);
       obj^.self.hdr:=nil;
       Exit(-5);
      end;

      count:=self_hdr^.Num_Segments;

      self_segs:=Pointer(self_hdr+1);
      obj^.self.segs:=self_segs;

      is_encrypted:=0;
      if (count<>0) then
      For i:=0 to count-1 do
       if ((self_segs[i].flags and (SELF_PROPS_ENCRYPTED or SELF_PROPS_COMPRESSED))<>0) then
       begin
        is_encrypted:=1;
        Break;
       end;

      obj^.is_encrypted:=is_encrypted;

      elf_hdr:=Pointer(self_segs)+(count*SizeOf(t_self_segment));
      obj^.self.elf_hdr:=elf_hdr;

      elf_phdr:=get_elf_phdr(elf_hdr);

      MinSeg:=High(Int64);
      MaxSeg:=0;

      count:=self_hdr^.Num_Segments;

      if (count<>0) then
      For i:=0 to count-1 do
       if ((self_segs[i].flags and SELF_PROPS_BLOCKED)<>0) then
       begin
        s:=SELF_SEGMENT_INDEX(self_segs[i].flags);
        s:=elf_phdr[s].p_offset;
        MinSeg:=MinInt64(s,MinSeg);
        s:=s+minInt64(self_segs[i].filesz,self_segs[i].filesz);
        MaxSeg:=MaxInt64(s,MaxSeg);
       end;

      obj^.self.MinSeg:=MinSeg;
      obj^.self.MaxSeg:=MaxSeg;

      if (is_encrypted=0) then //load elf
      begin
       obj^.elf.hdr :=AllocMem(MaxSeg);
       obj^.elf.size:=MaxSeg;

       //elf_hdr part
       n:=ptruint(elf_hdr)-ptruint(self_hdr);        //offset to hdr
       s:=self_hdr^.Header_Size+self_hdr^.Meta_size; //offset to end
       s:=MinInt64(obj^.size,s);                     //min size
       s:=MaxInt64(s,n)-n;                           //get size

       //first page
       Move(elf_hdr^,obj^.elf.hdr^,s);

       count:=self_hdr^.Num_Segments;

       if (count<>0) then
       For i:=0 to count-1 do
        if ((self_segs[i].flags and SELF_PROPS_BLOCKED)<>0) then
        begin
         s:=SELF_SEGMENT_INDEX(self_segs[i].flags);

         mem_size:=minInt64(self_segs[i].filesz,self_segs[i].memsz);

         src_ofs:=self_segs[i].offset;  //start offset
         dst_ofs:=elf_phdr[s].p_offset; //start offset

         fixup_offset_size(src_ofs,mem_size,obj^.size);
         fixup_offset_size(dst_ofs,mem_size,MaxSeg);

         Move( (Pointer(self_hdr)    +src_ofs)^, //src
               (Pointer(obj^.elf.hdr)+dst_ofs)^, //dst
               mem_size);                        //size
        end;
      end;

    end;
  else
    begin
     FileClose(F);
     Exit(-1);
    end;
 end;

end;

Function get_bytes_str(p:PByte;size:Integer):RawByteString;
begin
 Result:='';
 while (size<>0) do
 begin
  Result:=Result+HexStr(P^,2);
  Inc(P);
  Dec(size);
 end;
end;

type
 P_TROPHY_KEY_RECORD=^T_TROPHY_KEY_RECORD;
 T_TROPHY_KEY_RECORD=packed record
  str_ptr:QWORD; //"01","00"
  key_val:Array[0..15] of Byte;
  zero   :QWORD;
 end;

//30h    0
//31h    1
//00h
//
//30h    0
//30h    0
//00h

procedure _search(obj:p_elf_obj);
var
 base:Pointer;
 size:QWORD;
 curr_ptr :Pointer;
 curr_size:QWORD;
 //
 offset :QWORD;
 str_val:DWORD;
 P_REC  :P_TROPHY_KEY_RECORD;
begin
 //
 base:=obj^.elf.hdr;
 size:=obj^.elf.size;
 //
 curr_ptr :=base;
 curr_size:=size-SizeOf(T_TROPHY_KEY_RECORD)*2;
 //
 while (curr_size<>0) do
 begin
  offset:=PQWORD(curr_ptr)^;
  offset:=offset+$4000;

  if (offset<(size-8)) then
  begin
   str_val:=PDWORD(base+offset)^;
   str_val:=str_val and $FFFFFF;

   if (str_val=$003130) then //"01"
   begin
    P_REC:=curr_ptr;

    offset:=P_REC[1].str_ptr;
    offset:=offset+$4000;

    if (offset<(size-8)) then
    begin
     str_val:=PDWORD(base+offset)^;
     str_val:=str_val and $FFFFFF;

     if (str_val=$003030) then //"00"
     begin
      Writeln('Trophy keys found!');

      Writeln('(CEX) Release:',get_bytes_str(@P_REC[0].key_val,16));
      Writeln('(DEX) Debug  :',get_bytes_str(@P_REC[1].key_val,16));

      Writeln;
      Exit;
     end;

    end;

   end;

  end;

  //
  Inc(curr_ptr);
  Dec(curr_size);
 end;

 Writeln('Trophy keys NOT found!');
end;

var
 r:Integer;
 obj:elf_obj;

 FileName:RawByteString;

begin
 DefaultSystemCodePage:=CP_UTF8;
 DefaultUnicodeCodePage:=CP_UTF8;
 DefaultFileSystemCodePage:=CP_UTF8;
 DefaultRTLFileSystemCodePage:=CP_UTF8;
 UTF8CompareLocale:=CP_UTF8;

 if (ParamCount<=1) then
 begin
  Writeln('Usage: trophy_key_export elf/self-file (SceShellCore.elf)');
 end;

 FileName:=ParamStr(1);

 r:=load_self(FileName,@obj);

 if (r=0) then
 begin
  if (obj.is_encrypted<>0) then
  begin
   Writeln('Elf is_encrypted');
  end else
  begin
   _search(@obj);
  end;
 end else
 begin
  Writeln('Error(',r,') load file:',FileName);
 end;

 readln;
end.


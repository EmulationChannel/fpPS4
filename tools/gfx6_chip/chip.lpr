
uses

 gset,
 gmap,
 Classes,
 SysUtils;

type
 TRawStrCompare=class
  class function c(var a,b:RawByteString):boolean; static;
 end;

 TSeries=object
  __SI    :Boolean; //Southern Islands  1
  __SI__CI:Boolean;
  __SI__VI:Boolean;
  __VI    :Boolean; //Volcanic Islands  2
  __CI__VI:Boolean;
  __CI    :Boolean; //Caribbean Islands 3
  function  get_prio:Integer;
  Procedure Apply(var name:RawByteString);
  function  print_name(const name:RawByteString):RawByteString;
 end;

 TConstOffset=class
  Name  :RawByteString;
  Value :RawByteString;
  Series:TSeries;
  function print_name:RawByteString;
 end;

 TMapConstOffset=specialize TMap<RawByteString,TConstOffset,TRawStrCompare>;

 TMapStr=specialize TMap<RawByteString,RawByteString,TRawStrCompare>;
 TSetStr=specialize TSet<RawByteString,TRawStrCompare>;

function ReCompareText(const S1,S2:RawByteString):sizeint;
var
 i,count1,count2: sizeint;
 Chr1, Chr2: byte;
 P1, P2: PChar;
begin
 Count1 := Length(S1);
 Count2 := Length(S2);
 if (Count1<>Count2) then Exit(Count1-Count2);
 if (Count1>0) then
 begin
   i := 0;
   P1 := @S1[1];
   P2 := @S2[1];
   while (i<Count1) do
   begin
    Chr1 := byte(p1[i]);
    Chr2 := byte(p2[i]);
    if (Chr1<>Chr2) then
    begin
     Exit(Chr1-Chr2);
    end;
    Inc(I);
   end;
 end;
end;

class function TRawStrCompare.c(var a,b:RawByteString):boolean;
begin
 Result:=ReCompareText(a,b)<0;
end;

type
 TChars=Set of AnsiChar;

function FetchAny(var Value:RawByteString;Delimiters,Quotations:TChars):RawByteString;
Var
 i:SizeUInt;
 Quote:AnsiChar;
 State:Byte;
begin
 Result:='';
 Quote:=#0;
 State:=0;
 if Length(Value)>0 then
 begin
  For i:=1 to Length(Value) do
  begin
   case State of
    0:begin
       if (Value[i] in Quotations)  then
       begin
        State:=2;
        Quote:=Value[i];
       end else
       if (Value[i] in Delimiters) then
       begin

       end else
       begin
        Result:=Result+Value[i];
        State:=1;
       end;
      end;
    1:begin
       if (Value[i] in Quotations)  then
       begin
        State:=2;
        Quote:=Value[i];
       end else
       if (Value[i] in Delimiters) then
       begin
        System.Delete(Value,1,i);
        Exit;
       end else
       begin
        Result:=Result+Value[i];
       end;
      end;
    2:begin
       if Value[i]=Quote then
       begin
        State:=3;
       end else
       begin
        Result:=Result+Value[i];
       end;
      end;
    3:begin
       if Value[i]=Quote then
       begin
        State:=2;
        Result:=Result+Quote;
       end else
       if (Value[i] in Delimiters) then
       begin
        System.Delete(Value,1,i);
        Exit;
       end else
       begin
        State:=1;
        Quote:=#0;
        Result:=Result+Value[i];
       end;
      end;
   end;
  end;
  Value:='';
 end;
end;

function CutEnd(var Value:RawByteString;const S:RawByteString):Boolean;
begin
 if Copy(Value,Length(Value)-Length(S)+1,Length(S))=S then
 begin
  Delete(Value,Length(Value)-Length(S)+1,Length(S));
  Result:=True;
 end else
 begin
  Result:=False;
 end;
end;

Procedure CutBegin(var Value:RawByteString;const S:RawByteString);
begin
 if Copy(Value,1,Length(S))=S then
 begin
  Delete(Value,1,Length(S));
 end;
end;

function BeginIs(const Value,S:RawByteString):Boolean;
begin
 Result:=Copy(Value,1,Length(S))=S;
end;

function EndIs(const Value,S:RawByteString):Boolean;
begin
 Result:=Copy(Value,Length(Value)-Length(S)+1,Length(S))=S;
end;

Var
 RMNV_offsets:TMapConstOffset;
 RMVN_offsets:TMapConstOffset;

const
 MIN_OFFSET=$2000; // $20AD;
 MAX_OFFSET=$DC46;

 //per ring
 _SH_REG_BASE = $2C00;
 _SH_REG_END  = $3000;

 SH_REG_GFX_BASE = $2C00;
 SH_REG_GFX_END  = $2E00;

 SH_REG_COMPUTE_BASE = $2E00;
 SH_REG_COMPUTE_END  = $3000;

 //8 context
 CONTEXT_REG_BASE = $A000;
 CONTEXT_REG_END  = $A400;

 //1 context
 CONFIG_SPACE_START=$2000;
 CONFIG_SPACE_END  =$BFFF;

 //1 context
 USERCONFIG_REG_BASE = $C000;
 USERCONFIG_REG_END  = $FFFF;

type
 t_ofs_group=record
  lo,hi:word;
  name:pchar;
 end;

const
 ofs_groups:array[0..4] of t_ofs_group=(
  (lo:SH_REG_GFX_BASE    ;hi:SH_REG_GFX_END    ;name:'SH_REG_GFX'),
  (lo:SH_REG_COMPUTE_BASE;hi:SH_REG_COMPUTE_END;name:'SH_REG_COMPUTE'),
  (lo:CONTEXT_REG_BASE   ;hi:CONTEXT_REG_END   ;name:'CONTEXT_REG'),
  (lo:CONFIG_SPACE_START ;hi:CONFIG_SPACE_END  ;name:'CONFIG_SPACE'),
  (lo:USERCONFIG_REG_BASE;hi:USERCONFIG_REG_END;name:'USERCONFIG_REG')
 );

function is_valid_offset(v:Integer):Boolean;
var
 i:Integer;
begin
 Result:=(v>=MIN_OFFSET) and (v<=MAX_OFFSET);
 if not Result then Exit;

 Result:=False;
 For i:=0 to High(ofs_groups) do
 begin
  if (v>=ofs_groups[i].lo) and
     (v< ofs_groups[i].hi) then
  begin
   Exit(True);
  end;
 end;
end;

function get_offset_group(v:Integer):Integer;
var
 i:Integer;
begin
 Result:=-1;
 For i:=0 to High(ofs_groups) do
 begin
  if (v>=ofs_groups[i].lo) and
     (v< ofs_groups[i].hi) then
  begin
   Exit(i);
  end;
 end;
end;

function get_group_by_name(const name:RawByteString):Integer;
var
 i:Integer;
begin
 Result:=-1;
 For i:=0 to High(ofs_groups) do
 begin
  if (ofs_groups[i].name=name) then
  begin
   Exit(i);
  end;
 end;
end;

function TSeries.get_prio:Integer;
begin
 if __SI     then
 begin
  Result:=1;
 end else
 if __SI__CI then
 begin
  Result:=5;
 end else
 if __SI__VI then
 begin
  Result:=2;
 end else
 if __VI     then
 begin
  Result:=3;
 end else
 if __CI__VI then
 begin
  Result:=4;
 end else
 if __CI     then
 begin
  Result:=-1;
 end else
 begin
  Result:=0;
 end;
end;

Procedure TSeries.Apply(var name:RawByteString);
begin
 __SI__CI:=CutEnd(Name,'__SI__CI');
 __SI__VI:=CutEnd(Name,'__SI__VI');
 __CI__VI:=CutEnd(Name,'__CI__VI');
 __SI    :=CutEnd(Name,'__SI');
 __VI    :=CutEnd(Name,'__VI');
 __CI    :=CutEnd(Name,'__CI');
end;

function TSeries.print_name(const name:RawByteString):RawByteString;
begin
 Result:=Name;
  if __SI     then Result:=Result+'__SI'    ;
  if __SI__CI then Result:=Result+'__SI__CI';
  if __SI__VI then Result:=Result+'__SI__VI';
  if __VI     then Result:=Result+'__VI'    ;
  if __CI__VI then Result:=Result+'__CI__VI';
  if __CI     then Result:=Result+'__CI'    ;
end;

function NewConstOffset(const Name,Value:RawByteString):TConstOffset;
begin
 Result:=TConstOffset.Create;
 //
 Result.Name :=Name;
 Result.Value:=Value;
 Result.Series.Apply(Result.Name);
end;

function TConstOffset.print_name:RawByteString;
begin
 Result:=Series.print_name(name);
end;

function NormalizeName(const Name:RawByteString):RawByteString;
begin
 Result:=Name;
 CutEnd(Result,'__SI__CI');
 CutEnd(Result,'__SI__VI');
 CutEnd(Result,'__CI__VI');
 CutEnd(Result,'__SI');
 CutEnd(Result,'__VI');
 CutEnd(Result,'__CI');
end;

function prior_double(const n1:TConstOffset;n2:RawByteString):Byte;
var
 tmp:TSeries;
begin
 tmp:=Default(TSeries);
 tmp.Apply(n2);

 if BeginIs(n1.name,'mmDCP0_') then
 begin
  Result:=0;
 end else
 if BeginIs(n2,'mmDCP0_') then
 begin
  Result:=1;
 end else

 if BeginIs(n1.name,'mmCRTC0_') then
 begin
  Result:=0;
 end else
 if BeginIs(n2,'mmCRTC0_') then
 begin
  Result:=1;
 end else

 if (n1.name='mmSQ_DS_0') then
 begin
  Result:=0;
 end else
 if (n2='mmSQ_DS_0') then
 begin
  Result:=1;
 end else

 if BeginIs(n1.name,'mmCP_RB0_') then
 begin
  Result:=0;
 end else
 if BeginIs(n2,'mmCP_RB0_') then
 begin
  Result:=1;
 end else

 if (n1.Series.get_prio>tmp.get_prio) then
 begin
  Result:=0;
 end else
 if (n1.Series.get_prio<tmp.get_prio) then
 begin
  Result:=1;
 end else
 begin
  Result:=2;
 end;

end;

Procedure load_offsets(const fname:RawByteString);
label
 _new_values,
 _double;
var
 L:TStringList;
 i,v:Integer;
 S,Name,Value:RawByteString;
 maxlen:Integer;
 It:TMapConstOffset.TIterator;
 ConstOffset:TConstOffset;
 F:THandle;
begin
 RMNV_offsets:=TMapConstOffset.Create;
 RMVN_offsets:=TMapConstOffset.Create;
 maxlen:=0;
 L:=TStringList.Create;
 L.LoadFromFile(fname);
 For i:=0 to L.Count -1 do
 begin
  S:=L.Strings[i];
  Case FetchAny(S,[' ',#9],[]) of
   'constexpr':
    begin
     if (FetchAny(S,[' ',#9],[])='unsigned') then
     if (FetchAny(S,[' ',#9],[])='int') then
     begin
      Name:=FetchAny(S,[' ',#9],[]);

      if (BeginIs(Name,'mm')) then
      if (not EndIs(Name,'__CI')) then

       if (FetchAny(S,[' ',#9],[])='=') then
       begin

        Value:=FetchAny(S,[' ',#9,';'],[]);
        if BeginIs(Value,'0x') then
        begin
         System.Delete(Value,1,2);
         Value:='$'+Value;
        end;

        v:=StrToIntDef(Value,0);

        if is_valid_offset(v) then
        begin
         it:=RMNV_offsets.Find(NormalizeName(Name)); //name->value
         if Assigned(It) then
         begin
          if (It.Value.Value<>Value) then
          begin
           Goto _double;
          end;
          FreeAndNil(It);
         end else
         begin
          it:=RMVN_offsets.Find(Value); //value->name
          if Assigned(It) then
          begin
           if (It.Value.Name<>Name) then
           begin
            _double:

            ConstOffset:=It.Value;
            FreeAndNil(It);

            case prior_double(ConstOffset,Name) of
             0:
               begin
                Writeln('Double1:',Name,'=',Value,'<>',ConstOffset.print_name);
                //nothing
               end;
             1:
               begin
                Writeln('Double2:',Name,'=',Value,'<>',ConstOffset.print_name);

                RMNV_offsets.Delete(ConstOffset.Name);  //name->value
                RMVN_offsets.Delete(ConstOffset.Value); //value->name

                FreeAndNil(ConstOffset);

                goto _new_values;
               end;
             else
               begin
                Writeln('Double3:',Name,'=',Value,'<>',ConstOffset.print_name);
                Writeln('');
               end;
            end;

            //Writeln('Double:',Name,'=',Value,'<>',It.Value);
           end;
          end else
          begin
           _new_values:

            ConstOffset:=NewConstOffset(Name,Value);

            RMNV_offsets.Insert(ConstOffset.Name ,ConstOffset); //name->value
            RMVN_offsets.Insert(ConstOffset.Value,ConstOffset); //value->name
          end;
          //
         end;
        end;

       end;
     end;
    end;
  end;

 end;
 L.Free;

 F:=FileCreate(ChangeFileExt(fname,'.pas'));

 S:='unit '+ChangeFileExt(ExtractFileName(fname),'')+';'#13#10#13#10+
    'interface'#13#10#13#10+
    '{$mode objfpc}{$H+}'#13#10#13#10+
    'const'#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 //calc maxlen
 maxlen:=0;
 It:=RMVN_offsets.Min;
 if Assigned(It) then
 begin
  repeat
   ConstOffset:=It.Value;
   if Length(ConstOffset.Name)>maxlen then maxlen:=Length(ConstOffset.Name);
  until not It.Next;
  FreeAndNil(It);
 end;
 //calc maxlen

 It:=RMVN_offsets.Min;
 if Assigned(It) then
 begin
  repeat
   ConstOffset:=It.Value;
   S:=' '+ConstOffset.Name+Space(maxlen-Length(ConstOffset.Name))+'='+ConstOffset.Value+';'#13#10;
   FileWrite(F,Pchar(S)^,Length(S));
  until not It.Next;
  FreeAndNil(It);
 end;

 S:=#13#10'function getRegName(i:Word):RawByteString;'#13#10#13#10+
    'implementation'#13#10#13#10+
    'function getRegName(i:Word):RawByteString;'#13#10+
    'begin'#13#10+
    ' case i of'#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 It:=RMVN_offsets.Min;
 if Assigned(It) then
 begin
  repeat
   ConstOffset:=It.Value;
   S:='  '+ConstOffset.Name+Space(maxlen-Length(ConstOffset.Name))+':Result:='#$27+ConstOffset.Name+#$27';'#13#10;
   FileWrite(F,Pchar(S)^,Length(S));
  until not It.Next;
  FreeAndNil(It);
 end;

 S:=' else'#13#10+
    '  Result:=HexStr(i,4);'#13#10+
    ' end;'#13#10+
    'end;'#13#10+
    #13#10'end.'#13#10#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 FileClose(F);
end;

//

type
 TUnionList=class(TStringList)
  public
   name    :RawByteString;
   Series  :TSeries;
   bit_size:ptruint;
 end;
 TStructList=TUnionList;

 TMapUnionList=specialize TMap<RawByteString,TUnionList,TRawStrCompare>;

var
 UnionList:TMapUnionList;

function is_valid_reg_by_offset(const Name:RawByteString):Boolean;
var
 It:TMapConstOffset.TIterator;
 ConstOffset:TConstOffset;
begin
 it:=RMNV_offsets.Find('mm'+NormalizeName(Name)); //name->value
 if Assigned(it) then
 begin
  ConstOffset:=it.Value;
  FreeAndNil(it);

  Result:=(ConstOffset.Series.__SI    =EndIs(Name,'__SI'    )) and
          (ConstOffset.Series.__SI__CI=EndIs(Name,'__SI__CI')) and
          (ConstOffset.Series.__VI    =EndIs(Name,'__VI'    )) and
          (ConstOffset.Series.__CI__VI=EndIs(Name,'__CI__VI')) and
          (ConstOffset.Series.__CI    =EndIs(Name,'__CI'    ));
 end else
 begin
  Result:=False;
 end;
end;

Procedure load_registers(const fname:RawByteString);
label
 _new_values;
var
 L:TStringList;
 maxlen:Integer;
 i,w,v:Integer;
 S:RawByteString;
 It:TMapUnionList.TIterator;
 F:THandle;

 is_union,is_struct:Boolean;
 reserved:Integer;
 union_field:TUnionList;
 uprev_field:TUnionList;
 struct_field:TStructList;

 name,value:RawByteString;

begin
 UnionList:=TMapUnionList.Create;
 is_union:=false;
 is_struct:=false;
 L:=TStringList.Create;
 L.LoadFromFile(fname);
 For i:=0 to L.Count -1 do
 begin
  S:=L.Strings[i];
  Case FetchAny(S,[' ',#9],[]) of
   'union':
     begin
      name:=FetchAny(S,[' ',#9],[]);

      if (not EndIs(Name,'__CI')) then
      begin
       is_union :=True;
       is_struct:=false;
       reserved:=0;
       union_field:=TUnionList.Create;
       union_field.name:=name;
       union_field.Series.Apply(union_field.name);
      end;
     end;
   '};':
     if is_union then
     begin
      is_union :=false;
      is_struct:=false;
      It:=UnionList.Find(union_field.name);
      If Assigned(It) then
      begin
       uprev_field:=It.Value;
       FreeAndNil(It);

       Writeln('Double:',union_field.name);

       if (union_field.Series.get_prio>uprev_field.Series.get_prio) then
       begin
        UnionList.Delete(uprev_field.name);
        FreeAndNil(uprev_field);
        goto _new_values;
       end else
       begin
        FreeAndNil(union_field);
       end;

      end else
      begin
       _new_values:
       UnionList.Insert(union_field.name,union_field);
      end;
      union_field:=nil;
     end;
   'struct':
     if is_union then
     begin
      is_struct:=True;
      struct_field:=TStructList.Create;
      struct_field.NameValueSeparator:=':';
     end;
   '}':
     if is_struct then
     begin
      is_struct:=False;
      Name:=FetchAny(S,[' ',#9,',',';'],[]);
      Name:=NormalizeName(Name);
      struct_field.name:=Name;
      union_field.AddObject(struct_field.name,struct_field);

      if (union_field.bit_size<struct_field.bit_size) then
      begin
       union_field.bit_size:=struct_field.bit_size;
      end;

      struct_field:=nil;
     end;
   'unsigned':
     if is_struct then
     if (FetchAny(S,[' ',#9],[])='int') then
     begin
      name:=FetchAny(S,[' ',#9],[]);
      if (name=':') then
      begin
       repeat
        name:='RESERVED'+IntToStr(reserved);
        Inc(reserved);
       until (struct_field.IndexOfName(name)=-1);
      end else
      if FetchAny(S,[' ',#9],[])<>':' then
      begin
       Writeln('wtf?:',i);
      end;
      Name:=NormalizeName(Name);
      Case name of
       'INTERFACE',
       'OVERRIDE',
       'TYPE',
       'UNIT',
       'END':name:='_'+name;
      end;
      value:=FetchAny(S,[' ',#9,';'],[]);
      struct_field.Add(name+':bit'+value);

      v:=StrToIntDef(value,0);
      struct_field.bit_size:=struct_field.bit_size+v;

     end;
  end;

 end;
 L.Free;

 //

 F:=FileCreate(ChangeFileExt(fname,'.pas'));

 S:='unit '+ChangeFileExt(ExtractFileName(fname),'')+';'#13#10#13#10+
    '{$mode objfpc}{$H+}'#13#10#13#10+
    'interface'#13#10#13#10+
    'uses'#13#10+
    ' bittype;'#13#10#13#10+
    'type'#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 It:=UnionList.Min;
 if Assigned(It) then
 begin
  repeat
   union_field:=It.Value;

   if (union_field.Count=1) then
   begin
    struct_field:=TStructList(union_field.Objects[0]);
    if (struct_field.Count=1) then
    begin
     struct_field.GetNameValue(0,String(name),String(Value));
     S:=' T'+union_field.name+'='+Value+';'+#13#10#13#10;
     FileWrite(F,Pchar(S)^,Length(S));
    end else
    begin
     S:=' T'+union_field.name+'=bitpacked record'#13#10;
     FileWrite(F,Pchar(S)^,Length(S));

     maxlen:=0;
     For i:=0 to struct_field.Count-1 do
     begin
      name:=struct_field.Names[i];
      if Length(name)>maxlen then maxlen:=Length(name);
     end;

     For i:=0 to struct_field.Count-1 do
     begin
      struct_field.GetNameValue(i,String(name),String(Value));
      S:='  '+name+Space(maxlen-Length(name))+':'+Value+';'#13#10;
      FileWrite(F,Pchar(S)^,Length(S));
     end;

     S:=' end;'#13#10#13#10;
     FileWrite(F,Pchar(S)^,Length(S));
    end;
   end else
   begin
    S:=' T'+union_field.name+'=packed record'#13#10+
       '  Case Byte of'#13#10;
    FileWrite(F,Pchar(S)^,Length(S));

    For w:=0 to union_field.Count-1 do
    begin
     S:='   '+IntToStr(w)+':('#13#10;
     FileWrite(F,Pchar(S)^,Length(S));

     struct_field:=TStructList(union_field.Objects[w]);

     if (struct_field.Count=1) then
     begin
      struct_field.GetNameValue(0,String(name),String(Value));
      S:='    '+struct_field.name+':'+Value+');'+#13#10;
      FileWrite(F,Pchar(S)^,Length(S));
     end else
     begin
      S:='    '+struct_field.name+':bitpacked record'#13#10;
      FileWrite(F,Pchar(S)^,Length(S));

      maxlen:=0;
      For i:=0 to struct_field.Count-1 do
      begin
       name:=struct_field.Names[i];
       if Length(name)>maxlen then maxlen:=Length(name);
      end;

      For i:=0 to struct_field.Count-1 do
      begin
       struct_field.GetNameValue(i,String(name),String(Value));
       S:='     '+name+Space(maxlen-Length(name))+':'+Value+';'#13#10;
       FileWrite(F,Pchar(S)^,Length(S));
      end;

      S:='    end);'#13#10;
      FileWrite(F,Pchar(S)^,Length(S));
     end;

    end;

    S:=' end;'#13#10#13#10;
    FileWrite(F,Pchar(S)^,Length(S));

   end;

  until not It.Next;
  FreeAndNil(It);
 end;

 S:=#13#10'implementation'#13#10#13#10+
    'end.'#13#10#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 FileClose(F);
end;

type
 TEnum=TUnionList;

var
 Enum_Set:TSetStr;
 EnumList:TStringList;

Procedure load_enum(const fname:RawByteString);
var
 L:TStringList;
 maxlen:Integer;
 i,e:Integer;
 S,name,value:RawByteString;

 Enum:TEnum;

 is_enum:Boolean;

 F:THandle;

begin
 Enum_Set:=TSetStr.Create;
 EnumList:=TStringList.Create;
 is_enum:=False;
 maxlen:=0;

 L:=TStringList.Create;
 L.LoadFromFile(fname);
 For i:=0 to L.Count-1 do
 begin
  S:=L.Strings[i];
  name:=FetchAny(S,[' ',#9],[]);
  Case name of
   'typedef':
     begin
      if FetchAny(S,[' ',#9],[])='enum' then
      begin
       name:=FetchAny(S,[' ',#9,'{'],[]);
       is_enum:=True;
       Enum:=TEnum.Create;
       Enum.name:=name;
       Enum.NameValueSeparator:='=';
      end;
     end;
   '}':
     if is_enum then
     begin
      EnumList.AddObject(Enum.name,Enum);
      Enum:=nil;
      is_enum:=False;
     end;
   else
     if is_enum then
     begin
      if (not EndIs(Name,'__SI')) and
         (not EndIs(Name,'__CI')) and
         (not EndIs(Name,'__SI__CI')) then
      if FetchAny(S,[' ',#9],[])='=' then
      begin
       Name:=NormalizeName(Name);
       value:=FetchAny(S,[' ',#9,','],[]);
       if BeginIs(Value,'0x') then
       begin
        System.Delete(Value,1,2);
        Value:='$'+Value;
       end;
       if Enum_Set.NFind(Name)=nil then
       begin
        if Length(name)>maxlen then maxlen:=Length(name);
        Enum_Set.Insert(Name);
        Enum.Add(Name+'='+value);
       end else
       begin
        Writeln('Double enum:',Name);
       end;
      end;
     end;
  end;
 end;
 L.Free;

 F:=FileCreate(ChangeFileExt(fname,'.pas'));

 S:='unit '+ChangeFileExt(ExtractFileName(fname),'')+';'#13#10#13#10+
    '{$mode objfpc}{$H+}'#13#10#13#10+
    'interface'#13#10#13#10+
    'Const'#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 For i:=0 to EnumList.Count-1 do
 begin
  Enum:=TEnum(EnumList.Objects[i]);

  S:=' // '+Enum.name+#13#10;
  FileWrite(F,Pchar(S)^,Length(S));

  For e:=0 to Enum.Count-1 do
  begin
   Enum.GetNameValue(e,String(name),String(Value));

   S:=' '+name+Space(maxlen-Length(name))+'='+Value+';'#13#10;
   FileWrite(F,Pchar(S)^,Length(S));

  end;
 end;

 S:=#13#10'implementation'#13#10#13#10+
    'end.'#13#10#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 FileClose(F);

end;

type
 t_reg_nt=record
  _name:string[80];
  _type:string[80];
 end;

 p_group_regs=^t_group_regs;
 t_group_regs=array[0..$FFFF] of t_reg_nt;

function get_group_max(group:p_group_regs):Integer;
var
 i:Integer;
begin
 Result:=$FFFF;
 For i:=$FFFF downto 0 do
 begin
  if (group^[i]._name<>'') then Exit(i);
 end;
end;

var
 groups:array[0..High(ofs_groups)] of t_group_regs;

function get_zero_count(group:p_group_regs;min,max:Integer):Integer;
var
 i:Integer;
begin
 Result:=0;
 for i:=min to max do
 begin

  if (group^[i]._name='') then
  begin
   Inc(Result);
  end else
  begin
   Exit;
  end;

 end;
end;

function fill_name(group:p_group_regs;min,max:Integer;const name:RawByteString):Integer;
var
 i:Integer;
begin
 Result:=0;
 for i:=min to max do
 begin
  group^[i]._name:=name;
 end;
end;

Procedure load_groups(const fname:RawByteString);
var
 ItC:TMapConstOffset.TIterator;
 ItU:TMapUnionList.TIterator;
 S,name,value:RawByteString;
 i,g,v,maxlen_name,maxlen_type,count:Integer;
 min,max:Integer;
 group:p_group_regs;

 F:THandle;
begin
 FillChar(groups,sizeof(groups),0);

 ItC:=RMVN_offsets.Min;
 if Assigned(ItC) then
 begin
  repeat
   name :=ItC.Value.Name;
   value:=ItC.Value.Value;

   CutBegin(name,'mm');

   v:=StrToIntDef(value,0);

   g:=get_offset_group(v);

   if (g=-1) then
   begin
    writeln('wtf?');
   end;

   group:=@groups[g];

   group^[v]._name:=name;

   ItU:=UnionList.Find(name);
   If Assigned(ItU) then
   begin
    group^[v]._type:='T'+name;

    //Writeln('E:',name,' ',value);
    FreeAndNil(ItU);
   end else
   begin
    group^[v]._type:='DWORD';

    //Writeln('N:',name,' ',value);
   end;

  until not ItC.Next;
  FreeAndNil(ItC);
 end;

 //
 group:=@groups[get_group_by_name('CONTEXT_REG')];

 fill_name(group,$A318,$A38E,'(skip)');
 group^[$A318]._name:='RENDER_TARGET';
 group^[$A318]._type:='array[0..7] of TRENDER_TARGET';

 fill_name(group,$A2FA,$A2FD,'(skip)');
 group^[$A2FA]._name:='GB_CLIP';
 group^[$A2FA]._type:='TGB_CLIP';

 fill_name(group,$A090,$A091,'(skip)');
 group^[$A090]._name:='PA_SC_GENERIC_SCISSOR';
 group^[$A090]._type:='TVPORT_SCISSOR';

 fill_name(group,$A094,$A0B3,'(skip)');
 group^[$A094]._name:='PA_SC_VPORT_SCISSOR';
 group^[$A094]._type:='array[0..15] of TVPORT_SCISSOR';

 fill_name(group,$A0B4,$A0D3,'(skip)');
 group^[$A0B4]._name:='PA_SC_VPORT_ZMIN_MAX';
 group^[$A0B4]._type:='array[0..15] of TVPORT_ZMIN_MAX';

 fill_name(group,$A10F,$A16E,'(skip)');
 group^[$A10F]._name:='PA_CL_VPORT_SCALE_OFFSET';
 group^[$A10F]._type:='array[0..15] of TVPORT_SCALE_OFFSET';

 fill_name(group,$A1E0,$A1E7,'(skip)');
 group^[$A1E0]._name:='CB_BLEND_CONTROL';
 group^[$A1E0]._type:='array[0..7] of TCB_BLEND0_CONTROL';

 fill_name(group,$A191,$A1B0,'(skip)');
 group^[$A191]._name:='SPI_PS_INPUT_CNTL';
 group^[$A191]._type:='array[0..31] of TSPI_PS_INPUT_CNTL_0';

 fill_name(group,$A105,$A108,'(skip)');
 group^[$A105]._name:='CB_BLEND_RGBA';
 group^[$A105]._type:='array[0..3] of Single';

 //


 //
 group:=@groups[get_group_by_name('SH_REG_GFX')];

 fill_name(group,$2C0C,$2C1B,'(skip)');
 group^[$2C0C]._name:='SPI_SHADER_USER_DATA_PS';
 group^[$2C0C]._type:='TSPI_USER_DATA';

 fill_name(group,$2C4C,$2C5B,'(skip)');
 group^[$2C4C]._name:='SPI_SHADER_USER_DATA_VS';
 group^[$2C4C]._type:='TSPI_USER_DATA';

 fill_name(group,$2C8C,$2C9B,'(skip)');
 group^[$2C8C]._name:='SPI_SHADER_USER_DATA_GS';
 group^[$2C8C]._type:='TSPI_USER_DATA';

 fill_name(group,$2CCC,$2CDB,'(skip)');
 group^[$2CCC]._name:='SPI_SHADER_USER_DATA_ES';
 group^[$2CCC]._type:='TSPI_USER_DATA';

 fill_name(group,$2D0C,$2D1B,'(skip)');
 group^[$2D0C]._name:='SPI_SHADER_USER_DATA_HS';
 group^[$2D0C]._type:='TSPI_USER_DATA';

 fill_name(group,$2D4C,$2D5B,'(skip)');
 group^[$2D4C]._name:='SPI_SHADER_USER_DATA_LS';
 group^[$2D4C]._type:='TSPI_USER_DATA';

 group:=@groups[get_group_by_name('SH_REG_COMPUTE')];

 fill_name(group,$2E40,$2E4F,'(skip)');
 group^[$2E40]._name:='COMPUTE_USER_DATA';
 group^[$2E40]._type:='TSPI_USER_DATA';
 //

 for g:=0 to High(ofs_groups) do
 begin
  group:=@groups[g];

  min:=ofs_groups[g].lo;
  max:=get_group_max(group);

  for i:=min to max do
  begin

   if (group^[i]._name='') then
   begin
    count:=get_zero_count(group,i,max);

    if (count=1) then
    begin
     group^[i]._name:='REG_'+HexStr(i,4);
    end else
    begin
     fill_name(group,i,i+count-1,'(skip)');
     group^[i]._name:='REG_'+HexStr(i,4)+'_'+HexStr(i+count-1,4);
     group^[i]._type:='array[0..'+IntToStr(count-1)+'] of DWORD';
    end;

   end;

   if (group^[i]._type='') then
   begin
    group^[i]._type:='DWORD';
   end;

   //Writeln(' ',name,':',value,'; $',HexStr(i,4));
  end;
 end;

 F:=FileCreate(ChangeFileExt(fname,'.pas'));

 S:='unit '+ChangeFileExt(ExtractFileName(fname),'')+';'#13#10#13#10+
    '{$mode objfpc}{$H+}'#13#10#13#10+
    'interface'#13#10#13#10+
    'uses'#13#10+
    ' si_ci_vi_merged_registers;'#13#10#13#10+
    'type'#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 S:=
 ' TRENDER_TARGET=packed record'#13#10+
 '  BASE       :TCB_COLOR0_BASE       ; //mmCB_COLOR0_BASE_DEFAULT'#13#10+
 '  PITCH      :TCB_COLOR0_PITCH      ; //mmCB_COLOR0_PITCH_DEFAULT'#13#10+
 '  SLICE      :TCB_COLOR0_SLICE      ; //mmCB_COLOR0_SLICE_DEFAULT'#13#10+
 '  VIEW       :TCB_COLOR0_VIEW       ; //mmCB_COLOR0_VIEW_DEFAULT'#13#10+
 '  INFO       :TCB_COLOR0_INFO       ; //mmCB_COLOR0_INFO_DEFAULT'#13#10+
 '  ATTRIB     :TCB_COLOR0_ATTRIB     ; //mmCB_COLOR0_ATTRIB_DEFAULT'#13#10+
 '  DCC_CONTROL:TCB_COLOR0_DCC_CONTROL; //mmCB_COLOR0_DCC_CONTROL_DEFAULT'#13#10+
 '  CMASK      :TCB_COLOR0_CMASK      ; //mmCB_COLOR0_CMASK_DEFAULT'#13#10+
 '  CMASK_SLICE:TCB_COLOR0_CMASK_SLICE; //mmCB_COLOR0_CMASK_SLICE_DEFAULT'#13#10+
 '  FMASK      :TCB_COLOR0_FMASK      ; //mmCB_COLOR0_FMASK_DEFAULT'#13#10+
 '  FMASK_SLICE:TCB_COLOR0_FMASK_SLICE; //mmCB_COLOR0_FMASK_SLICE_DEFAULT'#13#10+
 '  CLEAR_WORD :QWORD;                  //mmCB_COLOR0_CLEAR_WORD0_DEFAULT'#13#10+
 '                                      //mmCB_COLOR0_CLEAR_WORD1_DEFAULT'#13#10+
 '  DCC_BASE   :TCB_COLOR0_DCC_BASE   ; //mmCB_COLOR0_DCC_BASE_DEFAULT'#13#10+
 '  ALIGN      :DWORD;'#13#10+
 ' end;'#13#10+
 ''#13#10+
 ' TGB_CLIP=packed record'#13#10+
 '  VERT_CLIP_ADJ:Single;'#13#10+
 '  VERT_DISC_ADJ:Single;'#13#10+
 '  HORZ_CLIP_ADJ:Single;'#13#10+
 '  HORZ_DISC_ADJ:Single;'#13#10+
 ' end; '#13#10+
 ''#13#10+
 ' TVPORT_SCISSOR=packed record'#13#10+
 '  TL:TPA_SC_VPORT_SCISSOR_0_TL;'#13#10+
 '  BR:TPA_SC_VPORT_SCISSOR_0_BR;'#13#10+
 ' end;'#13#10+
 ''#13#10+
 ' TVPORT_ZMIN_MAX=packed record'#13#10+
 '  ZMIN:Single;'#13#10+
 '  ZMAX:Single;'#13#10+
 ' end;'#13#10+
 ''#13#10+
 ' TVPORT_SCALE_OFFSET=packed record'#13#10+
 '  XSCALE :Single;'#13#10+
 '  XOFFSET:Single;'#13#10+
 '  YSCALE :Single;'#13#10+
 '  YOFFSET:Single;'#13#10+
 '  ZSCALE :Single;'#13#10+
 '  ZOFFSET:Single;'#13#10+
 ' end;'#13#10+
 ''#13#10+
 ' TSPI_USER_DATA=array[0..15] of DWORD;'#13#10+
 ''#13#10;

 FileWrite(F,Pchar(S)^,Length(S));

 for g:=0 to High(ofs_groups) do
 begin
  group:=@groups[g];

  min:=ofs_groups[g].lo;
  max:=get_group_max(group);

  S:=' T'+ofs_groups[g].name+'_GROUP=bitpacked record'#13#10;
  FileWrite(F,Pchar(S)^,Length(S));

  maxlen_name:=0;
  maxlen_type:=0;
  for i:=min to max do
  begin
   name :=group^[i]._name;
   value:=group^[i]._type;

   if (Length(name)>maxlen_name) then
   begin
    maxlen_name:=Length(name);
   end;

   if (Length(value)>maxlen_type) then
   begin
    maxlen_type:=Length(value);
   end;
  end;

  for i:=min to max do
  begin
   name :=group^[i]._name;
   value:=group^[i]._type;

   if (name<>'(skip)') then
   begin
    S:='  '+name+Space(maxlen_name-Length(name))+':'+value+';'+Space(maxlen_type-Length(value))+' // 0x'+HexStr(i,4)+#13#10;
    FileWrite(F,Pchar(S)^,Length(S));
   end;
  end;

  S:=' end;'#13#10#13#10;
  FileWrite(F,Pchar(S)^,Length(S));

 end;

 S:=#13#10'implementation'#13#10#13#10+
    'end.'#13#10#13#10;
 FileWrite(F,Pchar(S)^,Length(S));

 FileClose(F);
end;

begin
 load_offsets  ('si_ci_vi_merged_offset.h');
 load_registers('si_ci_vi_merged_registers.h');
 load_enum     ('si_ci_vi_merged_enum.h');
 load_groups   ('si_ci_vi_merged_groups.pas');
 readln;
end.


unit vShaderExt;

{$mode objfpc}{$H+}

interface

uses
  Classes,
  SysUtils,
  ps4_shader,
  vRegs2Vulkan,
  Vulkan,
  vDevice,
  vPipeline,
  vShader,
  vImage,
  vSetLayoutManager,
  vPipelineLayoutManager,
  si_ci_vi_merged_registers,
  si_ci_vi_merged_groups;


type
 TvResourceType=(
  vtRoot,
  vtImmData,
  vtBufPtr2,
  vtFunPtr2,
  vtVSharp4,
  vtSSharp4,
  vtTSharp4,
  vtTSharp8,
  vtLDS,
  vtGDS
 );

 TvDataLayout=packed record
  rtype :TvResourceType;
  parent:DWORD;
  offset:DWORD;
 end;

 ADataLayout=array of TvDataLayout;

 TvFuncCb=procedure(addr:ADataLayout) of object;

 TvLayoutFlags=Set of (vMemoryRead,vMemoryWrite,vMipArray);

 TvCustomLayout=packed record
  dtype :DWORD;
  bind  :DWORD;
  size  :DWORD;
  offset:DWORD;
  flags :TvLayoutFlags;
  addr  :ADataLayout;
 end;

 ACustomLayout=array of TvCustomLayout;

 TvCustomLayoutCb=procedure(const L:TvCustomLayout;Fset:TVkUInt32;pUserData,pImmData:PDWORD) of object;

 TShaderFuncKey=packed object
  FLen :Ptruint;
  pData:PDWORD;
  function  c(var a,b:TShaderFuncKey):Integer; static;
  Procedure SetData(Src:Pointer;Len:Ptruint);
  Procedure Free;
 end;

 AShaderFuncKey=array of TShaderFuncKey;

 TvShaderParserExt=class(TvShaderParser)
  procedure OnDescriptorSet(var Target,id:DWORD); override;
  procedure OnSourceExtension(P:PChar);           override;
  procedure OnDataLayout(P:PChar);
  procedure OnIExtLayout(P:PChar);
  procedure OnVertLayout(P:PChar);
  procedure OnBuffLayout(P:PChar);
  procedure OnUnifLayout(P:PChar);
  procedure OnTexlLayout(P:PChar);
  procedure OnImgsLayout(P:PChar);
  procedure OnRuntLayout(P:PChar);
  procedure OnArrsLayout(P:PChar);
  procedure OnFuncLayout(P:PChar);
 end;

 A_INPUT_CNTL=array[0..31] of TSPI_PS_INPUT_CNTL_0;

 PRENDER_TARGET=^TRENDER_TARGET;

 TEXPORT_INFO=packed record
  FORMAT     :Byte;
  NUMBER_TYPE:Byte;
  COMP_SWAP  :Byte;
 end;
 AEXPORT_INFO=array[0..7] of TEXPORT_INFO;

 TvShaderExt=class(TvShader)

  FDescSetId:Integer;

  FHash_gcn:QWORD;
  FHash_spv:QWORD;

  FSetLayout:TvSetLayout;

  FDataLayouts:ADataLayout;
  FVertLayouts:ACustomLayout;
  FUnifLayouts:ACustomLayout;
  FFuncLayouts:ACustomLayout;

  FPushConst:TvCustomLayout;

  FShaderFuncs:AShaderFuncKey;

  FImmData:array of DWORD;

  FParams:record
   VGPR_COMP_CNT:Byte;
   //
   NUM_INTERP   :Byte;
   EXPORT_COUNT :Byte;

   STEP_RATE_0:DWORD;
   STEP_RATE_1:DWORD;
   //
   SHADER_CONTROL:TDB_SHADER_CONTROL;
   INPUT_CNTL    :A_INPUT_CNTL;
   EXPORT_INFO   :AEXPORT_INFO;
  end;

  FGeomRectList:TvShaderExt;

  procedure  ClearInfo; override;
  Destructor Destroy;   override;
  function   parser:CvShaderParser; override;
  procedure  InitSetLayout;
  procedure  AddToPipeline(p:TvPipelineLayout);
  Procedure  AddDataLayout(rtype:TvResourceType;parent,offset:DWORD);
  Procedure  EnumFuncLayout(cb:TvFuncCb);
  function   GetLayoutAddr(parent:DWORD):ADataLayout;
  Procedure  AddVertLayout(parent,bind:DWORD);
  Procedure  EnumVertLayout(cb:TvCustomLayoutCb;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
  Procedure  AddBuffLayout(dtype:TVkDescriptorType;parent,bind,size,offset,flags:DWORD);
  Procedure  SetPushConst(parent,size:DWORD);
  Function   GetPushConstData(pUserData:Pointer):Pointer;
  Procedure  AddUnifLayout(dtype:TVkDescriptorType;parent,bind,flags:DWORD);
  Procedure  EnumUnifLayout(cb:TvCustomLayoutCb;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
  Procedure  AddFuncLayout(parent,size:DWORD);
  Procedure  EnumFuncLayout(cb:TvCustomLayoutCb;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
  Procedure  AddImmData(D:DWORD);
  function   GetImmData:PDWORD;
  procedure  FreeShaderFuncs;
  Procedure  PreloadShaderFuncs(pUserData:Pointer);
  Procedure  SetInstance       (VGPR_COMP_CNT:Byte;STEP_RATE_0,STEP_RATE_1:DWORD);
  Procedure  SET_SHADER_CONTROL(const SHADER_CONTROL:TDB_SHADER_CONTROL);
  Procedure  SET_INPUT_CNTL    (const INPUT_CNTL:A_INPUT_CNTL;NUM_INTERP:Byte);
  Procedure  SET_RENDER_TARGETS(R:PRENDER_TARGET;COUNT:Byte);
  function   IsPSSimpleShader:Boolean;
  function   IsVSSimpleShader:Boolean;
  function   IsCSClearShader:Boolean;
  function   IsVSRectListShader:Boolean;
 end;

 TBufBindExt=packed record
  fset  :TVkUInt32;
  bind  :TVkUInt32;
  offset:TVkUInt32;
  memuse:TVkUInt32;

  addr  :Pointer;
  size  :TVkUInt32;
 end;

 TvBindImageType=(vbSampled,vbStorage,vbMipStorage);

 TImageBindExt=packed record
  btype :TvBindImageType;
  fset  :TVkUInt32;
  bind  :TVkUInt32;
  memuse:TVkUInt32;

  FImage:TvImageKey;
  FView :TvImageViewKey;
 end;

 TSamplerBindExt=packed record
  fset:TVkUInt32;
  bind:TVkUInt32;

  PS:PSSharpResource4;
 end;

 TvUniformBuilder=object
  FBuffers :array of TBufBindExt;
  FImages  :array of TImageBindExt;
  FSamplers:array of TSamplerBindExt;

  Procedure AddVSharp(PV:PVSharpResource4;fset,bind,size,offset:DWord;flags:TvLayoutFlags);
  Procedure AddBufPtr(P:Pointer          ;fset,bind,size,offset:DWord;flags:TvLayoutFlags);

  Procedure AddTSharp4(PT:PTSharpResource4;btype:TvBindImageType;fset,bind:DWord;flags:TvLayoutFlags);
  Procedure AddTSharp8(PT:PTSharpResource8;btype:TvBindImageType;fset,bind:DWord;flags:TvLayoutFlags);
  Procedure AddSSharp4(PS:PSSharpResource4;fset,bind:DWord);
  procedure AddAttr   (const b:TvCustomLayout;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
 end;

 AvShaderStage=array[TvShaderStage] of TvShaderExt;

 PvShadersKey=^TvShadersKey;
 TvShadersKey=object
  FShaders:AvShaderStage;
  FPrimtype:Integer;
  Procedure SetLSShader(Shader:TvShaderExt);
  Procedure SetHSShader(Shader:TvShaderExt);
  Procedure SetESShader(Shader:TvShaderExt);
  Procedure SetGSShader(Shader:TvShaderExt);
  Procedure SetVSShader(Shader:TvShaderExt);
  Procedure SetPSShader(Shader:TvShaderExt);
  Procedure SetCSShader(Shader:TvShaderExt);
  procedure ExportLayout(var A:AvSetLayout;var B:AvPushConstantRange);
  Procedure ExportStages(Stages:PVkPipelineShaderStageCreateInfo;stageCount:PVkUInt32);
 end;

 TvBindVertexBuffer=packed object
  min_addr:Pointer;
  binding :Word;
  stride  :Word;
  count   :TVkUInt32;
  Function GetSize:TVkUInt32;
 end;

 AvVertexInputBindingDescription   =array[0..31] of TVkVertexInputBindingDescription;
 AvBindVertexBuffer                =array[0..31] of TvBindVertexBuffer;
 AvVertexInputAttributeDescription =array[0..31] of TVkVertexInputAttributeDescription;

 AvVertexInputBindingDescription2  =array[0..31] of TVkVertexInputBindingDescription2EXT;
 AvVertexInputAttributeDescription2=array[0..31] of TVkVertexInputAttributeDescription2EXT;

 TvVertexInputEXT=record
  vertexBindingDescriptionCount  :TVkUInt32;
  vertexAttributeDescriptionCount:TVkUInt32;
  VertexBindingDescriptions      :AvVertexInputBindingDescription2;
  VertexAttributeDescriptions    :AvVertexInputAttributeDescription2;
 end;

 TvAttrBuilder=object
  const
   maxVertexInputBindingStride=16383;
   maxVertexInputBindings     =32;
   maxVertexInputAttributes   =32;
  var
   FBindDescsCount:Byte;
   FAttrDescsCount:Byte;
   FBindDescs:AvVertexInputBindingDescription;
   FBindVBufs:AvBindVertexBuffer;
   FAttrDescs:AvVertexInputAttributeDescription;
  //
  function  NewBindDesc(binding,stride,count:TVkUInt32;base:Pointer):TVkUInt32;
  procedure NewAttrDesc(location,binding,offset:TVkUInt32;format:TVkFormat);
  procedure PatchAttr(binding,offset:TVkUInt32);
  Procedure AddVSharp(PV:PVSharpResource4;location:DWord);
  procedure AddAttr(const v:TvCustomLayout;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
  Procedure Export2(var input:TvVertexInputEXT);
 end;

 TvBufOffsetChecker=object
  FResult:Boolean;
  procedure AddAttr(const b:TvCustomLayout;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
 end;

 TvFuncLayout=object
  FList:array of ADataLayout;
  Procedure Add(const addr:ADataLayout);
 end;

 TvShaderGroup=class
  FKey   :TvShadersKey;
  FLayout:TvPipelineLayout;
  Procedure Clear;
  Function  Compile:Boolean;
  Procedure ExportAttrBuilder(var AttrBuilder   :TvAttrBuilder   ;GPU_USERDATA:PGPU_USERDATA);
  Procedure ExportUnifBuilder(var UniformBuilder:TvUniformBuilder;GPU_USERDATA:PGPU_USERDATA);
 end;

function GetSharpByPatch(pUserData,pImmData:Pointer;const addr:ADataLayout):Pointer;

function IsClearDepthShaders(const FShaders:AvShaderStage):Boolean; inline;

implementation

uses
 kern_dmem;

function Max(a,b:PtrInt):PtrInt; inline;
begin
 if (a>b) then Result:=a else Result:=b;
end;

function TShaderFuncKey.c(var a,b:TShaderFuncKey):Integer;
begin
 //1 FLen
 Result:=Integer((a.FLen>b.FLen) and (b.FLen<>0))-Integer((a.FLen<b.FLen) and (a.FLen<>0));
 if (Result<>0) then Exit;

 //2 pData
 Result:=CompareDWord(a.pData^,b.pData^,Max(a.FLen,b.FLen) div 4);
end;

Procedure TShaderFuncKey.SetData(Src:Pointer;Len:Ptruint);
begin
 Free;

 FLen :=Len;
 pData:=AllocMem(Len);

 Move(Src^,pData^,Len);
end;

Procedure TShaderFuncKey.Free;
begin
 if (FLen<>0) and (pData<>nil) then
 begin
  FreeMem(pData);
 end;
end;

Function TvBindVertexBuffer.GetSize:TVkUInt32;
begin
 if (stride=0) then
 begin
  Result:=count;
 end else
 begin
  Result:=stride*count;
 end;
end;

procedure TvShaderExt.ClearInfo;
begin
 inherited;

 //dont clear FDescSetId

 FSetLayout:=nil;

 FDataLayouts:=Default(ADataLayout);
 FVertLayouts:=Default(ACustomLayout);
 FUnifLayouts:=Default(ACustomLayout);
 FFuncLayouts:=Default(ACustomLayout);

 FPushConst:=Default(TvCustomLayout);

 SetLength(FImmData,0);

 FreeShaderFuncs;
end;

Destructor TvShaderExt.Destroy;
begin
 FreeShaderFuncs;

 inherited;
end;

function TvShaderExt.parser:CvShaderParser;
begin
 Result:=TvShaderParserExt;
end;

procedure TvShaderExt.InitSetLayout;
var
 i,p:Integer;
 descriptorCount:TVkUInt32;
 A:AVkDescriptorSetLayoutBinding;
begin
 if (FSetLayout<>nil) then Exit;
 A:=Default(AVkDescriptorSetLayoutBinding);

  //++ other todo
 SetLength(A,
           Length(FUnifLayouts)
          );

 p:=0;
 if (Length(FUnifLayouts)<>0) then
 begin
  For i:=0 to High(FUnifLayouts) do
  begin
   if (vMipArray in FUnifLayouts[i].flags) then
   begin
    descriptorCount:=16;
   end else
   begin
    descriptorCount:=1;
   end;
   //
   A[p]:=Default(TVkDescriptorSetLayoutBinding);
   A[p].binding        :=FUnifLayouts[i].bind;
   A[p].descriptorType :=TVkDescriptorType(FUnifLayouts[i].dtype);
   A[p].descriptorCount:=descriptorCount;
   A[p].stageFlags     :=ord(FStage);
   //
   Inc(p);
  end;
 end;

 FSetLayout:=FetchSetLayout(ord(FStage),0,A);
end;

procedure TvShaderExt.AddToPipeline(p:TvPipelineLayout);
begin
 InitSetLayout;

 p.AddLayout(FSetLayout);
 if (FPushConst.size<>0) then
 begin
  p.AddPushConst(0,FPushConst.size,ord(FStage));
 end;
end;

procedure TvShaderParserExt.OnDescriptorSet(var Target,id:DWORD);
begin
 with TvShaderExt(FOwner) do
 begin
  if (FDescSetId>=0) then id:=FDescSetId;
 end;
end;

function _get_hex_dword(P:PChar):DWord;
var
 Error:word;
 s:string[9];
begin
 s[0]:=#9;
 s[1]:='$';
 PQWORD(@s[2])^:=PQWORD(P)^;
 Result:=0;
 Val(s,Result,Error);
end;

function _get_hex_char(P:PChar):DWord;
begin
 case P^ of
  '0'..'9':Result:=ord(P^)-ord('0');
  'A'..'F':Result:=ord(P^)-ord('A')+$A;
 end;
end;

Procedure AddToCustomLayout(var A:ACustomLayout;const v:TvCustomLayout);
begin
 Insert(v,A,Length(A));
end;

Procedure AddToDataLayout(var A:ADataLayout;const v:TvDataLayout);
begin
 Insert(v,A,Length(A));
end;

//0123456789ABCDEF0123456789ABCDEF012345678
//#B;PID=00000000;OFS=00000000
//VA;PID=00000004;BND=00000000
//BP;PID=00000003;BND=00000000;LEN=00000040
//UI;PID=00000001;BND=00000000
//US;PID=00000002;BND=00000001

procedure TvShaderParserExt.OnSourceExtension(P:PChar);
begin
 //Writeln(P);
 Case P^ of
  '#':OnDataLayout(P);
  '!':OnIExtLayout(P);
  'V':OnVertLayout(P);
  'B':OnBuffLayout(P);
  'U':OnUnifLayout(P);
  'T':OnTexlLayout(P);
  'I':OnImgsLayout(P);
  'A':OnArrsLayout(P);
  'R':OnRuntLayout(P);
  'F':OnFuncLayout(P);
  else
   Assert(false,'TODO: OnSourceExtension:"'+P^+'"');
 end;
end;

Procedure TvShaderExt.AddDataLayout(rtype:TvResourceType;parent,offset:DWORD);
var
 v:TvDataLayout;
begin
 v:=Default(TvDataLayout);
 v.rtype :=rtype;
 v.parent:=parent;
 v.offset:=offset;

 AddToDataLayout(FDataLayouts,v);
end;

procedure TvShaderParserExt.OnDataLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'R':AddDataLayout(vtRoot   ,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'D':AddDataLayout(vtImmData,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'B':AddDataLayout(vtBufPtr2,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'F':AddDataLayout(vtFunPtr2,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'V':AddDataLayout(vtVSharp4,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'S':AddDataLayout(vtSSharp4,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  't':AddDataLayout(vtTSharp4,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'T':AddDataLayout(vtTSharp8,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'L':AddDataLayout(vtLDS    ,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  'G':AddDataLayout(vtGDS    ,_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  else
   Assert(false,'TODO: OnDataLayout:"'+P[1]+'"');
 end;
end;

procedure TvShaderParserExt.OnIExtLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'D':AddImmData(_get_hex_dword(@P[3]));
  else
   Assert(false,'TODO: OnIExtLayout:"'+P[1]+'"');
 end;
end;

Procedure TvShaderExt.EnumFuncLayout(cb:TvFuncCb);
var
 i:Integer;
begin
 if (cb=nil) then Exit;
 if (Length(FDataLayouts)=0) then Exit;
 For i:=0 to High(FDataLayouts) do
 if (FDataLayouts[i].rtype=vtFunPtr2) then
 begin
  cb(GetLayoutAddr(i));
 end;
end;

function TvShaderExt.GetLayoutAddr(parent:DWORD):ADataLayout;
begin
 Result:=Default(ADataLayout);
 repeat
  if (parent>=Length(FDataLayouts)) then
  begin
   SetLength(Result,0);
   Break;
  end;

  Insert(FDataLayouts[parent],Result,Length(Result));

  if (parent=0) then Break;
  parent:=FDataLayouts[parent].parent;
 until false;
end;

Procedure TvShaderExt.AddVertLayout(parent,bind:DWORD);
var
 v:TvCustomLayout;
begin
 v:=Default(TvCustomLayout);
 v.bind:=bind;
 v.addr:=GetLayoutAddr(parent);

 AddToCustomLayout(FVertLayouts,v);
end;

procedure TvShaderParserExt.OnVertLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'A':AddVertLayout(_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  else
   Assert(false,'TODO: OnVertLayout:"'+P[1]+'"');
 end;
end;

Procedure TvShaderExt.EnumVertLayout(cb:TvCustomLayoutCb;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
var
 i:Integer;
begin
 if (cb=nil) then Exit;
 if (Length(FVertLayouts)=0) then Exit;
 For i:=0 to High(FVertLayouts) do
 begin
  cb(FVertLayouts[i],Fset,pUserData,pImmData);
 end;
end;

Procedure TvShaderExt.AddBuffLayout(dtype:TVkDescriptorType;parent,bind,size,offset,flags:DWORD);
var
 v:TvCustomLayout;
begin
 if (dtype=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER) then
 begin
  if (size>$FFFF) then //max UBO
  begin
   dtype:=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
  end else
  begin
   dtype:=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
  end;
 end;

 v:=Default(TvCustomLayout);
 v.dtype :=ord(dtype);
 v.bind  :=bind;
 v.size  :=size;
 v.offset:=offset;
 v.flags :=TvLayoutFlags(flags);
 v.addr  :=GetLayoutAddr(parent);

 AddToCustomLayout(FUnifLayouts,v);
end;

Procedure TvShaderExt.SetPushConst(parent,size:DWORD);
begin
 FPushConst:=Default(TvCustomLayout);
 FPushConst.size:=size;
 FPushConst.addr:=GetLayoutAddr(parent)
end;

//BS;PID=00000002;BND=00000001;LEN=FFFFFFFF;OFS=00000000;MRW=1"
//0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB
//0               1               2               3
procedure TvShaderParserExt.OnBuffLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'P':SetPushConst(_get_hex_dword(@P[7]),_get_hex_dword(@P[$21]));
  'U':AddBuffLayout(VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
                    _get_hex_dword(@P[7]),
                    _get_hex_dword(@P[$14]),
                    _get_hex_dword(@P[$21]),
                    _get_hex_dword(@P[$2E]),
                    _get_hex_char (@P[$3B]));
  'S':AddBuffLayout(VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
                    _get_hex_dword(@P[7]),
                    _get_hex_dword(@P[$14]),
                    _get_hex_dword(@P[$21]),
                    _get_hex_dword(@P[$2E]),
                    _get_hex_char (@P[$3B]));
  else
   Assert(false,'TODO: OnBuffLayout:"'+P[1]+'"');
 end;
end;

Function TvShaderExt.GetPushConstData(pUserData:Pointer):Pointer;
begin
 Result:=nil;
 if (pUserData=nil) then Exit;
 if (FPushConst.size=0) then Exit;
 Result:=GetSharpByPatch(pUserData,GetImmData,FPushConst.addr);

 if (Result=nil) then Exit;

 Case FPushConst.addr[0].rtype of
  vtVSharp4:Result:=Pointer(PVSharpResource4(Result)^.base);
  vtTSharp4,
  vtTSharp8:Result:=Pointer(PTSharpResource4(Result)^.base shl 8);
  else;
 end;

end;

Procedure TvShaderExt.AddUnifLayout(dtype:TVkDescriptorType;parent,bind,flags:DWORD);
var
 v:TvCustomLayout;
begin
 v:=Default(TvCustomLayout);
 v.dtype:=ord(dtype);
 v.bind :=bind;
 v.flags:=TvLayoutFlags(flags);
 v.addr :=GetLayoutAddr(parent);

 AddToCustomLayout(FUnifLayouts,v);
end;

//IU;PID=00000001;BND=00000000;MRW=1
//US;PID=00000002;BND=00000001;MRW=1
//0123456789ABCDEF0123456789ABCDEF01
//0               1               2

procedure TvShaderParserExt.OnUnifLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'S':AddUnifLayout(VK_DESCRIPTOR_TYPE_SAMPLER,
                    _get_hex_dword(@P[7]),
                    _get_hex_dword(@P[$14]),
                    _get_hex_char (@P[$21]));
  else
   Assert(false,'TODO: OnUnifLayout:"'+P[1]+'"');
 end;
end;

procedure TvShaderParserExt.OnTexlLayout(P:PChar);
begin
 Assert(false,'TODO: OnTexlLayout:"'+P[1]+'"');
end;

procedure TvShaderParserExt.OnImgsLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'U':AddUnifLayout(VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE,
                    _get_hex_dword(@P[7]),
                    _get_hex_dword(@P[$14]),
                    _get_hex_char (@P[$21]));
  'S':AddUnifLayout(VK_DESCRIPTOR_TYPE_STORAGE_IMAGE,
                    _get_hex_dword(@P[7]),
                    _get_hex_dword(@P[$14]),
                    _get_hex_char (@P[$21]));
  else
   Assert(false,'TODO: OnImgsLayout:"'+P[1]+'"');
 end;
end;

procedure TvShaderParserExt.OnRuntLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'S':AddUnifLayout(VK_DESCRIPTOR_TYPE_STORAGE_IMAGE,
                    _get_hex_dword(@P[7]),
                    _get_hex_dword(@P[$14]),
                    _get_hex_char (@P[$21]));
  else
   Assert(false,'TODO: OnRuntLayout:"'+P[1]+'"');
 end;
end;

procedure TvShaderParserExt.OnArrsLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'S':AddUnifLayout(VK_DESCRIPTOR_TYPE_STORAGE_IMAGE,
                    _get_hex_dword(@P[7]),
                    _get_hex_dword(@P[$14]),
                    _get_hex_char (@P[$21]));
  else
   Assert(false,'TODO: OnArrsLayout:"'+P[1]+'"');
 end;
end;

Procedure TvShaderExt.EnumUnifLayout(cb:TvCustomLayoutCb;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
var
 i:Integer;
begin
 if (cb=nil) then Exit;
 if (Length(FUnifLayouts)=0) then Exit;
 For i:=0 to High(FUnifLayouts) do
 begin
  cb(FUnifLayouts[i],Fset,pUserData,pImmData);
 end;
end;

Procedure TvShaderExt.AddFuncLayout(parent,size:DWORD);
var
 v:TvCustomLayout;
begin
 v:=Default(TvCustomLayout);
 v.size:=size;
 v.addr:=GetLayoutAddr(parent);

 AddToCustomLayout(FFuncLayouts,v);
end;

procedure TvShaderParserExt.OnFuncLayout(P:PChar);
begin
 with TvShaderExt(FOwner) do
 Case P[1] of
  'F':AddFuncLayout(_get_hex_dword(@P[7]),_get_hex_dword(@P[$14]));
  else
   Assert(false,'TODO: OnFuncLayout:"'+P[1]+'"');
 end;
end;

Procedure TvShaderExt.EnumFuncLayout(cb:TvCustomLayoutCb;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
var
 i:Integer;
begin
 if (cb=nil) then Exit;
 if (Length(FFuncLayouts)=0) then Exit;
 For i:=0 to High(FFuncLayouts) do
 begin
  cb(FFuncLayouts[i],Fset,pUserData,pImmData);
 end;
end;

Procedure TvShaderExt.AddImmData(D:DWORD);
begin
 Insert(D,FImmData,Length(FImmData));
end;

function TvShaderExt.GetImmData:PDWORD;
begin
 Result:=@FImmData[0];
end;

procedure TvShaderExt.FreeShaderFuncs;
var
 i:Integer;
begin
 if (Length(FShaderFuncs)<>0) then
  For i:=0 to High(FShaderFuncs) do
  begin
   FShaderFuncs[i].Free;
  end;

 FShaderFuncs:=Default(AShaderFuncKey);
end;

Procedure TvShaderExt.PreloadShaderFuncs(pUserData:Pointer);
var
 P:Pointer;
 i:Integer;
begin
 FreeShaderFuncs;

 if (Length(FFuncLayouts)=0) then Exit;

 SetLength(FShaderFuncs,Length(FFuncLayouts));

 For i:=0 to High(FFuncLayouts) do
 begin

  P:=GetSharpByPatch(pUserData,GetImmData,FFuncLayouts[i].addr);
  if (P=nil) then
  begin
   FShaderFuncs[i]:=Default(TShaderFuncKey);
  end else
  begin
   FShaderFuncs[i].SetData(P,FFuncLayouts[i].size);
  end;

 end;
end;

Procedure TvShaderExt.SetInstance(VGPR_COMP_CNT:Byte;STEP_RATE_0,STEP_RATE_1:DWORD);
begin
 FParams.VGPR_COMP_CNT:=VGPR_COMP_CNT;

 if (VGPR_COMP_CNT>=1) then
 begin
  FParams.STEP_RATE_0:=STEP_RATE_0;
 end;

 if (VGPR_COMP_CNT>=2) then
 begin
  FParams.STEP_RATE_1:=STEP_RATE_1;
 end;

end;

Procedure TvShaderExt.SET_SHADER_CONTROL(const SHADER_CONTROL:TDB_SHADER_CONTROL);
begin
 FParams.SHADER_CONTROL:=SHADER_CONTROL;
end;

Procedure TvShaderExt.SET_INPUT_CNTL(const INPUT_CNTL:A_INPUT_CNTL;NUM_INTERP:Byte);
begin
 FParams.NUM_INTERP:=NUM_INTERP;

 Move(INPUT_CNTL,FParams.INPUT_CNTL,SizeOf(TSPI_PS_INPUT_CNTL_0)*NUM_INTERP);
end;

Procedure TvShaderExt.SET_RENDER_TARGETS(R:PRENDER_TARGET;COUNT:Byte);
var
 i:Byte;
begin
 FParams.EXPORT_COUNT:=COUNT;
 if (COUNT<>0) then
 for i:=0 to COUNT-1 do
 begin
  FParams.EXPORT_INFO[i].FORMAT     :=R[i].INFO.FORMAT;
  FParams.EXPORT_INFO[i].NUMBER_TYPE:=R[i].INFO.NUMBER_TYPE;
  FParams.EXPORT_INFO[i].COMP_SWAP  :=R[i].INFO.COMP_SWAP;
 end;
end;

//

function TvShaderExt.IsPSSimpleShader:Boolean;
begin
 if (self=nil) then Exit(False);

 Result:=(FHash_gcn=QWORD($E9FF5D4699E5B9AD));
end;

function TvShaderExt.IsVSSimpleShader:Boolean;
begin
 if (self=nil) then Exit(False);

 Result:=(FHash_gcn=QWORD($00DF6E6331449451));
end;

function TvShaderExt.IsCSClearShader:Boolean;
begin
 if (self=nil) then Exit(False);

 Result:=(FHash_gcn=QWORD($7DCE68F83F66B337));
end;

function TvShaderExt.IsVSRectListShader:Boolean;
begin
 if (self=nil) then Exit(False);

 Result:=(FHash_gcn=QWORD($00DF6E6331449451));
end;

function IsClearDepthShaders(const FShaders:AvShaderStage):Boolean; inline;
begin
 Result:=False;

 if (FShaders[vShaderStageLs]=nil) and
    (FShaders[vShaderStageHs]=nil) and
    (FShaders[vShaderStageEs]=nil) and
    (FShaders[vShaderStageGs]=nil) and
    (FShaders[vShaderStageCs]=nil) then

 if (FShaders[vShaderStageVs].IsVSSimpleShader) and
    (
     FShaders[vShaderStagePs].IsPSSimpleShader or
     (FShaders[vShaderStagePs]=nil)
    ) then
 begin
  Result:=True;

 end;
end;

///

function GetSharpByPatch(pUserData,pImmData:Pointer;const addr:ADataLayout):Pointer;
var
 i:Integer;
 pData :Pointer;
 pSharp:Pointer;
 pDmem :Pointer;
begin
 Result:=nil;
 if (Length(addr)=0) then Exit;

 pData :=pUserData;
 pSharp:=pUserData;
 pDmem :=pUserData;

 For i:=High(addr) downto 0 do
 begin
  pData:=pData+addr[i].offset;
  pDmem:=pDmem+addr[i].offset;

  Case addr[i].rtype of
   vtRoot:
     begin
      pSharp:=pData;
      pDmem :=pData;
     end;
   vtImmData:
     begin
      pData :=pImmData+addr[i].offset;
      pSharp:=pData;
      pDmem :=pData;
     end;
   vtBufPtr2:
     begin
      pData:=Pointer(PPtrUint(pDmem)^ and (not 3));

      pDmem:=nil;
      if not get_dmem_ptr(pData,@pDmem,nil) then
      begin
       Assert(false,'vtBufPtr2:get_dmem_ptr($'+HexStr(pData)+')');
      end;

      pSharp:=pData;
     end;
   vtFunPtr2:
     begin
      pData:=PPointer(pDmem)^;

      pDmem:=nil;
      if not get_dmem_ptr(pData,@pDmem,nil) then
      begin
       Assert(false,'vtFunPtr2:get_dmem_ptr($'+HexStr(pData)+')');
      end;

      pSharp:=pData;
     end;
   vtVSharp4:
     begin
      pSharp:=pData;

      if (i<>0) then
      begin
       pData:=Pointer(PVSharpResource4(pDmem)^.base);

       pDmem:=nil;
       if not get_dmem_ptr(pData,@pDmem,nil) then
       begin
        Assert(false,'vtVSharp4:get_dmem_ptr($'+HexStr(pData)+')');
       end;
      end;

     end;
   vtSSharp4:
     begin
      pSharp:=pData;
      Break;
     end;
   vtTSharp4,
   vtTSharp8:
     begin
      pSharp:=pData;

      if (i<>0) then
      begin
       pData:=Pointer(PTSharpResource4(pDmem)^.base shl 8);

       pDmem:=nil;
       if not get_dmem_ptr(pData,@pDmem,nil) then
       begin
        Assert(false,'vtTSharp:get_dmem_ptr($'+HexStr(pData)+')');
       end;
      end;

     end;
   else
    Assert(false,'GetSharpByPatch');
  end;

 end;

 Result:=pSharp;
end;

//

function TvAttrBuilder.NewBindDesc(binding,stride,count:TVkUInt32;base:Pointer):TVkUInt32;
var
 i:Byte;
begin
 if (FBindDescsCount>=maxVertexInputBindings) then
 begin
  Assert(false,'maxVertexInputBindings');
 end;

 i:=FBindDescsCount;
 FBindDescsCount:=FBindDescsCount+1;

 FBindVBufs[i].min_addr:=base;
 FBindVBufs[i].binding :=binding;
 FBindVBufs[i].stride  :=stride;
 FBindVBufs[i].count   :=count;

 FBindDescs[i].binding  :=binding;
 FBindDescs[i].stride   :=stride;
 FBindDescs[i].inputRate:=VK_VERTEX_INPUT_RATE_VERTEX;

 Result:=i;
end;

procedure TvAttrBuilder.NewAttrDesc(location,binding,offset:TVkUInt32;format:TVkFormat);
var
 i:Integer;
begin
 if (FAttrDescsCount>=maxVertexInputAttributes) then
 begin
  Assert(false,'maxVertexInputAttributes');
 end;

 i:=FAttrDescsCount;
 FAttrDescsCount:=FAttrDescsCount+1;

 FAttrDescs[i].location:=location;
 FAttrDescs[i].binding :=binding ;
 FAttrDescs[i].format  :=format  ;
 FAttrDescs[i].offset  :=offset  ;
end;

procedure TvAttrBuilder.PatchAttr(binding,offset:TVkUInt32);
var
 i:Integer;
begin
 if (FAttrDescsCount<>0) then
  For i:=0 to FAttrDescsCount-1 do
  if (FAttrDescs[i].binding=binding) then
  begin
   FAttrDescs[i].offset:=FAttrDescs[i].offset+offset;
  end;
end;

function _ptr_diff(p1,p2:Pointer):TVkUInt32; inline;
begin
 if (p1>p2) then
  Result:=p1-p2
 else
  Result:=p2-p1;
end;

Procedure TvAttrBuilder.AddVSharp(PV:PVSharpResource4;location:DWord);
var
 pv_base  :Pointer;
 pv_stride:TVkUInt32;
 pv_count :TVkUInt32;
 offset   :TVkUInt32;
 i:Integer;
begin
 if (PV=nil) then Exit;

 pv_base  :=Pointer(PV^.base);
 pv_stride:=PV^.stride;
 pv_count :=PV^.num_records;

 if (FBindDescsCount<>0) then
  For i:=0 to FBindDescsCount-1 do
  begin
   With FBindVBufs[i] do
   begin
    //If the element's stride is the same,
    // add the attribute to the binding
    if (stride=pv_stride) then
    begin
     //Let's calculate the difference in addresses
     // between the binding and the new buffer
     offset:=_ptr_diff(min_addr,pv_base);
     //If the difference is greater than the stride,
     // then we skip
     if (offset<=stride-1) then
     begin
      //If the offset is negative relative
      // to the base, then
      if (min_addr>pv_base) then
      begin
       //We patch the previous attributes,
       // adjust the offset
       PatchAttr(binding,offset);
       //This is now the new base address,
       // so reset the offset.
       min_addr:=pv_base;
       offset  :=0;
      end;

      //update count
      if (count<pv_count) then
      begin
       count:=pv_count;
      end;

      NewAttrDesc(location,binding,offset,_get_vsharp_cformat(PV));
      Exit;
     end;
    end;
   end;
  end;

 //Binding not found, adding new binding and attribute

 i:=FBindDescsCount;

 NewBindDesc(i,pv_stride,pv_count,pv_base);

 NewAttrDesc(location,i,0,_get_vsharp_cformat(PV));

end;

procedure TvAttrBuilder.AddAttr(const v:TvCustomLayout;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
var
 PV:PVSharpResource4;
begin
 PV:=GetSharpByPatch(pUserData,pImmData,v.addr);
 //print_vsharp(PV);
 AddVSharp(PV,v.bind);
end;

Procedure TvAttrBuilder.Export2(var input:TvVertexInputEXT);
var
 i:Byte;
begin
 input:=Default(TvVertexInputEXT);

 input.vertexBindingDescriptionCount  :=FBindDescsCount;
 input.vertexAttributeDescriptionCount:=FAttrDescsCount;

 if (FBindDescsCount<>0) then
 For i:=0 to FBindDescsCount-1 do
 begin
  input.VertexBindingDescriptions[i].sType    :=VK_STRUCTURE_TYPE_VERTEX_INPUT_BINDING_DESCRIPTION_2_EXT;
  input.VertexBindingDescriptions[i].binding  :=FBindDescs[i].binding;
  input.VertexBindingDescriptions[i].stride   :=FBindDescs[i].stride;
  input.VertexBindingDescriptions[i].inputRate:=FBindDescs[i].inputRate;
  input.VertexBindingDescriptions[i].divisor  :=1;
 end;

 if (FAttrDescsCount<>0) then
 For i:=0 to FAttrDescsCount-1 do
 begin
  input.VertexAttributeDescriptions[i].sType   :=VK_STRUCTURE_TYPE_VERTEX_INPUT_ATTRIBUTE_DESCRIPTION_2_EXT;
  input.VertexAttributeDescriptions[i].location:=FAttrDescs[i].location;
  input.VertexAttributeDescriptions[i].binding :=FAttrDescs[i].binding;
  input.VertexAttributeDescriptions[i].format  :=FAttrDescs[i].format;
  input.VertexAttributeDescriptions[i].offset  :=FAttrDescs[i].offset;
 end;

end;

//

function _get_buf_mem_usage(flags:TvLayoutFlags):Byte; inline;
begin
 Result:=(ord(vMemoryRead  in flags)*TM_READ) or
         (ord(vMemoryWrite in flags)*TM_WRITE);
end;

Procedure TvUniformBuilder.AddVSharp(PV:PVSharpResource4;fset,bind,size,offset:DWord;flags:TvLayoutFlags);
var
 b:TBufBindExt;
 stride,num_records:Integer;
begin
 Assert(PV<>nil);
 if (PV=nil) then Exit;

 //print_vsharp(PV);

 b:=Default(TBufBindExt);
 b.fset  :=fset;
 b.bind  :=bind;
 b.offset:=offset;
 b.memuse:=_get_buf_mem_usage(flags);

 b.addr:=Pointer(PV^.base);

 stride     :=PV^.stride;
 num_records:=PV^.num_records;
 //
 if (stride=0)      then stride:=1;
 if (num_records=0) then num_records:=1;
 //
 b.size:=(stride*num_records)+offset; //take into account the offset inside the shader
 //
 if (b.size>size) then b.size:=size;  //input size already taking into account offset

 Insert(b,FBuffers,Length(FBuffers));
end;

Procedure TvUniformBuilder.AddBufPtr(P:Pointer;fset,bind,size,offset:DWord;flags:TvLayoutFlags);
var
 b:TBufBindExt;
begin
 Assert(P<>nil);
 if (P=nil) or (size=0) then Exit;

 b:=Default(TBufBindExt);
 b.fset  :=fset;
 b.bind  :=bind;
 b.offset:=offset;
 b.memuse:=_get_buf_mem_usage(flags);

 b.addr:=P;
 b.size:=size; //input size already taking into account offset

 Insert(b,FBuffers,Length(FBuffers));
end;

Procedure TvUniformBuilder.AddTSharp4(PT:PTSharpResource4;btype:TvBindImageType;fset,bind:DWord;flags:TvLayoutFlags);
var
 b:TImageBindExt;
begin
 Assert(PT<>nil);
 if (PT=nil) then Exit;

 //print_tsharp4(PT);

 b:=Default(TImageBindExt);
 b.btype :=btype;
 b.fset  :=fset;
 b.bind  :=bind;
 b.memuse:=_get_buf_mem_usage(flags);

 b.FImage:=_get_tsharp4_image_info(PT);
 b.FView :=_get_tsharp4_image_view(PT);

 Insert(b,FImages,Length(FImages));
end;

Procedure TvUniformBuilder.AddTSharp8(PT:PTSharpResource8;btype:TvBindImageType;fset,bind:DWord;flags:TvLayoutFlags);
var
 b:TImageBindExt;
begin
 Assert(PT<>nil);
 if (PT=nil) then Exit;

 //print_tsharp8(PT);

 b:=Default(TImageBindExt);
 b.btype :=btype;
 b.fset  :=fset;
 b.bind  :=bind;
 b.memuse:=_get_buf_mem_usage(flags);

 b.FImage:=_get_tsharp8_image_info(PT);
 b.FView :=_get_tsharp8_image_view(PT);

 Insert(b,FImages,Length(FImages));
end;

procedure TvUniformBuilder.AddAttr(const b:TvCustomLayout;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
var
 P:Pointer;
begin
 P:=GetSharpByPatch(pUserData,pImmData,b.addr);
 Assert(P<>nil);
 if (P=nil) then Exit;

 Case TVkDescriptorType(b.dtype) of
  VK_DESCRIPTOR_TYPE_SAMPLER:
    Case b.addr[0].rtype of
     vtSSharp4:AddSSharp4(P,fset,b.bind);
     else
      Assert(false,'AddAttr');
    end;
  //
  VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE:
    Case b.addr[0].rtype of
     vtTSharp4:AddTSharp4(P,vbSampled,fset,b.bind,b.flags);
     vtTSharp8:AddTSharp8(P,vbSampled,fset,b.bind,b.flags);
     else
      Assert(false,'AddAttr');
    end;
  //
  VK_DESCRIPTOR_TYPE_STORAGE_IMAGE:
    if (vMipArray in b.flags) then
    begin
     Case b.addr[0].rtype of
      vtTSharp4:AddTSharp4(P,vbMipStorage,fset,b.bind,b.flags);
      vtTSharp8:AddTSharp8(P,vbMipStorage,fset,b.bind,b.flags);
      else
       Assert(false,'AddAttr');
     end;
    end else
    begin
     Case b.addr[0].rtype of
      vtTSharp4:AddTSharp4(P,vbStorage,fset,b.bind,b.flags);
      vtTSharp8:AddTSharp8(P,vbStorage,fset,b.bind,b.flags);
      else
       Assert(false,'AddAttr');
     end;
    end;
  //
  //VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER=4,
  //VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER=5,
  VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
  VK_DESCRIPTOR_TYPE_STORAGE_BUFFER:
    Case b.addr[0].rtype of
     vtRoot,
     vtBufPtr2:AddBufPtr(P,Fset,b.bind,b.size,b.offset,b.flags);
     vtVSharp4:AddVSharp(P,Fset,b.bind,b.size,b.offset,b.flags);
     else
      Assert(false,'AddAttr');
    end;

  else
   Assert(false,'AddAttr');
 end;

 //Writeln('----');
end;

function AlignShift(addr:Pointer;alignment:PtrUInt):PtrUInt; inline;
begin
 if (alignment>1) then
 begin
  Result:=(PtrUInt(addr) mod alignment);
 end else
 begin
  Result:=0;
 end;
end;

Procedure TvUniformBuilder.AddSSharp4(PS:PSSharpResource4;fset,bind:DWord);
var
 b:TSamplerBindExt;
begin
 Assert(PS<>nil);
 if (PS=nil) then Exit;

 //print_ssharp4(PS);

 b:=Default(TSamplerBindExt);
 b.fset:=fset;
 b.bind:=bind;
 b.PS:=PS;

 Insert(b,FSamplers,Length(FSamplers));
end;

//

Procedure TvShadersKey.SetLSShader(Shader:TvShaderExt);
begin
 if (Shader=nil) then Exit;
 if (Shader.FStage=VK_SHADER_STAGE_VERTEX_BIT) then
  FShaders[vShaderStageLs]:=Shader;
end;

Procedure TvShadersKey.SetHSShader(Shader:TvShaderExt);
begin
 if (Shader=nil) then Exit;
 if (Shader.FStage=VK_SHADER_STAGE_TESSELLATION_CONTROL_BIT) then
  FShaders[vShaderStageHs]:=Shader;
end;

Procedure TvShadersKey.SetESShader(Shader:TvShaderExt);
begin
 if (Shader=nil) then Exit;
 if (Shader.FStage=VK_SHADER_STAGE_TESSELLATION_EVALUATION_BIT) then
  FShaders[vShaderStageEs]:=Shader;
end;

Procedure TvShadersKey.SetGSShader(Shader:TvShaderExt);
begin
 if (Shader=nil) then Exit;
 if (Shader.FStage=VK_SHADER_STAGE_GEOMETRY_BIT) then
  FShaders[vShaderStageGs]:=Shader;
end;

Procedure TvShadersKey.SetVSShader(Shader:TvShaderExt);
begin
 if (Shader=nil) then Exit;
 if (Shader.FStage=VK_SHADER_STAGE_VERTEX_BIT) then
  FShaders[vShaderStageVs]:=Shader;
end;

Procedure TvShadersKey.SetPSShader(Shader:TvShaderExt);
begin
 if (Shader=nil) then Exit;
 if (Shader.FStage=VK_SHADER_STAGE_FRAGMENT_BIT) then
  FShaders[vShaderStagePs]:=Shader;
end;

Procedure TvShadersKey.SetCSShader(Shader:TvShaderExt);
begin
 if (Shader=nil) then Exit;
 if (Shader.FStage=VK_SHADER_STAGE_COMPUTE_BIT) then
 begin
  FShaders[vShaderStageCs]:=Shader;
 end;
end;

procedure TvShadersKey.ExportLayout(var A:AvSetLayout;
                                    var B:AvPushConstantRange);
var
 i:TvShaderStage;
 Shader:TvShaderExt;
 ia,p:Integer;
 CacheLayout:TvSetLayout;
begin
 p:=0;

 //need sorted by FDescSetId

 For i:=Low(TvShaderStage) to High(TvShaderStage) do
 begin
  Shader:=FShaders[i];
  if (Shader<>nil) then
  begin
   Shader.InitSetLayout;

   p:=Shader.FDescSetId;

   ia:=Length(A);
   if ((p+1)>ia) then
   begin
    SetLength(A,p+1);
    For ia:=ia to High(A) do
    begin
     A[ia]:=nil;
    end;
   end;

   A[p]:=Shader.FSetLayout;

   if (Shader.FPushConst.size<>0) then
   begin
    p:=Length(B);
    SetLength(B,p+1);

    B[p]:=Default(TVkPushConstantRange);
    B[p].stageFlags:=ord(Shader.FStage);
    B[p].offset    :=Shader.FPushConst.offset;
    B[p].size      :=Shader.FPushConst.size;
   end;

  end;
 end;

 //fill zeros
 if (Length(A)<>0) then
 begin
  CacheLayout:=nil;
  For ia:=0 to High(A) do
   if (A[ia]=nil) then
   begin
    if (CacheLayout=nil) then
    begin
     CacheLayout:=FetchSetLayout(0,0,[]);
    end;

    A[ia]:=CacheLayout;
   end;
 end;
end;

Procedure TvShadersKey.ExportStages(Stages:PVkPipelineShaderStageCreateInfo;stageCount:PVkUInt32);
var
 i:TvShaderStage;
 c:Integer;
begin
 c:=0;
 For i:=Low(TvShaderStage) to High(TvShaderStage) do
  if (FShaders[i]<>nil) then
  begin
   Assert(FShaders[i].FHandle<>VK_NULL_HANDLE);
   Stages[c].sType :=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
   Stages[c].stage :=FShaders[i].FStage;
   Stages[c].module:=FShaders[i].FHandle;
   Stages[c].pName :=PChar(FShaders[i].FEntry);
   Inc(c);
  end;
 stageCount^:=c;
end;

Procedure TvShaderGroup.Clear;
begin
 FKey:=Default(TvShadersKey);
 FLayout:=nil;
end;

Function TvShaderGroup.Compile:Boolean;
var
 A:AvSetLayout;
 B:AvPushConstantRange;
begin
 Result:=True;
 if (FLayout<>nil) then Exit;

 A:=Default(AvSetLayout);
 B:=Default(AvPushConstantRange);

 FKey.ExportLayout(A,B);

 FLayout:=FetchPipelineLayout(A,B);
 Result:=(FLayout<>nil);
end;

Procedure TvShaderGroup.ExportAttrBuilder(var AttrBuilder:TvAttrBuilder;GPU_USERDATA:PGPU_USERDATA);
var
 Shader:TvShaderExt;
 pUserData,pImmData:PDWORD;
begin
 Shader:=FKey.FShaders[vShaderStageVs];
 if (Shader<>nil) then
 begin
  pUserData:=GPU_USERDATA^.get_user_data(vShaderStageVs);
  pImmData :=Shader.GetImmData;
  Shader.EnumVertLayout(@AttrBuilder.AddAttr,Shader.FDescSetId,pUserData,pImmData);
 end;
end;

Procedure TvShaderGroup.ExportUnifBuilder(var UniformBuilder:TvUniformBuilder;GPU_USERDATA:PGPU_USERDATA);
var
 Shader:TvShaderExt;
 i:TvShaderStage;
 pUserData,pImmData:PDWORD;
begin
 For i:=Low(TvShaderStage) to High(TvShaderStage) do
 begin
  Shader:=FKey.FShaders[i];
  if (Shader<>nil) then
  begin
   pUserData:=GPU_USERDATA^.get_user_data(i);
   pImmData :=Shader.GetImmData;
   Shader.EnumUnifLayout(@UniformBuilder.AddAttr,Shader.FDescSetId,pUserData,pImmData);
  end;
 end;
end;

procedure TvBufOffsetChecker.AddAttr(const b:TvCustomLayout;Fset:TVkUInt32;pUserData,pImmData:PDWORD);
var
 P:Pointer;
 a:QWORD;
begin
 if not FResult then Exit;

 P:=GetSharpByPatch(pUserData,pImmData,b.addr);
 if (P=nil) then Exit;

 Case TVkDescriptorType(b.dtype) of
  //VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER=4,
  //VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER=5,
  VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
  VK_DESCRIPTOR_TYPE_STORAGE_BUFFER:
    Case b.addr[0].rtype of
     vtRoot,
     vtBufPtr2:
       begin
        a:=AlignShift(P,limits.minStorageBufferOffsetAlignment);
        if (a<>b.offset) then FResult:=False;
       end;
     vtVSharp4:
       begin
        a:=AlignShift(Pointer(PVSharpResource4(P)^.base),limits.minStorageBufferOffsetAlignment);
        if (a<>b.offset) then FResult:=False;
       end;
     else
      Assert(false);
    end;

  else;
 end;
end;

Procedure TvFuncLayout.Add(const addr:ADataLayout);
begin
 Insert(addr,FList,Length(FList));
end;

end.





unit vShaderManager;

{$mode objfpc}{$H+}

interface

uses
  SysUtils,
  Classes,
  Vulkan,
  murmurhash,
  g23tree,
  ps4_pssl,
  ps4_shader,

  vRegs2Vulkan,
  shader_dump,

  si_ci_vi_merged_enum,
  si_ci_vi_merged_registers,

  vDevice,

  vShader,
  vShaderExt,

  SprvEmit,
  emit_bin;

const
 STAGE_NAME:array[TvShaderStage] of PChar=(
  'Ls',
  'Hs',
  'Es',
  'Gs',
  'Vs',
  'Ps',
  'Cs');

type
 PShaderDataKey=^TShaderDataKey;
 TShaderDataKey=packed object
  FStage:TvShaderStage;
  FLen  :Ptruint;
  pData :PDWORD;
  FHash :QWORD;
  function  c(a,b:PShaderDataKey):Integer; static;
  Procedure SetData(Stage:TvShaderStage;Src:Pointer);
  Procedure Free;
 end;

 TShaderCodeCache=class
  key:TShaderDataKey;
  FShaderAliases:array of TvShaderExt;
  function   AddShader(FDescSetId:Integer;Stream:TStream;pUserData:Pointer):TvShaderExt;
  Destructor Destroy; override;
 end;

 PPushConstAllocator=^TPushConstAllocator;
 TPushConstAllocator=object
  size  :DWORD;
  offset:DWORD;
  Procedure Init;
  function  GetAvailable:DWORD;
  procedure Apply(i:DWORD);
 end;

{
 TShaderCacheSet
 ---------------
   [TShaderCodeCache]
   (
    [TShaderDataKey]
      FShaderAliases [TvShaderExt]
      ---------------

      ---------------
      ...............
      ---------------
   )
 ---------------
 ...............
 ---------------
}

function FetchShader(FStage:TvShaderStage;FDescSetId:Integer;var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TvShaderExt;
function FetchShaderGroup(F:PvShadersKey):TvShaderGroup;
function FetchShaderGroupRT(var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TvShaderGroup;
function FetchShaderGroupCS(var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TvShaderGroup;

function GetDumpSpvName(FStage:TvShaderStage;hash:QWORD):RawByteString;

implementation

uses
 vRectGS,
 //
 kern_rwlock,
 kern_dmem;

type
 TShadersKeyCompare=object
  function c(a,b:PvShadersKey):Integer; static;
 end;

 _TShaderCacheSet=specialize T23treeSet<PShaderDataKey,TShaderDataKey>;
 TShaderCacheSet=object(_TShaderCacheSet)
  lock:Pointer;
  Procedure Lock_wr;
  Procedure Unlock_wr;
 end;

 _TShaderGroupSet=specialize T23treeSet<PvShadersKey,TShadersKeyCompare>;
 TShaderGroupSet=object(_TShaderGroupSet)
  lock:Pointer;
  Procedure Lock_wr;
  Procedure Unlock_wr;
 end;

var
 FShaderCacheSet:TShaderCacheSet;
 FShaderGroupSet:TShaderGroupSet;

Procedure TShaderCacheSet.Lock_wr;
begin
 rw_wlock(lock);
end;

Procedure TShaderCacheSet.Unlock_wr;
begin
 rw_wunlock(lock);
end;

//

Procedure TShaderGroupSet.Lock_wr;
begin
 rw_wlock(lock);
end;

Procedure TShaderGroupSet.Unlock_wr;
begin
 rw_wunlock(lock);
end;

function Max(a,b:PtrInt):PtrInt; inline;
begin
 if (a>b) then Result:=a else Result:=b;
end;

function TShaderDataKey.c(a,b:PShaderDataKey):Integer;
begin
 //1 FStage
 Result:=Integer(a^.FStage>b^.FStage)-Integer(a^.FStage<b^.FStage);
 if (Result<>0) then Exit;

 //2 FLen
 Result:=Integer((a^.FLen>b^.FLen) and (b^.FLen<>0))-Integer((a^.FLen<b^.FLen) and (a^.FLen<>0));
 if (Result<>0) then Exit;

 //3 pData
 Result:=CompareDWord(a^.pData^,b^.pData^,Max(a^.FLen,b^.FLen) div 4);
end;

function TShadersKeyCompare.c(a,b:PvShadersKey):Integer;
begin
 Result:=CompareByte(a^.FShaders,b^.FShaders,SizeOf(AvShaderStage));
end;

function TShaderCodeCache.AddShader(FDescSetId:Integer;Stream:TStream;pUserData:Pointer):TvShaderExt;
begin
 Result:=TvShaderExt.Create;
 Result.FHash_gcn:=key.FHash;

 Result.FDescSetId:=FDescSetId; //set before loading
 Result.LoadFromStream(Stream);

 Insert(Result,FShaderAliases,Length(FShaderAliases));
end;

Destructor TShaderCodeCache.Destroy;
begin
 Key.Free;
 inherited;
end;

Procedure TShaderDataKey.SetData(Stage:TvShaderStage;Src:Pointer);
begin
 Free;

 FStage:=Stage;
 FLen  :=_calc_shader_size(Src);
 pData :=AllocMem(FLen);

 Move(Src^,pData^,FLen);

 FHash:=MurmurHash64A(pData,FLen,0);
end;

Procedure TShaderDataKey.Free;
begin
 if (FLen<>0) and (pData<>nil) then
 begin
  FreeMem(pData);
 end;
end;

function _FindShaderCodeCache(const key:TShaderDataKey):TShaderCodeCache;
var
 i:TShaderCacheSet.Iterator;
begin
 Result:=nil;
 i:=FShaderCacheSet.find(@key);
 if (i.Item<>nil) then
 begin
  Result:=TShaderCodeCache(ptruint(i.Item^)-ptruint(@TShaderCodeCache(nil).key));
 end;
end;

function _FetchShaderCodeCache(FStage:TvShaderStage;pData:PDWORD):TShaderCodeCache;
var
 key:TShaderDataKey;
 t:TShaderCodeCache;
begin

 key:=Default(TShaderDataKey);
 key.FStage:=FStage;

 if not get_dmem_ptr(pData,@key.pData,nil) then
 begin
  Assert(false,'_FetchShaderCodeCache');
 end;

 t:=_FindShaderCodeCache(key);

 if (t=nil) then
 begin
  t:=TShaderCodeCache.Create;
  t.key:=key;

  t.key.SetData(key.FStage,key.pData);

  FShaderCacheSet.Insert(@t.key);
 end;

 Result:=t;
end;

function GetDumpSpvName(FStage:TvShaderStage;hash:QWORD):RawByteString;
begin
 Result:=get_dev_progname+'_'+LowerCase(STAGE_NAME[FStage])+'_'+HexStr(hash,16)+'.spv';
end;

Procedure DumpSpv(FStage:TvShaderStage;M:TMemoryStream;hash:QWORD);
var
 F:THandle;
 fname:RawByteString;
begin
 if (hash=0) then
 begin
  hash:=MurmurHash64A(M.Memory,M.Size,0);
 end;

 fname:=GetDumpSpvName(FStage,hash);

 fname:='shader_dump\'+fname;

 if FileExists(fname) then Exit;

 CreateDir('shader_dump');

 F:=FileCreate(fname);
 FileWrite(F,M.Memory^,M.Size);
 FileClose(F);
end;

procedure TPushConstAllocator.Init;
begin
 Size:=limits.maxPushConstantsSize;
 offset:=0;
end;

function TPushConstAllocator.GetAvailable:DWORD;
begin
 Result:=0;
 if (offset<Size) then
 begin
  Result:=Size-offset;
 end;
end;

procedure TPushConstAllocator.Apply(i:DWORD);
begin
 offset:=offset+i;
end;

function _GetDmem(P:Pointer):Pointer; register;
begin
 Result:=nil;
 if not get_dmem_ptr(P,@Result,nil) then
 begin
  Assert(false,'_GetDmem');
 end;
end;

function ParseShader(FStage:TvShaderStage;pData:PDWORD;var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TMemoryStream;
var
 SprvEmit:TSprvEmit;
begin
 Result:=nil;
 SprvEmit:=TSprvEmit.Create;

 case FStage of
  vShaderStagePs:
  begin
   SprvEmit.InitPs(GPU_REGS.SG_REG^.SPI_SHADER_PGM_RSRC1_PS,
                   GPU_REGS.SG_REG^.SPI_SHADER_PGM_RSRC2_PS,
                   GPU_REGS.CX_REG^.SPI_PS_INPUT_ENA,
                   GPU_REGS.CX_REG^.SPI_PS_INPUT_ADDR);

   SprvEmit.SetUserData(GPU_REGS.get_user_data(FStage));

   SprvEmit.SET_SHADER_CONTROL(GPU_REGS.CX_REG^.DB_SHADER_CONTROL);
   SprvEmit.SET_INPUT_CNTL    (GPU_REGS.CX_REG^.SPI_PS_INPUT_CNTL,
                               GPU_REGS.CX_REG^.SPI_PS_IN_CONTROL.NUM_INTERP);
   SprvEmit.SET_RENDER_TARGETS(@GPU_REGS.CX_REG^.RENDER_TARGET,GPU_REGS.GET_HI_RT+1);
  end;
  vShaderStageVs:
  begin
   SprvEmit.InitVs(GPU_REGS.SG_REG^.SPI_SHADER_PGM_RSRC1_VS,
                   GPU_REGS.SG_REG^.SPI_SHADER_PGM_RSRC2_VS,
                   GPU_REGS.CX_REG^.VGT_INSTANCE_STEP_RATE_0,
                   GPU_REGS.CX_REG^.VGT_INSTANCE_STEP_RATE_1);

   SprvEmit.SetUserData(GPU_REGS.get_user_data(FStage));
  end;
  vShaderStageCs:
  begin
   SprvEmit.InitCs(GPU_REGS.SC_REG^.COMPUTE_PGM_RSRC1,
                   GPU_REGS.SC_REG^.COMPUTE_PGM_RSRC2);

   SprvEmit.SET_NUM_THREADS(GPU_REGS.SC_REG^.COMPUTE_NUM_THREAD_X,
                            GPU_REGS.SC_REG^.COMPUTE_NUM_THREAD_Y,
                            GPU_REGS.SC_REG^.COMPUTE_NUM_THREAD_Z);

   SprvEmit.SetUserData(GPU_REGS.get_user_data(FStage));
  end;

  else
    Assert(false,'TODO PARSE:'+STAGE_NAME[FStage]);
 end;

 SprvEmit.Config.PrintAsm      :=False;
 SprvEmit.Config.UseVertexInput:=True;
 SprvEmit.Config.UseTexelBuffer:=False;
 SprvEmit.Config.UseOutput16   :=storageInputOutput16;
 SprvEmit.Config.UseOnlyUserdataPushConst:=True;

 SprvEmit.Config.maxUniformBufferRange          :=0; // $FFFF
 SprvEmit.Config.PushConstantsOffset            :=0; // 0
 SprvEmit.Config.minStorageBufferOffsetAlignment:=limits.minStorageBufferOffsetAlignment; // $10
 SprvEmit.Config.minUniformBufferOffsetAlignment:=limits.minUniformBufferOffsetAlignment; // $100

 SprvEmit.Config.maxPushConstantsSize:=0;
 if (pc<>nil) then
 begin
  SprvEmit.Config.PushConstantsOffset :=pc^.offset;
  SprvEmit.Config.maxPushConstantsSize:=pc^.GetAvailable;
 end;

 //SprvEmit.Config.UseVertexInput:=False;

 SprvEmit.Config.OnGetDmem:=@_GetDmem;

 if (SprvEmit.ParseStage(pData)>1) then
 begin
  Writeln(StdErr,'Shader Parse Err');
  SprvEmit.Free;
  Exit;
 end;

 SprvEmit.PostStage;
 SprvEmit.AllocStage;

 Result:=TMemoryStream.Create;
 SprvEmit.SaveToStream(Result);

 SprvEmit.Free;
end;

function test_func(FShader:TvShaderExt;pUserData:Pointer):Boolean;
var
 L:PvCustomLayout;
 src,dst:Pointer;
 i:Integer;
begin
 Result:=True;
 if (Length(FShader.FFuncLayouts)=0) then Exit;

 For i:=0 to High(FShader.FFuncLayouts) do
 begin
  L:=@FShader.FFuncLayouts[i];

  src:=Pointer(@FShader.FImmData[0])+L^.offset;

  dst:=GetSharpByPatch(pUserData,FShader.GetImmData,L^.addr);

  if (src<>nil) then
  if (dst<>nil) then
  begin

   if (CompareDWord(src^,dst^,L^.size div SizeOf(DWORD))<>0) then
   begin
    Exit(False);
   end;

  end;

 end;
end;

function test_instance(FShader:TvShaderExt;FStage:TvShaderStage;var GPU_REGS:TGPU_REGS):Boolean;
var
 VGPR_COMP_CNT:Byte;
begin
 if (FStage<>vShaderStageVs) then Exit(True);

 VGPR_COMP_CNT:=GPU_REGS.SG_REG^.SPI_SHADER_PGM_RSRC1_VS.VGPR_COMP_CNT;

 if (FShader.FParams.VGPR_COMP_CNT<>VGPR_COMP_CNT) then Exit(False);

 if (VGPR_COMP_CNT>=1) then
 begin
  if (FShader.FParams.STEP_RATE_0<>GPU_REGS.CX_REG^.VGT_INSTANCE_STEP_RATE_0) then Exit(False);
 end;

 if (VGPR_COMP_CNT>=2) then
 begin
  if (FShader.FParams.STEP_RATE_1<>GPU_REGS.CX_REG^.VGT_INSTANCE_STEP_RATE_1) then Exit(False);
 end;

 Result:=True;
end;

function CompareExportInfo(FShader:TvShaderExt;R:PRENDER_TARGET):Boolean;
var
 i:Byte;
begin
 if (FShader.FParams.EXPORT_COUNT<>0) then
 for i:=0 to FShader.FParams.EXPORT_COUNT-1 do
 begin
  if (FShader.FParams.EXPORT_COLOR[i].FORMAT     <>R[i].INFO.FORMAT     ) then Exit(False);
  if (FShader.FParams.EXPORT_COLOR[i].NUMBER_TYPE<>R[i].INFO.NUMBER_TYPE) then Exit(False);
  if (FShader.FParams.EXPORT_COLOR[i].COMP_SWAP  <>R[i].INFO.COMP_SWAP  ) then Exit(False);
 end;
 //
 Result:=True;
end;

function test_params(FShader:TvShaderExt;FStage:TvShaderStage;var GPU_REGS:TGPU_REGS):Boolean;
begin

 if (FStage=vShaderStagePs) then
 begin
  if (DWORD(FShader.FParams.SHADER_CONTROL)<>DWORD(GPU_REGS.CX_REG^.DB_SHADER_CONTROL)) then Exit(False);

  if (FShader.FParams.NUM_INTERP<>GPU_REGS.CX_REG^.SPI_PS_IN_CONTROL.NUM_INTERP) then Exit(False);

  if (CompareByte(FShader.FParams.INPUT_CNTL,
                  GPU_REGS.CX_REG^.SPI_PS_INPUT_CNTL,
                  SizeOf(TSPI_PS_INPUT_CNTL_0)*FShader.FParams.NUM_INTERP)<>0) then Exit(False);

  if (not CompareExportInfo(FShader,@GPU_REGS.CX_REG^.RENDER_TARGET)) then Exit(False);
 end;

 if (FStage=vShaderStageCs) then
 begin
  if (DWORD(FShader.FParams.NUM_THREAD_X)<>DWORD(GPU_REGS.SC_REG^.COMPUTE_NUM_THREAD_X)) then Exit(False);
  if (DWORD(FShader.FParams.NUM_THREAD_Y)<>DWORD(GPU_REGS.SC_REG^.COMPUTE_NUM_THREAD_Y)) then Exit(False);
  if (DWORD(FShader.FParams.NUM_THREAD_Z)<>DWORD(GPU_REGS.SC_REG^.COMPUTE_NUM_THREAD_Z)) then Exit(False);
 end;

 Result:=True;
end;

function test_unif(FShader:TvShaderExt;FDescSetId:Integer;pUserData:Pointer):Boolean;
var
 ch:TvUnifChecker;
begin
 if (FShader.FDescSetId<>FDescSetId) then Exit(False);
 ch.FResult:=True;
 FShader.EnumUnifLayout(@ch.AddAttr,FDescSetId,pUserData,FShader.GetImmData);
 Result:=ch.FResult;
end;

function test_push_const(FShader:TvShaderExt;pc_offset,pc_size:DWORD):Boolean;
begin
 with FShader.FPushConst do
 begin
  Result:=(offset       >=pc_offset) and  //Checking offsets push constant
          ((offset+size)<=pc_size);       //Is the remaining size sufficient?
 end;
end;

function _FetchShader(FStage:TvShaderStage;FDescSetId:Integer;var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TvShaderExt;
var
 i:Integer;
 FShader:TvShaderExt;
 t:TShaderCodeCache;

 M:TMemoryStream;

 pData:PDWORD;
 pUserData:Pointer;

 pc_offset,pc_size,pc_diff:DWORD;

 FHash_spv:QWORD;

 str:RawByteString;
begin
 pData:=GPU_REGS.get_code_addr(FStage);

 {
  ...start <-\
             |
  ...offset  |
             |
  ...size  --/
 }

 if (pc<>nil) then //push const allocator used?
 begin
  pc_offset:=pc^.offset;
  pc_size  :=pc^.GetAvailable;
 end else
 begin
  pc_offset:=0;
  pc_size  :=0;
 end;

 t:=_FetchShaderCodeCache(FStage,pData);

 FShader:=nil;

 if (Length(t.FShaderAliases)<>0) then
 begin

  pUserData:=GPU_REGS.get_user_data(FStage);

  For i:=0 to High(t.FShaderAliases) do
  begin
   FShader:=t.FShaderAliases[i];

   if test_func(FShader,pUserData) then
   if test_instance(FShader,FStage,GPU_REGS) then
   if test_params(FShader,FStage,GPU_REGS) then
   if test_unif(FShader,FDescSetId,pUserData) then //Checking offsets within a shader
   if test_push_const(FShader,pc_offset,pc_size) then
   begin
    Break; //found
   end;

   FShader:=nil; //reset with not found
  end;

 end;

 if (FShader=nil) then //Rebuild with different parameters
 begin

  //dump gcn (before parse)
  if (Length(t.FShaderAliases)=0) then
  begin
   str:='';
   case FStage of
    vShaderStagePs:str:=DumpPS(GPU_REGS,t.key.FHash);
    vShaderStageVs:str:=DumpVS(GPU_REGS,t.key.FHash);
    vShaderStageCs:str:=DumpCS(GPU_REGS,t.key.FHash);
    else
     begin
      Writeln(stderr,'Unhandle stage:',FStage);
     end;
   end;
   //Writeln(str);
  end;
  //

  M:=ParseShader(FStage,pData,GPU_REGS,pc);
  Assert(M<>nil);

  //hach/dump
  FHash_spv:=MurmurHash64A(M.Memory,M.Size,0);
  DumpSpv(FStage,M,FHash_spv);
  //

  pUserData:=GPU_REGS.get_user_data(FStage);

  FShader:=t.AddShader(FDescSetId,M,pUserData);

  //set hash
  FShader.FHash_spv:=FHash_spv;

  //setname
  FShader.SetObjectName(LowerCase(STAGE_NAME[FStage])+
                        '_gcn:0x'+HexStr(FShader.FHash_gcn,16)+
                        '_spv:0x'+HexStr(FShader.FHash_spv,16));

  //free spv data
  M.Free;

  //

  if (FShader.FPushConst.size<>0) and (pc<>nil) then //push const used?
  begin
   FShader.FPushConst.offset:=pc_offset;   //Save offset
   Dec(FShader.FPushConst.size,pc_offset); //Move up size

   {
    ...start

    ...offset<-\
               |
    ...size  --/
   }
  end;

 end;

 if (FShader.FPushConst.size<>0) and (pc<>nil) then //push const used?
 begin
  pc_diff:=FShader.FPushConst.offset-pc_offset; //get diff offset
  pc^.Apply(pc_diff+FShader.FPushConst.size);   //apply with allocator
 end;

 Result:=FShader;
end;

function FetchShader(FStage:TvShaderStage;FDescSetId:Integer;var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TvShaderExt;
begin
 FShaderCacheSet.Lock_wr;

 Result:=_FetchShader(FStage,FDescSetId,GPU_REGS,pc);

 FShaderCacheSet.Unlock_wr;
end;

//

function _FindShaderGroup(F:PvShadersKey):TvShaderGroup;
var
 i:TShaderGroupSet.Iterator;
begin
 Result:=nil;
 i:=FShaderGroupSet.find(F);
 if (i.Item<>nil) then
 begin
  Result:=TvShaderGroup(ptruint(i.Item^)-ptruint(@TvShaderGroup(nil).FKey));
 end;
end;

function _FetchShaderGroup(F:PvShadersKey):TvShaderGroup;
var
 t:TvShaderGroup;
begin
 Result:=nil;

 t:=_FindShaderGroup(F);

 if (t=nil) then
 begin

  t:=TvShaderGroup.Create;
  t.FKey:=F^;

  if not t.Compile then
  begin
   FreeAndNil(t);
  end else
  begin
   FShaderGroupSet.Insert(@t.FKey);
  end;
 end;

 Result:=t;
end;

function FetchShaderGroup(F:PvShadersKey):TvShaderGroup;
begin
 Result:=nil;
 if (F=nil) then Exit;

 FShaderGroupSet.Lock_wr;

 Result:=_FetchShaderGroup(F);

 FShaderGroupSet.Unlock_wr;
end;

procedure EmitShaderGroupExtension(var GPU_REGS:TGPU_REGS;F:PvShadersKey);
Var
 M:TMemoryStream;
 PS:TvShaderExt;
 VS:TvShaderExt;
 GS:TvShaderExt;
begin
 //

 PS:=F^.FShaders[vShaderStagePs];
 VS:=F^.FShaders[vShaderStageVs];

 if (VS<>nil) and
    (not VS.IsVSRectListShader) and
    (ord(GPU_REGS.GET_PRIM_TYPE)=DI_PT_RECTLIST) then
 begin
  Assert(F^.FShaders[vShaderStageGs]=nil,'Geometry shader is already present');

  //load cache
  if (PS<>nil) then
  begin
   GS:=PS.FGeomRectList;
  end else
  begin
   GS:=VS.FGeomRectList;
  end;
  //load cache

  if (GS=nil) then
  begin
   M:=CompileRectangleGeometryShader(GPU_REGS);
   //M.SaveToFile('rect_geom.spv');

   GS:=TvShaderExt.Create;
   GS.LoadFromStream(M);

   GS.SetObjectName('GS_RECT');

   M.Free;

   //save cache
   if (PS<>nil) then
   begin
    PS.FGeomRectList:=GS;
   end else
   begin
    VS.FGeomRectList:=GS;
   end;
   //save cache
  end;

  F^.FShaders[vShaderStageGs]:=GS;
  F^.FPrimtype:=ord(VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST);
  //
 end;
end;

function FetchShaderGroupRT(var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TvShaderGroup;
var
 FShadersKey:TvShadersKey;
 i:TvShaderStage;
 FDescSetId:Integer;
begin
 FShadersKey:=Default(TvShadersKey);
 FShadersKey.FPrimtype:=-1;

 FDescSetId:=0;

 For i:=High(TvShaderStage) downto Low(TvShaderStage) do
 begin
  if (i<>vShaderStageCs) then
  if (GPU_REGS.get_code_addr(i)<>nil) then
  begin
   FShadersKey.FShaders[i]:=FetchShader(i,FDescSetId,GPU_REGS,pc);
   Inc(FDescSetId);
  end;
 end;

 EmitShaderGroupExtension(GPU_REGS,@FShadersKey);

 Result:=FetchShaderGroup(@FShadersKey);
end;

function FetchShaderGroupCS(var GPU_REGS:TGPU_REGS;pc:PPushConstAllocator):TvShaderGroup;
var
 FShadersKey:TvShadersKey;
begin
 FShadersKey:=Default(TvShadersKey);
 FShadersKey.FPrimtype:=-1;

 FShadersKey.FShaders[vShaderStageCs]:=FetchShader(vShaderStageCs,0,GPU_REGS,pc);

 Result:=FetchShaderGroup(@FShadersKey);
end;

end.


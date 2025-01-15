unit emit_alloc;

{$mode objfpc}{$H+}

interface

uses
  sysutils,
  spirv,

  srNode,
  srInterface,
  srType,
  srTypes,
  srConst,
  srRefId,
  srReg,
  srLayout,
  srVariable,
  srInput,
  srOutput,
  srVertLayout,
  srFragLayout,
  srUniform,
  srBuffer,
  srDecorate,
  srOp,
  srOpUtils,
  emit_fetch;

type
 TSprvEmit_alloc=class(TEmitFetch)
  procedure AllocSourceExtension;
  procedure AllocStage;
  procedure AllocSpirvID(P:PsrRefId);
  procedure AllocBinding;
  procedure AllocTypeBinding;
  procedure AllocEntryPoint;
  function  AddExecutionMode(mode:PtrUint):TSpirvOp;
  procedure AllocHeader;
  procedure AllocOpListId(node:TspirvOp);
  procedure AllocListId(node:TsrNode);
  procedure AllocFuncId;
  procedure AllocOpId(node:TSpirvOp);
  procedure AllocOpBlock(pBlock:TsrOpBlock);
 end;

implementation

procedure TSprvEmit_alloc.AllocSourceExtension;
var
 i:Integer;
 Writer:TseWriter;
begin
 DataLayoutList.AllocSourceExtension2;

 Writer:=Default(TseWriter);
 Writer.pList:=GetDebugInfoList;

 Writer.Header('-C');

 if (FExecutionModel=ExecutionModel.Vertex) then
 if (VGPR_COMP_CNT>=1) then
 begin
  Writer.IntOpt('VGPR_COMP_CNT'   ,VGPR_COMP_CNT);
  Writer.HexOpt('VGT_STEP_RATE_0' ,VGT_STEP_RATE_0);
  if (VGPR_COMP_CNT>=2) then
  begin
   Writer.HexOpt('VGT_STEP_RATE_1',VGT_STEP_RATE_1);
  end;
 end;

 if (FExecutionModel=ExecutionModel.Fragment) then
 begin
  Writer.HexOpt('DB_SHADER_CONTROL',DWORD(DB_SHADER_CONTROL));
  //
  if (PS_NUM_INTERP<>0) then
  begin
   Writer.IntOpt('PS_NUM_INTERP',PS_NUM_INTERP);
   for i:=0 to PS_NUM_INTERP-1 do
   begin
    Writer.HexOpt('PS_INPUT_CNTL',DWORD(FPSInputCntl[i].DATA));
   end;
  end;
  //
  if (EXPORT_COUNT<>0) then
  begin
   Writer.IntOpt('EXPORT_COUNT',EXPORT_COUNT);
   for i:=0 to EXPORT_COUNT-1 do
   begin
    Inc(Writer.deep);
    //
    Writer.Header('-EXPORT_COLOR');
    //
    Writer.IntOpt('FORMAT'     ,FExportInfo[i].FORMAT);
    Writer.IntOpt('NUMBER_TYPE',FExportInfo[i].NUMBER_TYPE);
    Writer.IntOpt('COMP_SWAP'  ,FExportInfo[i].COMP_SWAP);
    //
    Dec(Writer.deep);
   end;
  end;
 end;

 if (FExecutionModel=ExecutionModel.GLCompute) then
 begin
  Writer.HexOpt('CS_NUM_THREAD_X',CS_NUM_THREAD_X);
  Writer.HexOpt('CS_NUM_THREAD_Y',CS_NUM_THREAD_Y);
  Writer.HexOpt('CS_NUM_THREAD_Z',CS_NUM_THREAD_Z);
 end;

end;

procedure TSprvEmit_alloc.AllocStage;
begin
 AllocBinding;

 BufferList.AllocTypeBinding;
 AllocTypeBinding;

 AllocHeader;

 //Source Extension
 AllocSourceExtension;

 //Decorate Name
 BufferList  .AllocName;
 VariableList.AllocName;

 //header id
 AllocOpListId(HeaderList.First);
 AllocOpListId(DebugInfoList.First);
 AllocOpListId(DecorateList.First);

 //element id
 AllocListId(TypeList.First);
 AllocListId(ConstList.First);
 AllocListId(VariableList.First);

 AllocFuncId;
end;

procedure TSprvEmit_alloc.AllocSpirvID(P:PsrRefId);
begin
 RefIdAlloc.FetchSpirvID(P);
end;

procedure TSprvEmit_alloc.AllocBinding;
var
 FBinding:Integer;
begin
 InputList .AllocBinding;
 OutputList.AllocBinding;

 VertLayoutList.AllocBinding;
 FragLayoutList.AllocBinding;

 FBinding:=0;

 UniformList.AllocBinding(FBinding);
 BufferList .AllocBinding(FBinding);
end;

procedure TSprvEmit_alloc.AllocTypeBinding;
var
 node:TsrType;
begin
 node:=TypeList.First;
 While (node<>nil) do
 begin

  case node.OpId of

   Op.OpTypeArray,
   Op.OpTypeRuntimeArray:
    begin
     if (node.array_stride<>0) then
     begin
      DecorateList.OpDecorate(node,Decoration.ArrayStride,node.array_stride);
     end;
     //
     if (node.OpId=Op.OpTypeRuntimeArray) then
     if (node.is_array_image) then
     begin
      AddCapability(Capability.RuntimeDescriptorArray);
      HeaderList.SPV_EXT_descriptor_indexing;
     end;
    end;

   Op.OpTypeFloat:
     begin
      case node.dtype.BitSize of
       16:AddCapability(Capability.Float16);
       64:AddCapability(Capability.Float64);
       else;
      end;
     end;

   Op.OpTypeInt:
     begin
      case node.dtype.BitSize of
        8:AddCapability(Capability.Int8);
       16:AddCapability(Capability.Int16);
       64:AddCapability(Capability.Int64);
       else;
      end;
     end;

   else;
  end;

  node:=node.Next;
 end;
end;

procedure TSprvEmit_alloc.AllocOpListId(node:TspirvOp);
begin
 While (node<>nil) do
 begin
  AllocOpId(node);
  node:=node.Next;
 end;
end;

procedure TSprvEmit_alloc.AllocEntryPoint;
var
 node:TSpirvOp;
begin
 node:=HeaderList.AddSpirvOp(Op.OpEntryPoint);

 node.AddLiteral(FExecutionModel,ExecutionModel.GetStr(FExecutionModel));

 node.AddParam(Main);
 node.AddString(Main.name);

 InputList     .AllocEntryPoint(node);
 VertLayoutList.AllocEntryPoint(node);
 FragLayoutList.AllocEntryPoint(node);
 OutputList    .AllocEntryPoint(node);
end;

function TSprvEmit_alloc.AddExecutionMode(mode:PtrUint):TSpirvOp;
begin
 Result:=HeaderList.AddExecutionMode(Main,mode);
end;

procedure TSprvEmit_alloc.AllocHeader;
var
 node:TSpirvOp;
begin
 node:=HeaderList.AddSpirvOp(Op.OpMemoryModel);
 node.AddLiteral(AddressingModel.Logical,AddressingModel.GetStr(AddressingModel.Logical));
 node.AddLiteral(MemoryModel.GLSL450,MemoryModel.GetStr(MemoryModel.GLSL450));

 AllocEntryPoint;

 Case FExecutionModel of
  ExecutionModel.Fragment:
    begin
     AddExecutionMode(ExecutionMode.OriginUpperLeft);

     if FEarlyFragmentTests then
     begin
      AddExecutionMode(ExecutionMode.EarlyFragmentTests);
     end;

     case OutputList.FDepthMode of
      foDepthReplacing:AddExecutionMode(ExecutionMode.DepthReplacing);
      foDepthGreater  :AddExecutionMode(ExecutionMode.DepthGreater);
      foDepthLess     :AddExecutionMode(ExecutionMode.DepthLess);
      foDepthUnchanged:AddExecutionMode(ExecutionMode.DepthUnchanged);
      else;
     end;

    end;
  ExecutionModel.GLCompute:
    begin
     node:=AddExecutionMode(ExecutionMode.LocalSize);
     node.AddLiteral(FLocalSize.x);
     node.AddLiteral(FLocalSize.y);
     node.AddLiteral(FLocalSize.z);
    end;

  ExecutionModel.Geometry:
    begin
     node:=AddExecutionMode(ExecutionMode.OutputVertices);
     node.AddLiteral(FGeometryInfo.outputVertCount);
     //
     node:=AddExecutionMode(ExecutionMode.Invocations);
     node.AddLiteral(FGeometryInfo.invocationCount);
     //
     node:=AddExecutionMode(FGeometryInfo.InputMode);
     node:=AddExecutionMode(FGeometryInfo.OutputMode);
    end;

 end;

end;

procedure TSprvEmit_alloc.AllocListId(node:TsrNode);
begin
 While (node<>nil) do
 begin
  AllocSpirvID(node.GetRef);
  node:=node.Next;
 end;
end;

procedure TSprvEmit_alloc.AllocFuncId;
var
 pFunc:TSpirvFunc;
begin
 pFunc:=FuncList.First;
 While (pFunc<>nil) do
 begin
  AllocOpBlock(pFunc.pTop);
  pFunc:=pFunc.Next;
 end;
end;

procedure TSprvEmit_alloc.AllocOpId(node:TSpirvOp);
var
 Param:POpParamNode;
 Info:Op.TOpInfo;
 pReg:TsrRegNode;
begin
 if (node=nil) then Exit;

 Info:=Op.GetInfo(node.OpId);

 if Info.result then //dst
 begin
  Assert(node.pDst<>nil,'AllocOp$1');
  if (node.pDst<>nil) then
  begin
   AllocSpirvID(node.pDst.GetRef);
  end;
 end else
 begin  //no dst
  if (node.pDst<>nil) then
  begin
   AllocSpirvID(node.pDst.GetRef);
  end;
 end;

 if Info.rstype then //dst type
 begin
  if (node.pType=nil) then
  begin
   pReg:=node.pDst.specialize AsType<ntReg>;
   Assert(pReg<>nil,'AllocOp$2');
   Assert(pReg.dtype<>dtUnknow,'AllocOp$3');
   if (pReg<>nil) then
   begin
    node.pType:=TypeList.Fetch(pReg.dtype);
   end;
  end;
 end;

 Param:=node.ParamFirst;
 While (Param<>nil) do
 begin
  AllocSpirvID(Param.Value.GetRef);
  Param:=Param.Next;
 end;

end;

procedure TSprvEmit_alloc.AllocOpBlock(pBlock:TsrOpBlock);
var
 node:TSpirvOp;
begin
 if (pBlock=nil) then Exit;
 node:=pBlock.First;
 While (node<>nil) do
 begin
  if node.IsType(ntOp) then
  begin
   AllocOpId(node);
  end;
  node:=flow_down_next_up(node);
 end;
end;


end.


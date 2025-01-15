unit srVertLayout;

{$mode ObjFPC}{$H+}

interface

uses
 sysutils,
 spirv,
 ginodes,
 srNode,
 srType,
 srReg,
 srOp,
 srVariable,
 srLayout,
 srDecorate;

type
 PPsrDataLayout=^TsrDataLayout;

 TsrVertLayout=class(TsrDescriptor)
  public
   pLeft,pRight:TsrVertLayout;
   class function c(n1,n2:PPsrDataLayout):Integer; static;
  private
   key:TsrDataLayout;
  public
   pReg:TsrRegNode;
   //
   function  _GetStorageName:RawByteString; override;
   //
   property  pLayout:TsrDataLayout read key;
   procedure Init(p:TsrDataLayout); inline;
   function  GetStorageName:RawByteString;
   procedure AllocSourceExtension2(var Writer:TseWriter); override;
 end;

 ntVertLayout=TsrVertLayout;

 PsrVertLayoutList=^TsrVertLayoutList;
 TsrVertLayoutList=object
  type
   TNodeTree=specialize TNodeTreeClass<TsrVertLayout>;
  var
   FEmit:TCustomEmit;
   FTree:TNodeTree;
  procedure Init(Emit:TCustomEmit); inline;
  function  Fetch(p:TsrDataLayout;rtype:TsrDataType):TsrVertLayout;
  Function  First:TsrVertLayout;
  Function  Next(node:TsrVertLayout):TsrVertLayout;
  procedure AllocBinding;
  procedure AllocEntryPoint(EntryPoint:TSpirvOp);
 end;

implementation

function TsrVertLayout._GetStorageName:RawByteString;
begin
 Result:=GetStorageName;
end;

//

class function TsrVertLayout.c(n1,n2:PPsrDataLayout):Integer;
begin
 Result:=ord(n1^.Order>n2^.Order)-ord(n1^.Order<n2^.Order);
end;

procedure TsrVertLayout.Init(p:TsrDataLayout); inline;
begin
 FStorage:=StorageClass.Input;
 FBinding:=-1;
 key     :=p;
end;

function TsrVertLayout.GetStorageName:RawByteString;
begin
 Result:='atParam'+IntToStr(FBinding);
end;

procedure TsrVertLayoutList.Init(Emit:TCustomEmit); inline;
begin
 FEmit:=Emit;
end;

function TsrVertLayoutList.Fetch(p:TsrDataLayout;rtype:TsrDataType):TsrVertLayout;
begin
 Result:=FTree.Find(@p);
 if (Result=nil) then
 begin
  Result:=FEmit.specialize New<TsrVertLayout>;
  Result.Init(p);
  //
  Result.InitType(rtype);
  Result.InitVar();
  //
  FTree.Insert(Result);
  //
  p.FDescList.Push_tail(Result);
 end;
end;

Function TsrVertLayoutList.First:TsrVertLayout;
begin
 Result:=FTree.Min;
end;

Function TsrVertLayoutList.Next(node:TsrVertLayout):TsrVertLayout;
begin
 Result:=FTree.Next(node);
end;

procedure TsrVertLayoutList.AllocBinding;
var
 pDecorateList:TsrDecorateList;
 node:TsrVertLayout;
 pVar:TsrVariable;
 FBinding:Integer;
begin
 pDecorateList:=FEmit.GetDecorateList;
 FBinding:=0;
 node:=First;
 While (node<>nil) do
 begin
  pVar:=node.pVar;
  if (pVar<>nil) and node.IsUsed and (node.FBinding=-1) then
  begin
   pDecorateList.OpDecorate(pVar,Decoration.Location,FBinding);
   node.FBinding:=FBinding;
   Inc(FBinding);
  end;
  node:=Next(node);
 end;
end;

procedure TsrVertLayoutList.AllocEntryPoint(EntryPoint:TSpirvOp);
var
 node:TsrVertLayout;
 pVar:TsrVariable;
begin
 if (EntryPoint=nil) then Exit;
 node:=First;
 While (node<>nil) do
 begin
  pVar:=node.pVar;
  if (pVar<>nil) and node.IsUsed then
  begin
   EntryPoint.AddParam(pVar);
  end;
  node:=Next(node);
 end;
end;

procedure TsrVertLayout.AllocSourceExtension2(var Writer:TseWriter);
begin
 if (pVar<>nil) and IsUsed then
 begin
  //start block
  Writer.Header('+VTX_ATR');
  //
  Writer.IntOpt('BND',FBinding);
 end;
end;

end.


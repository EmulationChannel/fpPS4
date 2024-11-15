unit emit_DS;

{$mode objfpc}{$H+}

interface

uses
  sysutils,
  spirv,
  ps4_pssl,
  bittype,
  srType,
  srTypes,
  srConst,
  srInput,
  srReg,
  srOp,
  srLayout,
  srVariable,
  emit_fetch;

type
 TEmit_DS=class(TEmitFetch)
  procedure emit_DS;
  procedure _emit_DS_SWIZZLE_B32;
  function  fetch_ds_chain   (vbindex:TsrRegNode;rtype,atomic:TsrDataType;offset:Word):TsrChain;
  procedure emit_DS_WRITE    (rtype:TsrDataType);
  procedure emit_DS_WRITE2   (rtype:TsrDataType);
  procedure emit_DS_READ     (rtype:TsrDataType);
  procedure emit_DS_READ2    (rtype:TsrDataType);
  procedure emit_DS_ATOMIC_OP(rtype:TsrDataType;OpId:DWORD;rtn:Boolean);
 end;

implementation

const
 BitMode=0;
 QdMode =1;

type
 tds_pattern=packed record
  Case Byte of
   0:(qd:bitpacked record
       lanes:bit8;
       //lane0:bit2;
       //lane1:bit2;
       //lane2:bit2;
       //lane3:bit2;
       align:bit7;
       mode :bit1;
      end);
   1:(bit:bitpacked record
       mask_and:bit5;
       mask_or :bit5;
       mask_xor:bit5;
       mode    :bit1;
      end);
 end;

procedure TEmit_DS._emit_DS_SWIZZLE_B32; //TODO: DS_SWIZZLE_B32
Var
 dst:PsrRegSlot;
 src:TsrRegNode;
 inv:TsrRegNode;

 ofs:TsrRegNode;
 cm4:TsrRegNode;
 cm3:TsrRegNode;
 cm1:TsrRegNode;
 elm:TsrRegNode;
 tmp:TsrRegNode;
 lof:TsrRegNode;
 lob:TsrRegNode;
 lid:TsrRegNode;

 pat:tds_pattern;
begin
 {

 Word(pat):=PWORD(@FSPI.DS.OFFSET0)^;

 AddCap(Capability.GroupNonUniformShuffle);

 dst:=FRegsStory.get_vdst8(FSPI.DS.VDST);
 src:=fetch_vsrc8(FSPI.DS.ADDR,dtUnknow);

 inv:=AddInput(@FRegsStory.FUnattach,dtUint32,itSubgroupLocalInvocationId);

 Case pat.qd.mode of
  QdMode:
   begin
    ofs:=FetchReg(FConsts.Fetch(dtUint32,pat.qd.lanes));

    cm4:=FetchReg(FConsts.Fetch(dtUint32,4));
    cm3:=FetchReg(FConsts.Fetch(dtUint32,3));
    cm1:=FetchReg(FConsts.Fetch(dtUint32,1));

    inv^.mark_read;
    elm:=NewReg(dtUint32);
    _emit_Op2(line,Op.OpUMod,elm,inv,cm4);

    tmp:=NewReg(dtUint32);
    elm^.mark_read;
    _emit_OpShr(line,tmp,elm,cm1);
    elm:=tmp;

    tmp:=NewReg(dtUint32);
    elm^.mark_read;
    _emit_OpShr(line,tmp,ofs,elm);
    elm:=tmp;

    tmp:=NewReg(dtUint32);
    elm^.mark_read;
    _emit_Op2(line,Op.OpBitwiseAnd,tmp,elm,cm3);
    lof:=tmp; //laneOffset

    lob:=NewReg(dtUint32);
    cm4^.mark_read;
    _emit_Op2(line,Op.OpUDiv,lob,inv,cm4); //laneBase

    lid:=NewReg(dtUint32);
    lob^.mark_read;
    lof^.mark_read;
    _emit_OpIAdd(line,lid,lob,lof); //laneIndex


   end;
  BitMode:
   begin
    Assert(false,'TODO');
   end;
 end;






 dst:=FRegsStory.get_vdst8(FSPI.DS.VDST);
 SetConst(dst,dtFloat32,0);

 }
end;

{
const uint32_t typeId = getScalarTypeId(GcnScalarType::Uint32);

//SubgroupLocalInvocationId

auto invocationId = emitCommonSystemValueLoad(
	GcnSystemValue::SubgroupInvocationID, GcnRegMask::select(0));

uint16_t   offset    = util::concat<uint16_t>(ins.control.ds.offset1, ins.control.ds.offset0);
DsPattern* pat       = reinterpret_cast<DsPattern*>(&offset);
uint32_t   laneIndex = 0;

if (pat->m.mode == QdMode)
{

}
else
{
	uint32_t maskAnd = m_module.constu32(pat->bit.mask_and);
	uint32_t maskOr  = m_module.constu32(pat->bit.mask_or);
	uint32_t maskXor = m_module.constu32(pat->bit.mask_xor);

	// or 0x20 to protect high 32 lanes if subgroup size is greater than 32
	maskAnd = m_module.opBitwiseOr(typeId, m_module.constu32(0x20), maskAnd);

	uint32_t valAnd = m_module.opBitwiseAnd(typeId, invocationId.id, maskAnd);
	uint32_t valOr  = m_module.opBitwiseOr(typeId, valAnd, maskOr);
	laneIndex       = m_module.opBitwiseXor(typeId, valOr, maskXor);
}

uint32_t laneValue = m_module.opGroupNonUniformShuffle(typeId,
							,m_module.constu32(spv::ScopeSubgroup),
							,src.low.id,
							,laneIndex);

// Detect if src lane is active,
// if it's inactive, we need to return 0 for dst.
uint32_t laneMask = m_module.opShiftLeftLogical(typeId, m_module.constu32(1), laneIndex);
auto     exec     = m_state.exec.emitLoad(GcnRegMask::select(0));

uint32_t laneActive = m_module.opINotEqual(m_module.defBoolType(),
										   m_module.opBitwiseAnd(typeId, exec.low.id, laneMask),
										   m_module.constu32(0));

dst.low.id = m_module.opSelect(typeId,
							   laneActive,
							   laneValue,
							   m_module.constu32(0));

emitRegisterStore(ins.dst[0], dst);
}

function TEmit_DS.fetch_ds_chain(vbindex:TsrRegNode;rtype,atomic:TsrDataType;offset:Word):TsrChain;
var
 pLayout:TsrDataLayout;
 lvl_0:TsrChainLvl_0;
 lvl_1:TsrChainLvl_1;
begin
 case FSPI.DS.GDS of
  0:pLayout:=DataLayoutList.FetchLDS(); //base:LDS_BASE  size:min(M0[16:0], LDS_SIZE)
  1:pLayout:=DataLayoutList.FetchGDS(); //base:M0[31:16] size:M0[15:0]
 end;

 lvl_0.size  :=rtype.BitSize div 8;
 lvl_0.offset:=offset;

 //region_addr = (OFFSET + vbindex) & alignment
 if vbindex.is_const then
 begin
  lvl_0.offset:=lvl_0.offset + vbindex.AsConst.GetData;

  lvl_0.offset:=lvl_0.offset and (not (lvl_0.size-1));

  Result:=pLayout.Fetch(@lvl_0,nil,cflags(atomic));
 end else
 if ((lvl_0.offset mod lvl_0.size)=0) then
 begin
  //i = OFFSET + (vbindex / size)

  lvl_1.pIndex:=OpIDivTo(vbindex,lvl_0.size);
  lvl_1.stride:=lvl_0.size;

  //lvl_0.offset:=lvl_0.offset div lvl_0.size;

  Result:=pLayout.Fetch(@lvl_0,@lvl_1,cflags(atomic));
 end else
 begin
  //i = (vbindex + OFFSET) / size

  lvl_1.pIndex:=OpIAddTo(vbindex,lvl_0.offset);
  lvl_1.pIndex:=OpIDivTo(lvl_1.pIndex,lvl_0.size);
  lvl_1.stride:=lvl_0.size;

  lvl_0.offset:=0;

  Result:=pLayout.Fetch(@lvl_0,@lvl_1,cflags(atomic));
 end;
end;

//vbindex, vsrc[] [OFFSET:<0..65535>] [GDS:< 0|1>]
procedure TEmit_DS.emit_DS_WRITE(rtype:TsrDataType);
var
 pChain:TsrChain;

 vbindex:TsrRegNode;
 vsrc:TsrRegNode;
begin
 vbindex:=fetch_vdst8(FSPI.DS.ADDR,dtUint32);

 if (rtype.BitSize=64) then
 begin
  vsrc:=fetch_vdst8_64(FSPI.DS.DATA0,dtUint64);
 end else
 if (rtype.BitSize=32) then
 begin
  vsrc:=fetch_vdst8(FSPI.DS.DATA0,rtype);
 end else
 begin
  vsrc:=fetch_vdst8(FSPI.DS.DATA0,dtUnknow);
 end;

 case rtype of
  dtUint8 :vsrc:=OpUToU(vsrc,dtUint8);
  dtUint16:vsrc:=OpUToU(vsrc,dtUint16);
  else;
 end;

 pChain:=fetch_ds_chain(vbindex,rtype,dtUnknow,WORD(FSPI.DS.OFFSET));

 FetchStore(pChain,vsrc);
end;

//vbindex, vsrc0[], vsrc1[] [OFFSET0:<0..255>] [OFFSET1:<0..255>] [GDS:< 0|1>]
procedure TEmit_DS.emit_DS_WRITE2(rtype:TsrDataType);
var
 pChain:array[0..1] of TsrChain;

 vbindex:TsrRegNode;
 vsrc:array[0..1] of TsrRegNode;
begin
 vbindex:=fetch_vdst8(FSPI.DS.ADDR,dtUint32);

 if (rtype.BitSize=64) then
 begin
  vsrc[0]:=fetch_vdst8_64(FSPI.DS.DATA0,dtUint64);
  vsrc[1]:=fetch_vdst8_64(FSPI.DS.DATA1,dtUint64);
 end else
 begin
  vsrc[0]:=fetch_vdst8(FSPI.DS.DATA0,rtype);
  vsrc[1]:=fetch_vdst8(FSPI.DS.DATA1,rtype);
 end;

 pChain[0]:=fetch_ds_chain(vbindex,rtype,dtUnknow,FSPI.DS.OFFSET[0]*(rtype.BitSize div 8));
 pChain[1]:=fetch_ds_chain(vbindex,rtype,dtUnknow,FSPI.DS.OFFSET[1]*(rtype.BitSize div 8));

 FetchStore(pChain[0],vsrc[0]);
 FetchStore(pChain[1],vsrc[1]);
end;

//vdst[], vbindex [OFFSET:<0..65535>] [GDS:< 0|1>]
procedure TEmit_DS.emit_DS_READ(rtype:TsrDataType);
var
 pChain:TsrChain;

 vbindex:TsrRegNode;
 vdst:TsrRegNode;

 dst:array[0..1] of PsrRegSlot;
begin
 vbindex:=fetch_vdst8(FSPI.DS.ADDR,dtUint32);

 pChain:=fetch_ds_chain(vbindex,rtype,dtUnknow,WORD(FSPI.DS.OFFSET));

 vdst:=FetchLoad(pChain,rtype);

 case rtype of
  dtUint8 :vdst:=OpUToU(vdst,dtUint32);
  dtUint16:vdst:=OpUToU(vdst,dtUint32);
  //
  dtInt8  :vdst:=OpSToS(vdst,dtInt32);
  dtInt16 :vdst:=OpSToS(vdst,dtInt32);
  else;
 end;

 if (rtype.BitSize=64) then
 begin
  dst[0]:=get_vdst8(FSPI.DS.VDST+0);
  dst[1]:=get_vdst8(FSPI.DS.VDST+1);

  MakeCopy64(dst[0],dst[1],vdst);
 end else
 begin
  dst[0]:=get_vdst8(FSPI.DS.VDST);

  MakeCopy(dst[0],vdst);
 end;

end;

procedure TEmit_DS.emit_DS_READ2(rtype:TsrDataType);
var
 pChain:array[0..1] of TsrChain;

 vbindex:TsrRegNode;
 vdst:array[0..1] of TsrRegNode;

 dst:array[0..3] of PsrRegSlot;
begin
 vbindex:=fetch_vdst8(FSPI.DS.ADDR,dtUint32);

 pChain[0]:=fetch_ds_chain(vbindex,rtype,dtUnknow,FSPI.DS.OFFSET[0]*(rtype.BitSize div 8));
 pChain[1]:=fetch_ds_chain(vbindex,rtype,dtUnknow,FSPI.DS.OFFSET[1]*(rtype.BitSize div 8));

 vdst[0]:=FetchLoad(pChain[0],rtype);
 vdst[1]:=FetchLoad(pChain[1],rtype);

 if (rtype.BitSize=64) then
 begin
  dst[0]:=get_vdst8(FSPI.DS.VDST+0);
  dst[1]:=get_vdst8(FSPI.DS.VDST+1);
  dst[2]:=get_vdst8(FSPI.DS.VDST+2);
  dst[3]:=get_vdst8(FSPI.DS.VDST+3);

  MakeCopy64(dst[0],dst[1],vdst[0]);
  MakeCopy64(dst[2],dst[3],vdst[1]);
 end else
 begin
  dst[0]:=get_vdst8(FSPI.DS.VDST+0);
  dst[1]:=get_vdst8(FSPI.DS.VDST+1);

  MakeCopy(dst[0],vdst[0]);
  MakeCopy(dst[1],vdst[1]);
 end;
end;

//vdst, vbindex, vsrc [OFFSET:<0..65535>] [GDS:< 0|1>]
procedure TEmit_DS.emit_DS_ATOMIC_OP(rtype:TsrDataType;OpId:DWORD;rtn:Boolean);
var
 pChain:TsrChain;

 vbindex:TsrRegNode;
 vsrc:TsrRegNode;
 vdst:TsrRegNode;

 dst:array[0..1] of PsrRegSlot;
begin
 vbindex:=fetch_vdst8(FSPI.DS.ADDR,dtUint32);

 if (rtype.BitSize=64) then
 begin
  vsrc:=fetch_vdst8_64(FSPI.DS.DATA0,dtUint64);
 end else
 if (rtype.BitSize=32) then
 begin
  vsrc:=fetch_vdst8(FSPI.DS.DATA0,rtype);
 end else
 begin
  vsrc:=fetch_vdst8(FSPI.DS.DATA0,dtUnknow);
 end;

 case rtype of
  dtUint8 :vsrc:=OpUToU(vsrc,dtUint8);
  dtUint16:vsrc:=OpUToU(vsrc,dtUint16);
  else
 end;

 pChain:=fetch_ds_chain(vbindex,rtype,rtype,WORD(FSPI.DS.OFFSET));

 vdst:=FetchAtomic(pChain,OpId,rtype,vsrc);

 if rtn then
 begin
  //save result
  case rtype of
   dtUint8 :vdst:=OpUToU(vdst,dtUint32);
   dtUint16:vdst:=OpUToU(vdst,dtUint32);
   //
   dtInt8  :vdst:=OpSToS(vdst,dtInt32);
   dtInt16 :vdst:=OpSToS(vdst,dtInt32);
   else;
  end;

  if (rtype.BitSize=64) then
  begin
   dst[0]:=get_vdst8(FSPI.DS.VDST+0);
   dst[1]:=get_vdst8(FSPI.DS.VDST+1);

   MakeCopy64(dst[0],dst[1],vdst);
  end else
  begin
   dst[0]:=get_vdst8(FSPI.DS.VDST);

   MakeCopy(dst[0],vdst);
  end;
 end else
 begin
  //no result
  vdst.mark_read(nil); //self link
 end;

end;

procedure TEmit_DS.emit_DS;
begin

 Case FSPI.DS.OP of

  DS_NOP:;

  DS_WRITE_B8   :emit_DS_WRITE(dtUint8);
  DS_WRITE_B16  :emit_DS_WRITE(dtUint16);
  DS_WRITE_B32  :emit_DS_WRITE(dtUint32);
  DS_WRITE_B64  :emit_DS_WRITE(dtUint64);

  DS_WRITE2_B32 :emit_DS_WRITE2(dtUint32);
  DS_WRITE2_B64 :emit_DS_WRITE2(dtUint64);

  DS_READ_I8    :emit_DS_READ(dtInt8);
  DS_READ_U8    :emit_DS_READ(dtUint8);
  DS_READ_I16   :emit_DS_READ(dtInt16);
  DS_READ_U16   :emit_DS_READ(dtUint16);
  DS_READ_B32   :emit_DS_READ(dtUint32);
  DS_READ_B64   :emit_DS_READ(dtUint64);

  DS_READ2_B32  :emit_DS_READ2(dtUint32);
  DS_READ2_B64  :emit_DS_READ2(dtUint64);

  DS_ADD_U32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicIAdd,False);
  DS_SUB_U32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicISub,False);

  DS_INC_U32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicIIncrement,False);
  DS_DEC_U32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicIDecrement,False);

  DS_MIN_I32    :emit_DS_ATOMIC_OP(dtInt32 ,Op.OpAtomicSMin,False);
  DS_MAX_I32    :emit_DS_ATOMIC_OP(dtInt32 ,Op.OpAtomicSMax,False);

  DS_MIN_U32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicUMin,False);
  DS_MAX_U32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicUMax,False);

  DS_AND_B32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicAnd,False);
  DS_OR_B32     :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicOr ,False);
  DS_XOR_B32    :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicXor,False);

  DS_ADD_RTN_U32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicIAdd,True);
  DS_SUB_RTN_U32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicISub,True);

  DS_INC_RTN_U32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicIIncrement,True);
  DS_DEC_RTN_U32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicIDecrement,True);

  DS_MIN_RTN_I32:emit_DS_ATOMIC_OP(dtInt32 ,Op.OpAtomicSMin,True);
  DS_MAX_RTN_I32:emit_DS_ATOMIC_OP(dtInt32 ,Op.OpAtomicSMax,True);

  DS_MIN_RTN_U32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicUMin,True);
  DS_MAX_RTN_U32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicUMax,True);

  DS_AND_RTN_B32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicAnd,True);
  DS_OR_RTN_B32 :emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicOr ,True);
  DS_XOR_RTN_B32:emit_DS_ATOMIC_OP(dtUint32,Op.OpAtomicXor,True);

  //DS_SWIZZLE_B32 v4 v3 v0 v0 OFFSET:0x80AA GDS:0

  //DS_SWIZZLE_B32: //TODO
  // begin;
  //   _emit_DS_SWIZZLE_B32;
  // end;

  else
   Assert(false,'DS?'+IntToStr(FSPI.DS.OP)+' '+get_str_spi(FSPI));
 end;

end;

{
OFFSET0:Byte;
OFFSET1:Byte;
GDS:bit1;
ADDR:Byte;  (vbindex)
DATA0:Byte; (vsrc0)
DATA1:Byte; (vsrc1)
VDST:Byte;
}

end.



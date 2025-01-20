unit vImage;

{$mode objfpc}{$H+}

interface

uses
 SysUtils,
 Vulkan,
 vDevice,
 vPipeline,
 vMemory,
 vDependence;

const
 VK_FORMAT_R10G11B11_UFLOAT_FAKE32=TVkFormat(ord(VK_FORMAT_B10G11R11_UFLOAT_PACK32)+1000000000);

type
 PvImageBarrier=^TvImageBarrier;
 TvImageBarrier=object
  type
   t_push_cb=function():TVkCommandBuffer of object;
  var
   //image:TVkImage;
   //range:TVkImageSubresourceRange;
   //
   AccessMask:TVkAccessFlags;
   ImgLayout :TVkImageLayout;
   StageMask :TVkPipelineStageFlags;
  Procedure Init({_image:TVkImage;_sub:TVkImageSubresourceRange});
  function  Push(cmd:TVkCommandBuffer;
                 cb:t_push_cb;
                 image:TVkImage;
                 range:TVkImageSubresourceRange;
                 dstAccessMask:TVkAccessFlags;
  	         newImageLayout:TVkImageLayout;
  	         dstStageMask:TVkPipelineStageFlags):Boolean;
 end;

 TvSwapChainImage=class
  FHandle:TVkImage;
  FView  :TVkImage;
  Barrier:TvImageBarrier;
  procedure   PushBarrier(cmd:TVkCommandBuffer;
                          range:TVkImageSubresourceRange;
                          dstAccessMask:TVkAccessFlags;
                          newImageLayout:TVkImageLayout;
                          dstStageMask:TVkPipelineStageFlags);
 end;

 TvSwapChain=class
  FSurface:TvSurface;
  FSize   :TVkExtent2D;
  FHandle :TVkSwapchainKHR;
  FImages :array of TvSwapChainImage;
  Constructor Create(Surface:TvSurface;mode:Integer;imageUsage:TVkImageUsageFlags);
  Destructor  Destroy; override;
 end;

 TvImageView=class(TvRefsObject)
  FHandle:TVkImageView;
  Destructor  Destroy; override;
 end;

 TvCustomImage=class(TvRefsObject)
  FHandle:TVkImage;
  FFormat:TVkFormat; //real used format
  FBind  :TvPointer;
  FBRefs :ptruint;
  FName  :RawByteString;
  function    is_invalid:Boolean;
  procedure   FreeHandle; virtual;
  Destructor  Destroy; override;
  function    GetImageInfo:TVkImageCreateInfo; virtual; abstract;
  function    GetRequirements:TVkMemoryRequirements;
  function    GetDedicatedAllocation:Boolean;
  function    Compile(ext:Pointer):Boolean; virtual;
  function    BindMem(P:TvPointer):TVkResult;
  procedure   UnBindMem(do_free:Boolean);
  procedure   OnReleaseMem(Sender:TObject); virtual;
  procedure   SetObjectName(const name:RawByteString);
  //
  function    _Acquire(Sender:TObject):Boolean;
  procedure   _Release(Sender:TObject);
  function    Acquire(Sender:TObject):Boolean; override;
  procedure   Release(Sender:TObject);         override;
 end;

const
 //usage image
 TM_READ =1;
 TM_WRITE=2;
 TM_CLEAR=4;
 TM_MIXED=8;

type
 t_image_usage=(iu_attachment,iu_depthstenc,iu_sampled,iu_storage,iu_transfer,iu_buffer,iu_htile,iu_cmask);
 s_image_usage=set of t_image_usage;

type
 TvExtent3D=packed record
  width :Word; //(0..16383)
  height:Word; //(0..16383)
  depth :Word; //(0..8192)
 end;

 TvDstSel=bitpacked record
  x,y,z,w:0..15; //(0..6)
 end;

 TvImageMemoryKey=packed object
  start:QWORD;
  __end:QWORD;
 end;

 TvTiling=bitpacked record
  idx:0..31; //0..31 (5)
  alt:0..1;  //1
 end;

 TvImageKeyParams=bitpacked object
  itype      :0..3; //2 TVkImageType 0..2
  cube       :0..1; //1 VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT
  pow2pad    :0..1; //1
  reserved   :0..15; //4
  tiling     :TvTiling;
  samples    :Byte; //TVkSampleCountFlagBits 1..4 (3)
  mipLevels  :Byte; //(0..15) (4)
  width      :Word; //(0..16383)
  height     :Word; //(0..16383)
  depth      :Word; //(0..8192)
  arrayLayers:Word; //(0..16383)
  pitch      :Word; //(0..16383)
  pad_width  :Word;
  pad_height :Word;
  function layerCount:Word;
 end;

 PvImageKey=^TvImageKey;
 TvImageKey=packed object
  Addr   :Pointer;
  Addr2  :Pointer;
  cformat:TVkFormat;
  params :TvImageKeyParams;
 end;

 PvImageViewKey=^TvImageViewKey;
 TvImageViewKey=packed object
  cformat   :TVkFormat;
  vtype     :Byte;      //TVkImageViewType 0..6
  fusage    :Byte;
  dstSel    :TvDstSel;  //word
  base_level:Byte;      //first mip level   (0..15)
  last_level:Byte;      //last  mip level   (0..15)
  base_array:Word;      //first array index (0..16383)
  last_array:Word;      //texture height    (0..16383)
  minLod    :TVkFloat;
  function arrayLayers:Word;
  function baseArrayLayer:Word;
  function layerCount:Word;
 end;

 TvImage=class(TvCustomImage)
  FExtent:TVkExtent3D;
  FUsage :TVkFlags;
  Fflags :TVkImageCreateFlags;
  Barrier:TvImageBarrier;
  Constructor Create(format:TVkFormat;extent:TVkExtent3D;usage:TVkFlags;flags:TVkImageCreateFlags;ext:Pointer=nil);
  function    GetImageInfo:TVkImageCreateInfo;    override;
  function    GetViewInfo:TVkImageViewCreateInfo; virtual; abstract;
  function    NewView:TvImageView;
  function    NewViewF(Format:TVkFormat):TvImageView;
  procedure   PushBarrier(cmd:TVkCommandBuffer;
                          range:TVkImageSubresourceRange;
                          dstAccessMask:TVkAccessFlags;
                          newImageLayout:TVkImageLayout;
                          dstStageMask:TVkPipelineStageFlags);
 end;

 TvHostImage1D=class(TvImage)
  function    GetImageInfo:TVkImageCreateInfo; override;
 end;

 TvHostImage2D=class(TvImage)
  function    GetImageInfo:TVkImageCreateInfo; override;
 end;

 TvDeviceImage1D=class(TvImage)
  function    GetViewInfo:TVkImageViewCreateInfo; override;
  function    GetImageInfo:TVkImageCreateInfo;    override;
 end;

 TvDeviceImage2D=class(TvImage)
  function    GetViewInfo:TVkImageViewCreateInfo; override;
  function    GetImageInfo:TVkImageCreateInfo;    override;
 end;

 TvFramebufferAttachmentShort=packed record
  cformat   :TVkFormat;
  width     :Word;
  height    :Word;
  layerCount:Word;
 end;

 AvFramebufferAttach=array[0..8] of TVkFramebufferAttachmentImageInfo;
 AvFramebufferAShort=array[0..8] of TvFramebufferAttachmentShort;

 AvFramebufferImages=array[0..8] of TvImageView;
 AvImageViews       =array[0..8] of TVkImageView;

 TvFramebuffer=class(TvRefsObject)
  FHandle:TVkFramebuffer;
  function   IsImageless:Boolean; virtual;
  Destructor Destroy; override;
 end;

 PvFramebufferImagelessKey=^TvFramebufferImagelessKey;
 TvFramebufferImagelessKey=packed object
  FRenderPass :TvRenderPass;
  FWidth      :Word;
  FHeight     :Word;
  FLayers     :Word;
  FImagesCount:Word;
  FImages     :AvFramebufferAShort;
  Procedure SetRenderPass(r:TvRenderPass);
  Procedure SetSize(Size:TVkExtent2D);
  Procedure AddImageAt(Key:TvImageKey);
  Procedure Export(var F:AvFramebufferAttach);
 end;

 TvFramebufferImageless=class(TvFramebuffer)
  Key:TvFramebufferImagelessKey;
  function IsImageless:Boolean; override;
  function Compile:Boolean;
 end;

 PvFramebufferBindedKey=^TvFramebufferBindedKey;
 TvFramebufferBindedKey=packed object
  FRenderPass :TvRenderPass;
  FWidth      :Word;
  FHeight     :Word;
  FLayers     :Word;
  FImagesCount:Word;
  FImages     :AvFramebufferImages;
  Procedure SetRenderPass(r:TvRenderPass);
  Procedure SetSize(Size:TVkExtent2D);
  Procedure AddImageView(v:TvImageView);
 end;

 TvFramebufferBinded=class(TvFramebuffer)
  Key:TvFramebufferBindedKey;
  FAcquire:bitpacked array[0..8] of Boolean;
  function   Compile:Boolean;
  Procedure  AcquireImageViews;
  Procedure  ReleaseImageViews;
  Destructor Destroy; override;
 end;

Function GetAspectMaskByFormat(cformat:TVkFormat):DWORD;

Function GetDepthStencilInitLayout(DEPTH_USAGE,STENCIL_USAGE:Byte):TVkImageLayout;
Function GetDepthStencilSendLayout(DEPTH_USAGE,STENCIL_USAGE:Byte):TVkImageLayout;
Function GetDepthStencilAccessAttachMask(DEPTH_USAGE,STENCIL_USAGE:Byte):TVkAccessFlags;
function GetColorSendLayout(IMAGE_USAGE:Byte):TVkImageLayout;
Function GetColorAccessAttachMask(IMAGE_USAGE:Byte):TVkAccessFlags;

Function getFormatSize(cformat:TVkFormat):Byte; //in bytes
function IsTexelFormat(cformat:TVkFormat):Boolean;
function IsDepthOrStencilFormat(cformat:TVkFormat):Boolean;
Function IsDepthAndStencil     (cformat:TVkFormat):Boolean;
function GetDepthOnlyFormat    (cformat:TVkFormat):TVkFormat;
function GetStencilOnlyFormat  (cformat:TVkFormat):TVkFormat;

function GetDepthOnly  (const key:TvImageKey):TvImageKey;
function GetStencilOnly(const key:TvImageKey):TvImageKey;

function vkGetFormatSupport(format:TVkFormat;tiling:TVkImageTiling;usage:TVkImageUsageFlags):Boolean;
function vkFixFormatSupport(format:TVkFormat;tiling:TVkImageTiling;usage:TVkImageUsageFlags):TVkFormat;

function GET_FORMATS_LEN(buf:PVkFormat):Byte;
function GET_VK_IMAGE_MUTABLE(cformat:TVkFormat):PVkFormat;

function GET_VK_FORMAT_STORAGE(cformat:TVkFormat):TVkFormat;

function GET_VK_IMAGE_USAGE_DEFAULT   (cformat:TVkFormat):TVkFlags;
function GET_VK_IMAGE_USAGE_ATTACHMENT(cformat:TVkFormat):TVkFlags;
function GET_VK_IMAGE_CREATE_DEFAULT  (cformat:TVkFormat):TVkFlags;

Function GetNormalizedParams(const key:TvImageKey):TvImageKeyParams;
Function CompareNormalized(const a,b:TvImageKey):Integer;

implementation

uses
 subr_backtrace;

function TvImageKeyParams.layerCount:Word;
begin
 if (TVkImageType(itype)=VK_IMAGE_TYPE_3D) then
 begin
  Result:=1; //3D texture array does not exist?
 end else
 if (cube<>0) then
 begin
  Result:=((arrayLayers+5) div 6)*6; //align up
 end else
 begin
  Result:=arrayLayers;
 end;
end;

//

function TvImageViewKey.arrayLayers:Word;
begin
 Result:=last_array-base_array+1;
end;

function TvImageViewKey.baseArrayLayer:Word;
begin
 case TVkImageViewType(vtype) of
  VK_IMAGE_VIEW_TYPE_3D:
   begin
    Result:=0; //3D texture array does not exist?
   end;
  VK_IMAGE_VIEW_TYPE_CUBE,
  VK_IMAGE_VIEW_TYPE_CUBE_ARRAY:
   begin
    if (arrayLayers mod 6)<>0 then
    begin
     //broken CUBE?
     Result:=0;
    end else
    begin
     Result:=base_array;
    end;
   end;
  else
   begin
    Result:=base_array;
   end;
 end;
end;

function TvImageViewKey.layerCount:Word;
begin
 case TVkImageViewType(vtype) of
  VK_IMAGE_VIEW_TYPE_3D:
   begin
    Result:=1; //3D texture array does not exist?
   end;
  VK_IMAGE_VIEW_TYPE_CUBE,
  VK_IMAGE_VIEW_TYPE_CUBE_ARRAY:
   begin
    Result:=((arrayLayers+5) div 6)*6; //align up
   end;
  else
   begin
    Result:=arrayLayers;
   end;
 end;
end;

Function getFormatSize(cformat:TVkFormat):Byte; //in bytes
begin
 Result:=0;
 Case cformat of
  VK_FORMAT_UNDEFINED                 :Result:=0;

  //pixel size

  VK_FORMAT_R8_UNORM                  ,
  VK_FORMAT_R8_SNORM                  ,
  VK_FORMAT_R8_USCALED                ,
  VK_FORMAT_R8_SSCALED                ,
  VK_FORMAT_R8_UINT                   ,
  VK_FORMAT_R8_SINT                   ,
  VK_FORMAT_R8_SRGB                   :Result:=1;

  VK_FORMAT_A4R4G4B4_UNORM_PACK16_EXT ,
  VK_FORMAT_A4B4G4R4_UNORM_PACK16_EXT ,
  VK_FORMAT_R4G4B4A4_UNORM_PACK16     ,
  VK_FORMAT_B4G4R4A4_UNORM_PACK16     ,
  VK_FORMAT_R5G6B5_UNORM_PACK16       ,
  VK_FORMAT_B5G6R5_UNORM_PACK16       ,

  VK_FORMAT_A1R5G5B5_UNORM_PACK16     ,
  VK_FORMAT_R5G5B5A1_UNORM_PACK16     ,

  VK_FORMAT_R8G8_UNORM                ,
  VK_FORMAT_R8G8_SNORM                ,
  VK_FORMAT_R8G8_USCALED              ,
  VK_FORMAT_R8G8_SSCALED              ,
  VK_FORMAT_R8G8_UINT                 ,
  VK_FORMAT_R8G8_SINT                 ,
  VK_FORMAT_R8G8_SRGB                 ,

  VK_FORMAT_R16_UNORM                 ,
  VK_FORMAT_R16_SNORM                 ,
  VK_FORMAT_R16_USCALED               ,
  VK_FORMAT_R16_SSCALED               ,
  VK_FORMAT_R16_UINT                  ,
  VK_FORMAT_R16_SINT                  ,
  VK_FORMAT_R16_SFLOAT                :Result:=2;

  VK_FORMAT_R8G8B8A8_UNORM            ,
  VK_FORMAT_R8G8B8A8_SNORM            ,
  VK_FORMAT_R8G8B8A8_USCALED          ,
  VK_FORMAT_R8G8B8A8_SSCALED          ,
  VK_FORMAT_R8G8B8A8_UINT             ,
  VK_FORMAT_R8G8B8A8_SINT             ,
  VK_FORMAT_R8G8B8A8_SRGB             ,

  VK_FORMAT_B8G8R8A8_UNORM            ,
  VK_FORMAT_B8G8R8A8_SNORM            ,
  VK_FORMAT_B8G8R8A8_USCALED          ,
  VK_FORMAT_B8G8R8A8_SSCALED          ,
  VK_FORMAT_B8G8R8A8_UINT             ,
  VK_FORMAT_B8G8R8A8_SINT             ,
  VK_FORMAT_B8G8R8A8_SRGB             ,

  VK_FORMAT_A8B8G8R8_UNORM_PACK32     ,
  VK_FORMAT_A8B8G8R8_SNORM_PACK32     ,
  VK_FORMAT_A8B8G8R8_USCALED_PACK32   ,
  VK_FORMAT_A8B8G8R8_SSCALED_PACK32   ,
  VK_FORMAT_A8B8G8R8_UINT_PACK32      ,
  VK_FORMAT_A8B8G8R8_SINT_PACK32      ,
  VK_FORMAT_A8B8G8R8_SRGB_PACK32      ,

  VK_FORMAT_A2R10G10B10_UNORM_PACK32  ,
  VK_FORMAT_A2R10G10B10_SNORM_PACK32  ,
  VK_FORMAT_A2R10G10B10_USCALED_PACK32,
  VK_FORMAT_A2R10G10B10_SSCALED_PACK32,
  VK_FORMAT_A2R10G10B10_UINT_PACK32   ,
  VK_FORMAT_A2R10G10B10_SINT_PACK32   ,
  VK_FORMAT_A2B10G10R10_UNORM_PACK32  ,
  VK_FORMAT_A2B10G10R10_SNORM_PACK32  ,
  VK_FORMAT_A2B10G10R10_USCALED_PACK32,
  VK_FORMAT_A2B10G10R10_SSCALED_PACK32,
  VK_FORMAT_A2B10G10R10_UINT_PACK32   ,
  VK_FORMAT_A2B10G10R10_SINT_PACK32   ,

  VK_FORMAT_R16G16_UNORM              ,
  VK_FORMAT_R16G16_SNORM              ,
  VK_FORMAT_R16G16_USCALED            ,
  VK_FORMAT_R16G16_SSCALED            ,
  VK_FORMAT_R16G16_UINT               ,
  VK_FORMAT_R16G16_SINT               ,
  VK_FORMAT_R16G16_SFLOAT             ,

  VK_FORMAT_R32_UINT                  ,
  VK_FORMAT_R32_SINT                  ,
  VK_FORMAT_R32_SFLOAT                ,

  VK_FORMAT_B10G11R11_UFLOAT_PACK32   ,
  VK_FORMAT_R10G11B11_UFLOAT_FAKE32   ,

  VK_FORMAT_E5B9G9R9_UFLOAT_PACK32    :Result:=4;

  VK_FORMAT_R16G16B16A16_UNORM        ,
  VK_FORMAT_R16G16B16A16_SNORM        ,
  VK_FORMAT_R16G16B16A16_USCALED      ,
  VK_FORMAT_R16G16B16A16_SSCALED      ,
  VK_FORMAT_R16G16B16A16_UINT         ,
  VK_FORMAT_R16G16B16A16_SINT         ,
  VK_FORMAT_R16G16B16A16_SFLOAT       ,

  VK_FORMAT_R32G32_UINT               ,
  VK_FORMAT_R32G32_SINT               ,
  VK_FORMAT_R32G32_SFLOAT             :Result:=8;

  VK_FORMAT_R32G32B32_UINT            ,
  VK_FORMAT_R32G32B32_SINT            ,
  VK_FORMAT_R32G32B32_SFLOAT          :Result:=12;

  VK_FORMAT_R32G32B32A32_UINT         ,
  VK_FORMAT_R32G32B32A32_SINT         ,
  VK_FORMAT_R32G32B32A32_SFLOAT       :Result:=16;

  //stencil
  VK_FORMAT_S8_UINT                   :Result:=1;
  //depth
  VK_FORMAT_D16_UNORM                 :Result:=2;
  VK_FORMAT_X8_D24_UNORM_PACK32       :Result:=4;
  VK_FORMAT_D32_SFLOAT                :Result:=4;
  //depth stencil
  VK_FORMAT_D16_UNORM_S8_UINT         :Result:=3;
  VK_FORMAT_D24_UNORM_S8_UINT         :Result:=4;
  VK_FORMAT_D32_SFLOAT_S8_UINT        :Result:=5;

  //texel size
  VK_FORMAT_BC1_RGB_UNORM_BLOCK..
  VK_FORMAT_BC1_RGBA_SRGB_BLOCK,
  VK_FORMAT_BC4_UNORM_BLOCK..
  VK_FORMAT_BC4_SNORM_BLOCK      :Result:=8;

  VK_FORMAT_BC2_UNORM_BLOCK..
  VK_FORMAT_BC3_SRGB_BLOCK,
  VK_FORMAT_BC5_UNORM_BLOCK..
  VK_FORMAT_BC7_SRGB_BLOCK       :Result:=16;

  else
   Assert(false,'getFormatSize:TODO:'+IntToStr(ord(cformat)));
 end;
end;

function IsTexelFormat(cformat:TVkFormat):Boolean;
begin
 Case cformat of
  VK_FORMAT_BC1_RGB_UNORM_BLOCK..
  VK_FORMAT_BC7_SRGB_BLOCK:
   Result:=True;
  else
   Result:=False;
 end;
end;

function IsDepthOrStencilFormat(cformat:TVkFormat):Boolean;
begin
 Case cformat of
  //stencil
  VK_FORMAT_S8_UINT,
  //depth
  VK_FORMAT_D16_UNORM,
  VK_FORMAT_X8_D24_UNORM_PACK32,
  VK_FORMAT_D32_SFLOAT,
  //depth stencil
  VK_FORMAT_D16_UNORM_S8_UINT,
  VK_FORMAT_D24_UNORM_S8_UINT,
  VK_FORMAT_D32_SFLOAT_S8_UINT:
   Result:=True;
  else
   Result:=False;
 end;
end;

Function IsDepthAndStencil(cformat:TVkFormat):Boolean;
begin
 Case cformat of
  VK_FORMAT_D16_UNORM_S8_UINT,
  VK_FORMAT_D24_UNORM_S8_UINT,
  VK_FORMAT_D32_SFLOAT_S8_UINT:
   Result:=True;
  else
   Result:=False;
 end;
end;

function GetDepthOnlyFormat(cformat:TVkFormat):TVkFormat;
begin
 Case cformat of
  //depth
  VK_FORMAT_D16_UNORM,
  VK_FORMAT_X8_D24_UNORM_PACK32,
  VK_FORMAT_D32_SFLOAT:
   Result:=cformat;
  //depth stencil
  VK_FORMAT_D16_UNORM_S8_UINT :Result:=VK_FORMAT_D16_UNORM;
  VK_FORMAT_D24_UNORM_S8_UINT :Result:=VK_FORMAT_X8_D24_UNORM_PACK32;
  VK_FORMAT_D32_SFLOAT_S8_UINT:Result:=VK_FORMAT_D32_SFLOAT;
  else
   Result:=VK_FORMAT_UNDEFINED;
 end;
end;

function GetStencilOnlyFormat(cformat:TVkFormat):TVkFormat;
begin
 Case cformat of
  //stencil
  VK_FORMAT_S8_UINT,
  //depth stencil
  VK_FORMAT_D16_UNORM_S8_UINT,
  VK_FORMAT_D24_UNORM_S8_UINT,
  VK_FORMAT_D32_SFLOAT_S8_UINT:
   Result:=VK_FORMAT_S8_UINT;
  else
   Result:=VK_FORMAT_UNDEFINED;
 end;
end;

//

function GetDepthOnly(const key:TvImageKey):TvImageKey;
begin
 Result.Addr   :=key.Addr;
 Result.Addr2  :=nil;
 Result.cformat:=GetDepthOnlyFormat(key.cformat);
 Result.params :=key.params;
end;

function GetStencilOnly(const key:TvImageKey):TvImageKey;
begin
 Result.Addr   :=key.Addr2;
 Result.Addr2  :=nil;
 Result.cformat:=GetStencilOnlyFormat(key.cformat);
 Result.params :=key.params;
end;

//

function TvFramebuffer.IsImageless:Boolean;
begin
 Result:=False;
end;

Destructor TvFramebuffer.Destroy;
begin
 if (FHandle<>VK_NULL_HANDLE) then
 begin
  vkDestroyFramebuffer(Device.FHandle,FHandle,nil);
 end;
 inherited;
end;

//

Procedure TvFramebufferBindedKey.SetRenderPass(r:TvRenderPass);
begin
 FRenderPass:=r;
end;

Procedure TvFramebufferBindedKey.SetSize(Size:TVkExtent2D);
begin
 FWidth :=Size.width;
 FHeight:=Size.height;
 FLayers:=1;
end;

Procedure TvFramebufferBindedKey.AddImageView(v:TvImageView);
begin
 Assert(v<>nil,'AddImageView');
 if (FImagesCount>=Length(AvFramebufferImages)) then Exit;
 FImages[FImagesCount]:=v;
 Inc(FImagesCount);
end;

///

const
 MUTABLE_8:array[0..7] of TVkFormat=(
  VK_FORMAT_R8_UNORM,
  VK_FORMAT_R8_SNORM,
  VK_FORMAT_R8_USCALED,
  VK_FORMAT_R8_SSCALED,
  VK_FORMAT_R8_UINT,
  VK_FORMAT_R8_SINT,
  VK_FORMAT_R8_SRGB,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_16:array[0..18] of TVkFormat=(
  //VK_FORMAT_A4R4G4B4_UNORM_PACK16_EXT,  //VK1.3
  //VK_FORMAT_A4B4G4R4_UNORM_PACK16_EXT,  //VK1.3
  VK_FORMAT_R4G4B4A4_UNORM_PACK16,
  VK_FORMAT_B4G4R4A4_UNORM_PACK16,
  VK_FORMAT_R5G6B5_UNORM_PACK16,
  VK_FORMAT_B5G6R5_UNORM_PACK16,
  VK_FORMAT_R8G8_UNORM,
  VK_FORMAT_R8G8_SNORM,
  VK_FORMAT_R8G8_USCALED,
  VK_FORMAT_R8G8_SSCALED,
  VK_FORMAT_R8G8_UINT,
  VK_FORMAT_R8G8_SINT,
  VK_FORMAT_R8G8_SRGB,
  VK_FORMAT_R16_UNORM,
  VK_FORMAT_R16_SNORM,
  VK_FORMAT_R16_USCALED,
  VK_FORMAT_R16_SSCALED,
  VK_FORMAT_R16_UINT,
  VK_FORMAT_R16_SINT,
  VK_FORMAT_R16_SFLOAT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_8888:array[0..44] of TVkFormat=(
  VK_FORMAT_R8G8B8A8_UNORM,
  VK_FORMAT_R8G8B8A8_SNORM,
  VK_FORMAT_R8G8B8A8_USCALED,
  VK_FORMAT_R8G8B8A8_SSCALED,
  VK_FORMAT_R8G8B8A8_UINT,
  VK_FORMAT_R8G8B8A8_SINT,
  VK_FORMAT_R8G8B8A8_SRGB,
  VK_FORMAT_B8G8R8A8_UNORM,
  VK_FORMAT_B8G8R8A8_SNORM,
  VK_FORMAT_B8G8R8A8_USCALED,
  VK_FORMAT_B8G8R8A8_SSCALED,
  VK_FORMAT_B8G8R8A8_UINT,
  VK_FORMAT_B8G8R8A8_SINT,
  VK_FORMAT_B8G8R8A8_SRGB,
  VK_FORMAT_A8B8G8R8_UNORM_PACK32,
  VK_FORMAT_A8B8G8R8_SNORM_PACK32,
  VK_FORMAT_A8B8G8R8_USCALED_PACK32,
  VK_FORMAT_A8B8G8R8_SSCALED_PACK32,
  VK_FORMAT_A8B8G8R8_UINT_PACK32,
  VK_FORMAT_A8B8G8R8_SINT_PACK32,
  VK_FORMAT_A8B8G8R8_SRGB_PACK32,
  VK_FORMAT_A2R10G10B10_UNORM_PACK32,
  VK_FORMAT_A2R10G10B10_SNORM_PACK32,
  VK_FORMAT_A2R10G10B10_USCALED_PACK32,
  VK_FORMAT_A2R10G10B10_SSCALED_PACK32,
  VK_FORMAT_A2R10G10B10_UINT_PACK32,
  VK_FORMAT_A2R10G10B10_SINT_PACK32,
  VK_FORMAT_A2B10G10R10_UNORM_PACK32,
  VK_FORMAT_A2B10G10R10_SNORM_PACK32,
  VK_FORMAT_A2B10G10R10_USCALED_PACK32,
  VK_FORMAT_A2B10G10R10_SSCALED_PACK32,
  VK_FORMAT_A2B10G10R10_UINT_PACK32,
  VK_FORMAT_A2B10G10R10_SINT_PACK32,
  VK_FORMAT_R16G16_UNORM,
  VK_FORMAT_R16G16_SNORM,
  VK_FORMAT_R16G16_USCALED,
  VK_FORMAT_R16G16_SSCALED,
  VK_FORMAT_R16G16_UINT,
  VK_FORMAT_R16G16_SINT,
  VK_FORMAT_R16G16_SFLOAT,
  VK_FORMAT_R32_UINT,
  VK_FORMAT_R32_SINT,
  VK_FORMAT_R32_SFLOAT,
  VK_FORMAT_B10G11R11_UFLOAT_PACK32,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_5999:array[0..1] of TVkFormat=(
  VK_FORMAT_E5B9G9R9_UFLOAT_PACK32,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_3232:array[0..10] of TVkFormat=(
  VK_FORMAT_R16G16B16A16_UNORM,
  VK_FORMAT_R16G16B16A16_SNORM,
  VK_FORMAT_R16G16B16A16_USCALED,
  VK_FORMAT_R16G16B16A16_SSCALED,
  VK_FORMAT_R16G16B16A16_UINT,
  VK_FORMAT_R16G16B16A16_SINT,
  VK_FORMAT_R16G16B16A16_SFLOAT,
  VK_FORMAT_R32G32_UINT,
  VK_FORMAT_R32G32_SINT,
  VK_FORMAT_R32G32_SFLOAT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_323232:array[0..3] of TVkFormat=(
  VK_FORMAT_R32G32B32_UINT,
  VK_FORMAT_R32G32B32_SINT,
  VK_FORMAT_R32G32B32_SFLOAT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_32323232:array[0..3] of TVkFormat=(
  VK_FORMAT_R32G32B32A32_UINT,
  VK_FORMAT_R32G32B32A32_SINT,
  VK_FORMAT_R32G32B32A32_SFLOAT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_D16_UNORM:array[0..1] of TVkFormat=(
  VK_FORMAT_D16_UNORM,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_X8_D24_UNORM:array[0..1] of TVkFormat=(
  VK_FORMAT_X8_D24_UNORM_PACK32,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_D32_SFLOAT:array[0..1] of TVkFormat=(
  VK_FORMAT_D32_SFLOAT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_S8_UINT:array[0..1] of TVkFormat=(
  VK_FORMAT_S8_UINT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_D16_UNORM_S8_UINT:array[0..1] of TVkFormat=(
  VK_FORMAT_D16_UNORM_S8_UINT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_D24_UNORM_S8_UINT:array[0..1] of TVkFormat=(
  VK_FORMAT_D24_UNORM_S8_UINT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_D32_SFLOAT_S8_UINT:array[0..1] of TVkFormat=(
  VK_FORMAT_D32_SFLOAT_S8_UINT,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC1_RGB:array[0..2] of TVkFormat=(
  VK_FORMAT_BC1_RGB_UNORM_BLOCK,
  VK_FORMAT_BC1_RGB_SRGB_BLOCK,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC1_RGBA:array[0..2] of TVkFormat=(
  VK_FORMAT_BC1_RGBA_UNORM_BLOCK,
  VK_FORMAT_BC1_RGBA_SRGB_BLOCK,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC2:array[0..2] of TVkFormat=(
  VK_FORMAT_BC2_UNORM_BLOCK,
  VK_FORMAT_BC2_SRGB_BLOCK,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC3:array[0..2] of TVkFormat=(
  VK_FORMAT_BC3_UNORM_BLOCK,
  VK_FORMAT_BC3_SRGB_BLOCK,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC4:array[0..2] of TVkFormat=(
  VK_FORMAT_BC4_UNORM_BLOCK,
  VK_FORMAT_BC4_SNORM_BLOCK,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC5:array[0..2] of TVkFormat=(
  VK_FORMAT_BC5_UNORM_BLOCK,
  VK_FORMAT_BC5_SNORM_BLOCK,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC6:array[0..2] of TVkFormat=(
  VK_FORMAT_BC6H_UFLOAT_BLOCK,
  VK_FORMAT_BC6H_SFLOAT_BLOCK,
  VK_FORMAT_UNDEFINED
 );

 MUTABLE_BC7:array[0..2] of TVkFormat=(
  VK_FORMAT_BC7_UNORM_BLOCK,
  VK_FORMAT_BC7_SRGB_BLOCK,
  VK_FORMAT_UNDEFINED
 );

function GET_FORMATS_LEN(buf:PVkFormat):Byte;
begin
 Result:=0;
 if (buf=nil) then Exit;
 while (buf[0]<>VK_FORMAT_UNDEFINED) do
 begin
  Inc(Result);
  Inc(buf);
 end;
end;

function GET_VK_IMAGE_MUTABLE(cformat:TVkFormat):PVkFormat;
begin
 Result:=nil;

 case cformat of

  VK_FORMAT_R8_UNORM  :Result:=@MUTABLE_8;
  VK_FORMAT_R8_SNORM  :Result:=@MUTABLE_8;
  VK_FORMAT_R8_USCALED:Result:=@MUTABLE_8;
  VK_FORMAT_R8_SSCALED:Result:=@MUTABLE_8;
  VK_FORMAT_R8_UINT   :Result:=@MUTABLE_8;
  VK_FORMAT_R8_SINT   :Result:=@MUTABLE_8;
  VK_FORMAT_R8_SRGB   :Result:=@MUTABLE_8;

  VK_FORMAT_A4R4G4B4_UNORM_PACK16_EXT:Result:=@MUTABLE_16;
  VK_FORMAT_A4B4G4R4_UNORM_PACK16_EXT:Result:=@MUTABLE_16;
  VK_FORMAT_R4G4B4A4_UNORM_PACK16    :Result:=@MUTABLE_16;
  VK_FORMAT_B4G4R4A4_UNORM_PACK16    :Result:=@MUTABLE_16;
  VK_FORMAT_R5G6B5_UNORM_PACK16      :Result:=@MUTABLE_16;
  VK_FORMAT_B5G6R5_UNORM_PACK16      :Result:=@MUTABLE_16;
  VK_FORMAT_R8G8_UNORM               :Result:=@MUTABLE_16;
  VK_FORMAT_R8G8_SNORM               :Result:=@MUTABLE_16;
  VK_FORMAT_R8G8_USCALED             :Result:=@MUTABLE_16;
  VK_FORMAT_R8G8_SSCALED             :Result:=@MUTABLE_16;
  VK_FORMAT_R8G8_UINT                :Result:=@MUTABLE_16;
  VK_FORMAT_R8G8_SINT                :Result:=@MUTABLE_16;
  VK_FORMAT_R8G8_SRGB                :Result:=@MUTABLE_16;
  VK_FORMAT_R16_UNORM                :Result:=@MUTABLE_16;
  VK_FORMAT_R16_SNORM                :Result:=@MUTABLE_16;
  VK_FORMAT_R16_USCALED              :Result:=@MUTABLE_16;
  VK_FORMAT_R16_SSCALED              :Result:=@MUTABLE_16;
  VK_FORMAT_R16_UINT                 :Result:=@MUTABLE_16;
  VK_FORMAT_R16_SINT                 :Result:=@MUTABLE_16;
  VK_FORMAT_R16_SFLOAT               :Result:=@MUTABLE_16;

  VK_FORMAT_R8G8B8A8_UNORM            :Result:=@MUTABLE_8888;
  VK_FORMAT_R8G8B8A8_SNORM            :Result:=@MUTABLE_8888;
  VK_FORMAT_R8G8B8A8_USCALED          :Result:=@MUTABLE_8888;
  VK_FORMAT_R8G8B8A8_SSCALED          :Result:=@MUTABLE_8888;
  VK_FORMAT_R8G8B8A8_UINT             :Result:=@MUTABLE_8888;
  VK_FORMAT_R8G8B8A8_SINT             :Result:=@MUTABLE_8888;
  VK_FORMAT_R8G8B8A8_SRGB             :Result:=@MUTABLE_8888;
  VK_FORMAT_B8G8R8A8_UNORM            :Result:=@MUTABLE_8888;
  VK_FORMAT_B8G8R8A8_SNORM            :Result:=@MUTABLE_8888;
  VK_FORMAT_B8G8R8A8_USCALED          :Result:=@MUTABLE_8888;
  VK_FORMAT_B8G8R8A8_SSCALED          :Result:=@MUTABLE_8888;
  VK_FORMAT_B8G8R8A8_UINT             :Result:=@MUTABLE_8888;
  VK_FORMAT_B8G8R8A8_SINT             :Result:=@MUTABLE_8888;
  VK_FORMAT_B8G8R8A8_SRGB             :Result:=@MUTABLE_8888;
  VK_FORMAT_A8B8G8R8_UNORM_PACK32     :Result:=@MUTABLE_8888;
  VK_FORMAT_A8B8G8R8_SNORM_PACK32     :Result:=@MUTABLE_8888;
  VK_FORMAT_A8B8G8R8_USCALED_PACK32   :Result:=@MUTABLE_8888;
  VK_FORMAT_A8B8G8R8_SSCALED_PACK32   :Result:=@MUTABLE_8888;
  VK_FORMAT_A8B8G8R8_UINT_PACK32      :Result:=@MUTABLE_8888;
  VK_FORMAT_A8B8G8R8_SINT_PACK32      :Result:=@MUTABLE_8888;
  VK_FORMAT_A8B8G8R8_SRGB_PACK32      :Result:=@MUTABLE_8888;
  VK_FORMAT_A2R10G10B10_UNORM_PACK32  :Result:=@MUTABLE_8888;
  VK_FORMAT_A2R10G10B10_SNORM_PACK32  :Result:=@MUTABLE_8888;
  VK_FORMAT_A2R10G10B10_USCALED_PACK32:Result:=@MUTABLE_8888;
  VK_FORMAT_A2R10G10B10_SSCALED_PACK32:Result:=@MUTABLE_8888;
  VK_FORMAT_A2R10G10B10_UINT_PACK32   :Result:=@MUTABLE_8888;
  VK_FORMAT_A2R10G10B10_SINT_PACK32   :Result:=@MUTABLE_8888;
  VK_FORMAT_A2B10G10R10_UNORM_PACK32  :Result:=@MUTABLE_8888;
  VK_FORMAT_A2B10G10R10_SNORM_PACK32  :Result:=@MUTABLE_8888;
  VK_FORMAT_A2B10G10R10_USCALED_PACK32:Result:=@MUTABLE_8888;
  VK_FORMAT_A2B10G10R10_SSCALED_PACK32:Result:=@MUTABLE_8888;
  VK_FORMAT_A2B10G10R10_UINT_PACK32   :Result:=@MUTABLE_8888;
  VK_FORMAT_A2B10G10R10_SINT_PACK32   :Result:=@MUTABLE_8888;
  VK_FORMAT_R16G16_UNORM              :Result:=@MUTABLE_8888;
  VK_FORMAT_R16G16_SNORM              :Result:=@MUTABLE_8888;
  VK_FORMAT_R16G16_USCALED            :Result:=@MUTABLE_8888;
  VK_FORMAT_R16G16_SSCALED            :Result:=@MUTABLE_8888;
  VK_FORMAT_R16G16_UINT               :Result:=@MUTABLE_8888;
  VK_FORMAT_R16G16_SINT               :Result:=@MUTABLE_8888;
  VK_FORMAT_R16G16_SFLOAT             :Result:=@MUTABLE_8888;
  VK_FORMAT_R32_UINT                  :Result:=@MUTABLE_8888;
  VK_FORMAT_R32_SINT                  :Result:=@MUTABLE_8888;
  VK_FORMAT_R32_SFLOAT                :Result:=@MUTABLE_8888;
  VK_FORMAT_B10G11R11_UFLOAT_PACK32   :Result:=@MUTABLE_8888;
  VK_FORMAT_R10G11B11_UFLOAT_FAKE32   :Result:=@MUTABLE_8888;

  VK_FORMAT_E5B9G9R9_UFLOAT_PACK32    :Result:=@MUTABLE_5999;

  VK_FORMAT_R16G16B16A16_UNORM  :Result:=@MUTABLE_3232;
  VK_FORMAT_R16G16B16A16_SNORM  :Result:=@MUTABLE_3232;
  VK_FORMAT_R16G16B16A16_USCALED:Result:=@MUTABLE_3232;
  VK_FORMAT_R16G16B16A16_SSCALED:Result:=@MUTABLE_3232;
  VK_FORMAT_R16G16B16A16_UINT   :Result:=@MUTABLE_3232;
  VK_FORMAT_R16G16B16A16_SINT   :Result:=@MUTABLE_3232;
  VK_FORMAT_R16G16B16A16_SFLOAT :Result:=@MUTABLE_3232;
  VK_FORMAT_R32G32_UINT         :Result:=@MUTABLE_3232;
  VK_FORMAT_R32G32_SINT         :Result:=@MUTABLE_3232;
  VK_FORMAT_R32G32_SFLOAT       :Result:=@MUTABLE_3232;

  VK_FORMAT_R32G32B32_UINT      :Result:=@MUTABLE_323232;
  VK_FORMAT_R32G32B32_SINT      :Result:=@MUTABLE_323232;
  VK_FORMAT_R32G32B32_SFLOAT    :Result:=@MUTABLE_323232;

  VK_FORMAT_R32G32B32A32_UINT   :Result:=@MUTABLE_32323232;
  VK_FORMAT_R32G32B32A32_SINT   :Result:=@MUTABLE_32323232;
  VK_FORMAT_R32G32B32A32_SFLOAT :Result:=@MUTABLE_32323232;

  VK_FORMAT_D16_UNORM:Result:=@MUTABLE_D16_UNORM;

  VK_FORMAT_X8_D24_UNORM_PACK32:Result:=@MUTABLE_X8_D24_UNORM;

  VK_FORMAT_D32_SFLOAT:Result:=@MUTABLE_D32_SFLOAT;

  VK_FORMAT_S8_UINT:Result:=@MUTABLE_S8_UINT;

  VK_FORMAT_D16_UNORM_S8_UINT:Result:=@MUTABLE_D16_UNORM_S8_UINT;

  VK_FORMAT_D24_UNORM_S8_UINT:Result:=@MUTABLE_D24_UNORM_S8_UINT;

  VK_FORMAT_D32_SFLOAT_S8_UINT:Result:=@MUTABLE_D32_SFLOAT_S8_UINT;

  VK_FORMAT_BC1_RGB_UNORM_BLOCK:Result:=@MUTABLE_BC1_RGB;
  VK_FORMAT_BC1_RGB_SRGB_BLOCK :Result:=@MUTABLE_BC1_RGB;

  VK_FORMAT_BC1_RGBA_UNORM_BLOCK:Result:=@MUTABLE_BC1_RGBA;
  VK_FORMAT_BC1_RGBA_SRGB_BLOCK :Result:=@MUTABLE_BC1_RGBA;

  VK_FORMAT_BC2_UNORM_BLOCK:Result:=@MUTABLE_BC2;
  VK_FORMAT_BC2_SRGB_BLOCK :Result:=@MUTABLE_BC2;

  VK_FORMAT_BC3_UNORM_BLOCK:Result:=@MUTABLE_BC3;
  VK_FORMAT_BC3_SRGB_BLOCK :Result:=@MUTABLE_BC3;

  VK_FORMAT_BC4_UNORM_BLOCK:Result:=@MUTABLE_BC4;
  VK_FORMAT_BC4_SNORM_BLOCK:Result:=@MUTABLE_BC4;

  VK_FORMAT_BC5_UNORM_BLOCK:Result:=@MUTABLE_BC5;
  VK_FORMAT_BC5_SNORM_BLOCK:Result:=@MUTABLE_BC5;

  VK_FORMAT_BC6H_UFLOAT_BLOCK:Result:=@MUTABLE_BC6;
  VK_FORMAT_BC6H_SFLOAT_BLOCK:Result:=@MUTABLE_BC6;

  VK_FORMAT_BC7_UNORM_BLOCK:Result:=@MUTABLE_BC7;
  VK_FORMAT_BC7_SRGB_BLOCK :Result:=@MUTABLE_BC7;

  else;
 end;

end;

function GET_VK_FORMAT_STORAGE(cformat:TVkFormat):TVkFormat;
begin
 Result:=cformat;

 case cformat of

  VK_FORMAT_R8_SNORM,
  VK_FORMAT_R8_USCALED,
  VK_FORMAT_R8_SSCALED,
  VK_FORMAT_R8_SINT:Result:=VK_FORMAT_R8_UINT;

  VK_FORMAT_R8_SRGB:Result:=VK_FORMAT_R8_UNORM;

  VK_FORMAT_A4R4G4B4_UNORM_PACK16_EXT,
  VK_FORMAT_A4B4G4R4_UNORM_PACK16_EXT,
  VK_FORMAT_R4G4B4A4_UNORM_PACK16,
  VK_FORMAT_B4G4R4A4_UNORM_PACK16,
  VK_FORMAT_R5G6B5_UNORM_PACK16,
  VK_FORMAT_B5G6R5_UNORM_PACK16,
  VK_FORMAT_R8G8_SNORM,
  VK_FORMAT_R8G8_USCALED,
  VK_FORMAT_R8G8_SSCALED,
  VK_FORMAT_R8G8_SINT:Result:=VK_FORMAT_R8G8_UINT;

  VK_FORMAT_R8G8_SRGB:Result:=VK_FORMAT_R8G8_UNORM;

  VK_FORMAT_R16_SNORM,
  VK_FORMAT_R16_USCALED,
  VK_FORMAT_R16_SSCALED,
  VK_FORMAT_R16_SINT,
  VK_FORMAT_R16_SFLOAT:Result:=VK_FORMAT_R16_UINT;

  VK_FORMAT_R8G8B8A8_SNORM,
  VK_FORMAT_R8G8B8A8_USCALED,
  VK_FORMAT_R8G8B8A8_SSCALED,
  VK_FORMAT_R8G8B8A8_SINT:Result:=VK_FORMAT_R8G8B8A8_UINT;

  VK_FORMAT_R8G8B8A8_SRGB:Result:=VK_FORMAT_R8G8B8A8_UNORM;

  VK_FORMAT_B8G8R8A8_SNORM,
  VK_FORMAT_B8G8R8A8_USCALED,
  VK_FORMAT_B8G8R8A8_SSCALED,
  VK_FORMAT_B8G8R8A8_UINT,
  VK_FORMAT_B8G8R8A8_SINT:Result:=VK_FORMAT_R8G8B8A8_UINT;

  VK_FORMAT_B8G8R8A8_SRGB:Result:=VK_FORMAT_B8G8R8A8_UNORM;

  VK_FORMAT_A8B8G8R8_SNORM_PACK32,
  VK_FORMAT_A8B8G8R8_USCALED_PACK32,
  VK_FORMAT_A8B8G8R8_SSCALED_PACK32,
  VK_FORMAT_A8B8G8R8_SINT_PACK32:Result:=VK_FORMAT_A8B8G8R8_UINT_PACK32;

  VK_FORMAT_A8B8G8R8_SRGB_PACK32:Result:=VK_FORMAT_A8B8G8R8_UNORM_PACK32;

  VK_FORMAT_A2R10G10B10_SNORM_PACK32,
  VK_FORMAT_A2R10G10B10_USCALED_PACK32,
  VK_FORMAT_A2R10G10B10_SSCALED_PACK32,
  VK_FORMAT_A2R10G10B10_UINT_PACK32,
  VK_FORMAT_A2R10G10B10_SINT_PACK32:Result:=VK_FORMAT_A2R10G10B10_UNORM_PACK32;

  VK_FORMAT_A2B10G10R10_SNORM_PACK32,
  VK_FORMAT_A2B10G10R10_USCALED_PACK32,
  VK_FORMAT_A2B10G10R10_SSCALED_PACK32,
  VK_FORMAT_A2B10G10R10_UINT_PACK32,
  VK_FORMAT_A2B10G10R10_SINT_PACK32:Result:=VK_FORMAT_A2B10G10R10_UNORM_PACK32;

  VK_FORMAT_R16G16_SNORM,
  VK_FORMAT_R16G16_USCALED,
  VK_FORMAT_R16G16_SSCALED,
  VK_FORMAT_R16G16_UINT,
  VK_FORMAT_R16G16_SINT,
  VK_FORMAT_R16G16_SFLOAT:Result:=VK_FORMAT_R16G16_UNORM;

  VK_FORMAT_R32_SINT,
  VK_FORMAT_R32_SFLOAT,
  VK_FORMAT_B10G11R11_UFLOAT_PACK32:Result:=VK_FORMAT_R32_UINT;

  VK_FORMAT_R10G11B11_UFLOAT_FAKE32:Result:=VK_FORMAT_R32_UINT;

  VK_FORMAT_E5B9G9R9_UFLOAT_PACK32:Result:=VK_FORMAT_R32_UINT;

  VK_FORMAT_R16G16B16A16_SNORM,
  VK_FORMAT_R16G16B16A16_USCALED,
  VK_FORMAT_R16G16B16A16_SSCALED,
  VK_FORMAT_R16G16B16A16_SINT,
  VK_FORMAT_R16G16B16A16_SFLOAT:Result:=VK_FORMAT_R16G16B16A16_UINT;

  VK_FORMAT_R32G32_SINT,
  VK_FORMAT_R32G32_SFLOAT:Result:=VK_FORMAT_R32G32_UINT;

  VK_FORMAT_R32G32B32_SINT,
  VK_FORMAT_R32G32B32_SFLOAT:Result:=VK_FORMAT_R32G32B32_UINT;

  VK_FORMAT_R32G32B32A32_SINT,
  VK_FORMAT_R32G32B32A32_SFLOAT:Result:=VK_FORMAT_R32G32B32A32_UINT;

  VK_FORMAT_BC1_RGB_UNORM_BLOCK..
  VK_FORMAT_BC1_RGBA_SRGB_BLOCK,
  VK_FORMAT_BC4_UNORM_BLOCK..
  VK_FORMAT_BC4_SNORM_BLOCK:Result:=VK_FORMAT_R32G32_UINT;

  VK_FORMAT_BC2_UNORM_BLOCK..
  VK_FORMAT_BC3_SRGB_BLOCK,
  VK_FORMAT_BC5_UNORM_BLOCK..
  VK_FORMAT_BC7_SRGB_BLOCK:Result:=VK_FORMAT_R32G32B32A32_UINT;

  else;
 end;
end;

const
 VK_IMAGE_USAGE_=
   ord(VK_IMAGE_USAGE_TRANSFER_SRC_BIT) or
   ord(VK_IMAGE_USAGE_TRANSFER_DST_BIT) or
   ord(VK_IMAGE_USAGE_SAMPLED_BIT);

 VK_IMAGE_USAGE_DEFAULT=
   VK_IMAGE_USAGE_ or
   ord(VK_IMAGE_USAGE_STORAGE_BIT);

 VK_IMAGE_USAGE_DEFAULT_COLOR=
   VK_IMAGE_USAGE_ or
   ord(VK_IMAGE_USAGE_STORAGE_BIT) or
   ord(VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT);

 VK_IMAGE_USAGE_DEFAULT_DEPTH=
   VK_IMAGE_USAGE_ or
   ord(VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT);

function GET_VK_IMAGE_USAGE_DEFAULT(cformat:TVkFormat):TVkFlags;
begin
 Case cformat of
  VK_FORMAT_R4G4_UNORM_PACK8..
  VK_FORMAT_A1R5G5B5_UNORM_PACK16,

  VK_FORMAT_A8B8G8R8_UNORM_PACK32..
  VK_FORMAT_A2B10G10R10_SINT_PACK32,

  VK_FORMAT_R10G11B11_UFLOAT_FAKE32,

  VK_FORMAT_B10G11R11_UFLOAT_PACK32..
  VK_FORMAT_E5B9G9R9_UFLOAT_PACK32:
   Result:=VK_IMAGE_USAGE_DEFAULT;

  VK_FORMAT_D16_UNORM..
  VK_FORMAT_D32_SFLOAT_S8_UINT:
   Result:=VK_IMAGE_USAGE_DEFAULT_DEPTH;

  VK_FORMAT_BC1_RGB_UNORM_BLOCK..
  VK_FORMAT_BC7_SRGB_BLOCK:
   Result:=VK_IMAGE_USAGE_DEFAULT;

  else
   Result:=VK_IMAGE_USAGE_DEFAULT_COLOR;
 end;
end;

function GET_VK_IMAGE_USAGE_ATTACHMENT(cformat:TVkFormat):TVkFlags;
begin
 Case cformat of
  VK_FORMAT_R4G4_UNORM_PACK8..
  VK_FORMAT_A1R5G5B5_UNORM_PACK16,

  VK_FORMAT_A8B8G8R8_UNORM_PACK32..
  VK_FORMAT_A2B10G10R10_SINT_PACK32,

  VK_FORMAT_R10G11B11_UFLOAT_FAKE32,

  VK_FORMAT_B10G11R11_UFLOAT_PACK32..
  VK_FORMAT_E5B9G9R9_UFLOAT_PACK32:
   Result:=ord(VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT);

  VK_FORMAT_D16_UNORM..
  VK_FORMAT_D32_SFLOAT_S8_UINT:
   Result:=ord(VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT);

  VK_FORMAT_BC1_RGB_UNORM_BLOCK..
  VK_FORMAT_BC7_SRGB_BLOCK:
   Result:=0; //prohibited

  else
   Result:=ord(VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT);
 end;
end;

function GET_VK_IMAGE_CREATE_DEFAULT(cformat:TVkFormat):TVkFlags;
begin
 Case cformat of
  VK_FORMAT_BC1_RGB_UNORM_BLOCK..
  VK_FORMAT_BC7_SRGB_BLOCK:
   Result:=ord(VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT) or
           ord(VK_IMAGE_CREATE_EXTENDED_USAGE_BIT) or
           ord(VK_IMAGE_CREATE_BLOCK_TEXEL_VIEW_COMPATIBLE_BIT);

  else
   Result:=ord(VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT) or
           ord(VK_IMAGE_CREATE_EXTENDED_USAGE_BIT);
 end;
end;

procedure FixToNormalizedTiling(var tiling:TvTiling); inline;
begin
 case tiling.idx of
  9,13,27:tiling.idx:=5;
    14,28:tiling.idx:=10;
    16,29:tiling.idx:=11;
    17,30:tiling.idx:=12;
  else;
 end;
end;

Function GetNormalizedParams(const key:TvImageKey):TvImageKeyParams;
begin
 Result:=key.params;

 if IsTexelFormat(key.cformat) then
 begin
  Result.width :=(Result.width +3) shr 2;
  Result.height:=(Result.height+3) shr 2;
 end;

 FixToNormalizedTiling(Result.tiling);

 Result.pitch     :=0;
 Result.pad_width :=0;
 Result.pad_height:=0;
end;

Function CompareNormalized(const a,b:TvImageKey):Integer;
begin
 //1 Addr
 Result:=Integer(a.Addr>b.Addr)-Integer(a.Addr<b.Addr);
 if (Result<>0) then Exit;
 //1 Stencil
 Result:=Integer(a.Addr2>b.Addr2)-Integer(a.Addr2<b.Addr2);
 if (Result<>0) then Exit;
 //2 cformat
 Result:=getFormatSize(a.cformat)-getFormatSize(b.cformat);
 if (Result<>0) then Exit;
 //3 params
 Result:=CompareByte(GetNormalizedParams(a),GetNormalizedParams(b),SizeOf(TvImageKeyParams));
end;

//

Procedure TvFramebufferImagelessKey.SetRenderPass(r:TvRenderPass);
begin
 FRenderPass:=r;
end;

Procedure TvFramebufferImagelessKey.SetSize(Size:TVkExtent2D);
begin
 FWidth :=Size.width;
 FHeight:=Size.height;
 FLayers:=1;
end;

Procedure TvFramebufferImagelessKey.AddImageAt(Key:TvImageKey);
begin
 if (FImagesCount>=Length(FImages)) then Exit;

 if (Key.params.width>FWidth) then
 begin
  FWidth:=Key.params.width;
 end;

 if (Key.params.height>FHeight) then
 begin
  FHeight:=Key.params.height;
 end;

 if (Key.params.layerCount>FLayers) then
 begin
  FLayers:=Key.params.layerCount;
 end;

 with FImages[FImagesCount] do
 begin
  cformat   :=Key.cformat;
  width     :=Key.params.width;
  height    :=Key.params.height;
  layerCount:=key.params.layerCount;
 end;

 Inc(FImagesCount);
end;

Procedure TvFramebufferImagelessKey.Export(var F:AvFramebufferAttach);
var
 cformat:TVkFormat;
 MUTABLE:PVkFormat;
 i:Word;
begin

 if (FImagesCount<>0) then
 For i:=0 to FImagesCount-1 do
 begin
  cformat:=FImages[i].cformat;
  MUTABLE:=GET_VK_IMAGE_MUTABLE(cformat);

  with F[i] do
  begin
   sType          :=VK_STRUCTURE_TYPE_FRAMEBUFFER_ATTACHMENT_IMAGE_INFO;
   pNext          :=nil;
   flags          :=GET_VK_IMAGE_CREATE_DEFAULT  (cformat);
   usage          :=GET_VK_IMAGE_USAGE_ATTACHMENT(cformat);
   width          :=FImages[i].width;
   height         :=FImages[i].height;
   layerCount     :=FImages[i].layerCount;
   viewFormatCount:=GET_FORMATS_LEN(MUTABLE);
   pViewFormats   :=MUTABLE;
  end;
 end;

end;

///

function TvFramebufferImageless.IsImageless:Boolean;
begin
 Result:=True;
end;

function TvFramebufferImageless.Compile:Boolean;
var
 r:TVkResult;
 info:TVkFramebufferCreateInfo;
 imgs:TVkFramebufferAttachmentsCreateInfo;
 fatt:AvFramebufferAttach;
begin
 Result:=False;
 if (FHandle<>VK_NULL_HANDLE) then Exit(True);

 if (Key.FRenderPass=nil) then Exit;
 if (Key.FRenderPass.FHandle=VK_NULL_HANDLE) then Exit;
 if (Key.FImagesCount=0) then Exit;
 if (Key.FWidth=0) or (Key.FHeight=0) then Exit;

 info:=Default(TVkFramebufferCreateInfo);
 info.sType          :=VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
 info.renderPass     :=Key.FRenderPass.FHandle;
 info.attachmentCount:=Key.FImagesCount;
 info.width          :=Key.FWidth;
 info.height         :=Key.FHeight;
 info.layers         :=Key.FLayers;
 info.flags          :=ord(VK_FRAMEBUFFER_CREATE_IMAGELESS_BIT);
 info.pAttachments   :=nil;

 Key.Export(fatt);

 imgs:=Default(TVkFramebufferAttachmentsCreateInfo);
 imgs.sType:=VK_STRUCTURE_TYPE_FRAMEBUFFER_ATTACHMENTS_CREATE_INFO;
 imgs.attachmentImageInfoCount:=Key.FImagesCount;
 imgs.pAttachmentImageInfos   :=@fatt;

 info.pNext:=@imgs;

 r:=vkCreateFramebuffer(Device.FHandle,@info,nil,@FHandle);
 if (r<>VK_SUCCESS) then
 begin
  Writeln(StdErr,'vkCreateFramebuffer');
 end;

 Result:=(r=VK_SUCCESS);
end;

///

Procedure TvFramebufferBinded.AcquireImageViews;
var
 i:Word;
begin
 if (Key.FImagesCount<>0) then
 For i:=0 to Key.FImagesCount-1 do
 if (Key.FImages[i]<>nil) then
 if (not FAcquire[i]) then
 begin
  Key.FImages[i].Acquire(Self);
  FAcquire[i]:=True;
 end;
end;

Procedure TvFramebufferBinded.ReleaseImageViews;
var
 i:Word;
begin
 if (Key.FImagesCount<>0) then
 For i:=0 to Key.FImagesCount-1 do
 if (Key.FImages[i]<>nil) then
 if (FAcquire[i]) then
 begin
  Key.FImages[i].Release(Self);
  FAcquire[i]:=False;
 end;
end;

function TvFramebufferBinded.Compile:Boolean;
var
 i:TVkUInt32;
 r:TVkResult;
 info:TVkFramebufferCreateInfo;
 FImageViews:AvImageViews;
begin
 Result:=False;
 if (FHandle<>VK_NULL_HANDLE) then Exit(True);

 if (Key.FRenderPass=nil) then Exit;
 if (Key.FRenderPass.FHandle=VK_NULL_HANDLE) then Exit;
 if (Key.FImagesCount=0) then Exit;
 if (Key.FWidth=0) or (Key.FHeight=0) then Exit;

 AcquireImageViews;

 info:=Default(TVkFramebufferCreateInfo);
 info.sType          :=VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
 info.renderPass     :=Key.FRenderPass.FHandle;
 info.attachmentCount:=Key.FImagesCount;
 info.width          :=Key.FWidth;
 info.height         :=Key.FHeight;
 info.layers         :=Key.FLayers;

 For i:=0 to Key.FImagesCount-1 do
 begin
  if (Key.FImages[i]<>nil) then
  begin
   FImageViews[i]:=Key.FImages[i].FHandle;
  end;
 end;

 info.pAttachments:=@FImageViews;

 r:=vkCreateFramebuffer(Device.FHandle,@info,nil,@FHandle);
 if (r<>VK_SUCCESS) then
 begin
  Writeln(StdErr,'vkCreateFramebuffer');
 end;

 Result:=(r=VK_SUCCESS);
end;

Destructor TvFramebufferBinded.Destroy;
begin
 ReleaseImageViews;
 inherited;
end;

Constructor TvSwapChain.Create(Surface:TvSurface;mode:Integer;imageUsage:TVkImageUsageFlags);
var
 queueFamilyIndices:array[0..1] of TVkUInt32;
 cinfo:TVkSwapchainCreateInfoKHR;
 r:TVkResult;
 i,count:TVkUInt32;
 cimg:TVkImageViewCreateInfo;
 FImage:array of TVkImage;
 FView:TVkImageView;
begin
 FSurface:=Surface;

 Case mode of
  1,2,3:;
  else
       mode:=1;
 end;

 FSize:=Surface.GetSize;
 if (FSize.width=0) or (FSize.height=0) then Exit;

 cinfo:=Default(TVkSwapchainCreateInfoKHR);
 cinfo.sType           :=VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
 cinfo.surface         :=FSurface.FHandle;
 cinfo.minImageCount   :=2;
 cinfo.imageFormat     :=FSurface.Fformat.format;
 cinfo.imageColorSpace :=FSurface.Fformat.colorSpace;
 cinfo.imageExtent     :=FSize;
 cinfo.imageArrayLayers:=1;
 cinfo.imageUsage      :=imageUsage or ord(VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT);

 if (VulkanApp.FGFamily<>Surface.FPFamily) then
 begin
  queueFamilyIndices[0]:=VulkanApp.FGFamily;
  queueFamilyIndices[1]:=Surface.FPFamily;
  cinfo.imageSharingMode      :=VK_SHARING_MODE_CONCURRENT;
  cinfo.queueFamilyIndexCount :=2;
  cinfo.pQueueFamilyIndices   :=@queueFamilyIndices;
 end else
 begin
  cinfo.imageSharingMode      :=VK_SHARING_MODE_EXCLUSIVE;
  cinfo.queueFamilyIndexCount :=0;
  cinfo.pQueueFamilyIndices   :=nil;
 end;

 cinfo.preTransform  :=VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
 cinfo.compositeAlpha:=VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
 cinfo.presentMode   :=Surface.FModes[mode-1];
 cinfo.clipped       :=VK_TRUE;
 cinfo.oldSwapchain  :=VK_NULL_HANDLE;

 r:=vkCreateSwapchainKHR(Device.FHandle,@cinfo,nil,@FHandle);
 if (r<>VK_SUCCESS) then
 begin
  Writeln(StdErr,'vkCreateSwapchainKHR:',r);
  Exit;
 end;

 count:=1;
 Case mode of
  1,2:count:=2;
    3:count:=3;
 end;

 SetLength(FImage,count);
 SetLength(FImages,count);

 r:=vkGetSwapchainImagesKHR(Device.FHandle,FHandle,@count,@FImage[0]);
 if (r<>VK_SUCCESS) then
 begin
  Writeln(StdErr,'vkGetSwapchainImagesKHR:',r);
  Exit;
 end;

 cimg:=Default(TVkImageViewCreateInfo);
 cimg.sType       :=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
 cimg.viewType    :=VK_IMAGE_VIEW_TYPE_2D;
 cimg.format      :=Surface.Fformat.format;
 cimg.components.r:=VK_COMPONENT_SWIZZLE_IDENTITY;
 cimg.components.g:=VK_COMPONENT_SWIZZLE_IDENTITY;
 cimg.components.b:=VK_COMPONENT_SWIZZLE_IDENTITY;
 cimg.components.a:=VK_COMPONENT_SWIZZLE_IDENTITY;
 cimg.subresourceRange.aspectMask    :=TVkImageAspectFlags(VK_IMAGE_ASPECT_COLOR_BIT);
 cimg.subresourceRange.baseMipLevel  :=0;
 cimg.subresourceRange.levelCount    :=1;
 cimg.subresourceRange.baseArrayLayer:=0;
 cimg.subresourceRange.layerCount    :=1;

 For i:=0 to count-1 do
 begin
  cimg.image:=FImage[i];
  FView:=VK_NULL_HANDLE;
  r:=vkCreateImageView(Device.FHandle,@cimg,nil,@FView);
  if (r<>VK_SUCCESS) then
  begin
   Writeln(StdErr,'vkCreateImageView:',r);
   Exit;
  end;
  FImages[i]:=TvSwapChainImage.Create;
  FImages[i].FHandle:=FImage[i];
  FImages[i].FView  :=FView;
  FImages[i].Barrier.Init;
 end;
end;

Destructor TvSwapChain.Destroy;
var
 i:Integer;
begin
 For i:=0 to High(FImages) do
 begin
  if (FImages[i].FView<>VK_NULL_HANDLE) then
  begin
   vkDestroyImageView(Device.FHandle,FImages[i].FView,nil);
  end;
  FImages[i].Free;
 end;
 if (FHandle<>VK_NULL_HANDLE) then
 begin
  vkDestroySwapchainKHR(Device.FHandle,FHandle,nil);
 end;
end;

function TvCustomImage.is_invalid:Boolean;
begin
 Result:=(FHandle=VK_NULL_HANDLE);
end;

procedure TvCustomImage.FreeHandle;
begin
 if (FHandle<>VK_NULL_HANDLE) then
 begin
  vkDestroyImage(Device.FHandle,FHandle,nil);
  FHandle:=VK_NULL_HANDLE;
 end;
end;

Destructor TvCustomImage.Destroy;
begin
 FreeHandle;
 //
 UnBindMem(True);
 //
 inherited;
end;

function TvCustomImage.GetRequirements:TVkMemoryRequirements;
begin
 Result:=Default(TVkMemoryRequirements);
 vkGetImageMemoryRequirements(Device.FHandle,FHandle,@Result);
end;

function TvCustomImage.GetDedicatedAllocation:Boolean;
var
 info:TVkImageMemoryRequirementsInfo2;
 rmem:TVkMemoryRequirements2;
 rded:TVkMemoryDedicatedRequirements;
begin
 Result:=false;
 if Pointer(vkGetImageMemoryRequirements2)=nil then Exit;
 info:=Default(TVkImageMemoryRequirementsInfo2);
 info.sType:=VK_STRUCTURE_TYPE_IMAGE_MEMORY_REQUIREMENTS_INFO_2;
 info.image:=FHandle;
 rmem:=Default(TVkMemoryRequirements2);
 rmem.sType:=VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2;
 rded:=Default(TVkMemoryDedicatedRequirements);
 rded.sType:=VK_STRUCTURE_TYPE_MEMORY_DEDICATED_REQUIREMENTS;
 rmem.pNext:=@rded;
 vkGetImageMemoryRequirements2(Device.FHandle,@info,@rmem);
 Result:=(rded.requiresDedicatedAllocation<>VK_FALSE) or
         (rded.prefersDedicatedAllocation <>VK_FALSE);
end;

function TvCustomImage.Compile(ext:Pointer):Boolean;
var
 cinfo:TVkImageCreateInfo;
 clist:TVkImageFormatListCreateInfo;
 MUTABLE:PVkFormat;
 r:TVkResult;
begin
 Result:=False;

 if (FHandle<>VK_NULL_HANDLE) then Exit(True);

 cinfo:=GetImageInfo;
 cinfo.format:=vkFixFormatSupport(cinfo.format,cinfo.tiling,cinfo.usage);

 //save real format
 FFormat:=cinfo.format;

 cinfo.pNext:=@clist;

 MUTABLE:=GET_VK_IMAGE_MUTABLE(cinfo.format);

 clist:=Default(TVkImageFormatListCreateInfo);
 clist.sType:=VK_STRUCTURE_TYPE_IMAGE_FORMAT_LIST_CREATE_INFO;

 clist.viewFormatCount:=GET_FORMATS_LEN(MUTABLE);
 clist.pViewFormats   :=MUTABLE;

 clist.pNext:=ext;

 r:=vkCreateImage(Device.FHandle,@cinfo,nil,@FHandle);
 if (r<>VK_SUCCESS) then
 begin
  Writeln(StdErr,'vkCreateImage:',r);
  Exit;
 end;
 Result:=True;
end;

function TvCustomImage.BindMem(P:TvPointer):TVkResult;
begin
 if P.Acquire then //try Acquire
 begin
  //
  Result:=vkBindImageMemory(Device.FHandle,FHandle,P.FMemory.FHandle,P.FOffset);
  //
  if (Result=VK_SUCCESS) then
  begin
   FBind:=P;
   P.FMemory.AddDependence(@Self.OnReleaseMem);
  end;
  //
  P.Release; //release Acquire
 end else
 begin
  Result:=VK_ERROR_UNKNOWN;
 end;
end;

procedure TvCustomImage.UnBindMem(do_free:Boolean);
var
 B:TvPointer;
 R:ptruint;
begin
 if (FBind.FMemory<>nil) then
 begin
  B:=FBind;
  FBind.FMemory:=nil;
  //
  R:=ptruint(System.InterlockedExchange(Pointer(FBRefs),nil));
  while (R<>0) do
  begin
   B.Release;
   Dec(R);
  end;
  //
  if do_free then
  begin
   MemManager.FreeMemory(B);
  end;
 end;
end;

procedure TvCustomImage.OnReleaseMem(Sender:TObject);
begin
 FreeHandle;
 //
 UnBindMem(False);
end;

procedure TvCustomImage.SetObjectName(const name:RawByteString);
begin
 FName:=name;
 DebugReport.SetObjectName(VK_OBJECT_TYPE_IMAGE,FHandle,PChar(name));
end;

function TvCustomImage._Acquire(Sender:TObject):Boolean;
begin
 Result:=inherited Acquire(Sender);
end;

procedure TvCustomImage._Release(Sender:TObject);
begin
 inherited Release(Sender);
end;

function TvCustomImage.Acquire(Sender:TObject):Boolean;
begin
 if (FBind.FMemory<>nil) then
 begin
  Result:=FBind.Acquire;
  if Result then
  begin
   System.InterlockedIncrement(Pointer(FBRefs));
   inherited Acquire(Sender);
  end;
 end else
 begin
  Result:=False;
  //Result:=inherited Acquire(Sender);
 end;
end;

procedure TvCustomImage.Release(Sender:TObject);
var
 B:TvPointer;
 R:ptruint;
begin
 while True do
 begin
  B:=FBind;
  if (B.FMemory<>nil) and (FBRefs<>0) then
  begin
   R:=FBRefs;
   if (System.InterlockedCompareExchange(Pointer(FBRefs),Pointer(R-1),Pointer(R))=Pointer(R)) then
   begin
    B.Release;
    inherited Release(Sender);
    Break;
   end;
  end else
  begin
   inherited Release(Sender);
   Break;
  end;
 end;
end;

procedure _test_and_set_to(var new:TVkFlags;
                           test:TVkFlags;
                           val_test:TVkImageUsageFlagBits;
                           val_sets:TVkFormatFeatureFlagBits);
begin
 if ((test and ord(val_test))<>0) then
 begin
  new:=new or ord(val_sets);
 end;
end;

function vkGetFormatSupport(format:TVkFormat;tiling:TVkImageTiling;usage:TVkImageUsageFlags):Boolean;
var
 prop:TVkFormatProperties;
 test:TVkFormatFeatureFlags;
begin
 Result:=False;

 prop:=Default(TVkFormatProperties);
 vkGetPhysicalDeviceFormatProperties(
  VulkanApp.FPhysicalDevice,
  format,
  @prop);

 test:=0;
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_TRANSFER_SRC_BIT            ,VK_FORMAT_FEATURE_TRANSFER_SRC_BIT);
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_TRANSFER_DST_BIT            ,VK_FORMAT_FEATURE_TRANSFER_DST_BIT);
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_SAMPLED_BIT                 ,VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT);
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_STORAGE_BIT                 ,VK_FORMAT_FEATURE_STORAGE_IMAGE_BIT);
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT        ,VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT);
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT        ,VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BLEND_BIT);
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT,VK_FORMAT_FEATURE_DEPTH_STENCIL_ATTACHMENT_BIT);
 _test_and_set_to(test,usage,VK_IMAGE_USAGE_INPUT_ATTACHMENT_BIT        ,VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BLEND_BIT);

 Case tiling of
  VK_IMAGE_TILING_OPTIMAL:
   begin
    Result:=(prop.optimalTilingFeatures and test)=test;
   end;
  VK_IMAGE_TILING_LINEAR:
   begin
    Result:=(prop.linearTilingFeatures and test)=test;
   end;
  else;
 end;

end;

//D16_UNORM_S8_UINT -> D24_UNORM_S8_UINT   -> D32_SFLOAT_S8_UINT
//D16_UNORM         -> X8_D24_UNORM_PACK32 -> D32_SFLOAT

function vkFixFormatSupport(format:TVkFormat;tiling:TVkImageTiling;usage:TVkImageUsageFlags):TVkFormat;
begin
 Result:=format;

 repeat

  Case Result of

   VK_FORMAT_D16_UNORM_S8_UINT:
    begin
     if vkGetFormatSupport(Result,tiling,usage) then Break;
     Result:=VK_FORMAT_D24_UNORM_S8_UINT;
    end;

   VK_FORMAT_D24_UNORM_S8_UINT:
    begin
     if vkGetFormatSupport(Result,tiling,usage) then Break;
     Result:=VK_FORMAT_D32_SFLOAT_S8_UINT;
    end;

   VK_FORMAT_D16_UNORM:
    begin
     if vkGetFormatSupport(Result,tiling,usage) then Break;
     Result:=VK_FORMAT_X8_D24_UNORM_PACK32;
    end;

   VK_FORMAT_X8_D24_UNORM_PACK32:
    begin
     if vkGetFormatSupport(Result,tiling,usage) then Break;
     Result:=VK_FORMAT_D32_SFLOAT;
    end;

   else
        Break;
  end;

 until false;

end;

Constructor TvImage.Create(format:TVkFormat;extent:TVkExtent3D;usage:TVkFlags;flags:TVkImageCreateFlags;ext:Pointer=nil);
begin
 FFormat:=format;
 FExtent:=extent;
 FUsage:=usage;
 Fflags:=flags;
 Barrier.Init;
 Compile(ext);
end;

function TvImage.GetImageInfo:TVkImageCreateInfo;
begin
 Result:=Default(TVkImageCreateInfo);
 Result.format:=FFormat;
 Result.extent:=FExtent;
 Result.usage :=FUsage;
 Result.flags :=Fflags;
end;

function TvImage.NewView:TvImageView;
begin
 Result:=NewViewF(FFormat);
end;

function TvImage.NewViewF(Format:TVkFormat):TvImageView;
var
 cinfo:TVkImageViewCreateInfo;
 FImg:TVkImageView;
 r:TVkResult;
begin
 Result:=nil;
 cinfo:=GetViewInfo;
 cinfo.image :=FHandle;
 cinfo.format:=Format;
 FImg:=VK_NULL_HANDLE;
 r:=vkCreateImageView(Device.FHandle,@cinfo,nil,@FImg);
 if (r<>VK_SUCCESS) then
 begin
  Writeln(StdErr,'vkCreateImageView:',r);
  Exit;
 end;
 Result:=TvImageView.Create;
 Result.FHandle:=FImg;
end;

procedure TvSwapChainImage.PushBarrier(cmd:TVkCommandBuffer;
                                       range:TVkImageSubresourceRange;
                                       dstAccessMask:TVkAccessFlags;
                                       newImageLayout:TVkImageLayout;
                                       dstStageMask:TVkPipelineStageFlags);
begin
 if (cmd=VK_NULL_HANDLE) then Exit;

 Barrier.Push(cmd,
              nil,
              FHandle,
              range,
              dstAccessMask,
              newImageLayout,
              dstStageMask);
end;

procedure TvImage.PushBarrier(cmd:TVkCommandBuffer;
                              range:TVkImageSubresourceRange;
                              dstAccessMask:TVkAccessFlags;
                              newImageLayout:TVkImageLayout;
                              dstStageMask:TVkPipelineStageFlags);
begin
 if (cmd=VK_NULL_HANDLE) then Exit;

 Barrier.Push(cmd,
              nil,
              FHandle,
              range,
              dstAccessMask,
              newImageLayout,
              dstStageMask);
end;

Destructor TvImageView.Destroy;
begin
 if (FHandle<>VK_NULL_HANDLE) then
 begin
  vkDestroyImageView(Device.FHandle,FHandle,nil);
 end;
end;

function TvHostImage1D.GetImageInfo:TVkImageCreateInfo;
begin
 Result:=inherited;
 Result.sType        :=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
 Result.imageType    :=VK_IMAGE_TYPE_1D;
 Result.arrayLayers  :=1;
 Result.mipLevels    :=1;
 Result.initialLayout:=VK_IMAGE_LAYOUT_UNDEFINED;
 Result.samples      :=VK_SAMPLE_COUNT_1_BIT;
 Result.tiling       :=VK_IMAGE_TILING_LINEAR;
end;

function TvHostImage2D.GetImageInfo:TVkImageCreateInfo;
begin
 Result:=inherited;
 Result.sType        :=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
 Result.imageType    :=VK_IMAGE_TYPE_2D;
 Result.arrayLayers  :=1;
 Result.mipLevels    :=1;
 Result.initialLayout:=VK_IMAGE_LAYOUT_UNDEFINED;
 Result.samples      :=VK_SAMPLE_COUNT_1_BIT;
 Result.tiling       :=VK_IMAGE_TILING_LINEAR;
end;

//

function TvDeviceImage1D.GetImageInfo:TVkImageCreateInfo;
begin
 Result:=inherited;
 Result.sType        :=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
 Result.imageType    :=VK_IMAGE_TYPE_1D;
 Result.arrayLayers  :=1;
 Result.mipLevels    :=1;
 Result.initialLayout:=VK_IMAGE_LAYOUT_UNDEFINED;
 Result.samples      :=VK_SAMPLE_COUNT_1_BIT;
 Result.tiling       :=VK_IMAGE_TILING_OPTIMAL;
end;

function TvDeviceImage1D.GetViewInfo:TVkImageViewCreateInfo;
begin
 Result:=Default(TVkImageViewCreateInfo);
 Result.sType       :=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
 Result.viewType    :=VK_IMAGE_VIEW_TYPE_1D;
 Result.format      :=FFormat;
 Result.components.r:=VK_COMPONENT_SWIZZLE_IDENTITY;
 Result.components.g:=VK_COMPONENT_SWIZZLE_IDENTITY;
 Result.components.b:=VK_COMPONENT_SWIZZLE_IDENTITY;
 Result.components.a:=VK_COMPONENT_SWIZZLE_IDENTITY;

 Case FFormat of
  VK_FORMAT_S8_UINT:
   Result.subresourceRange.aspectMask  :=ord(VK_IMAGE_ASPECT_STENCIL_BIT);

  VK_FORMAT_D16_UNORM,
  VK_FORMAT_X8_D24_UNORM_PACK32,
  VK_FORMAT_D32_SFLOAT:
   Result.subresourceRange.aspectMask  :=ord(VK_IMAGE_ASPECT_DEPTH_BIT);

  VK_FORMAT_D16_UNORM_S8_UINT,
  VK_FORMAT_D24_UNORM_S8_UINT,
  VK_FORMAT_D32_SFLOAT_S8_UINT:
   Result.subresourceRange.aspectMask  :=ord(VK_IMAGE_ASPECT_DEPTH_BIT) or ord(VK_IMAGE_ASPECT_STENCIL_BIT);

  else
   Result.subresourceRange.aspectMask  :=ord(VK_IMAGE_ASPECT_COLOR_BIT);
 end;

 Result.subresourceRange.baseMipLevel  :=0;
 Result.subresourceRange.levelCount    :=1;
 Result.subresourceRange.baseArrayLayer:=0;
 Result.subresourceRange.layerCount    :=1;
end;

//

function TvDeviceImage2D.GetImageInfo:TVkImageCreateInfo;
begin
 Result:=inherited;
 Result.sType        :=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
 Result.imageType    :=VK_IMAGE_TYPE_2D;
 Result.arrayLayers  :=1;
 Result.mipLevels    :=1;
 Result.initialLayout:=VK_IMAGE_LAYOUT_UNDEFINED;
 Result.samples      :=VK_SAMPLE_COUNT_1_BIT;
 Result.tiling       :=VK_IMAGE_TILING_OPTIMAL;
end;

function TvDeviceImage2D.GetViewInfo:TVkImageViewCreateInfo;
begin
 Result:=Default(TVkImageViewCreateInfo);
 Result.sType       :=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
 Result.viewType    :=VK_IMAGE_VIEW_TYPE_2D;
 Result.format      :=FFormat;
 Result.components.r:=VK_COMPONENT_SWIZZLE_IDENTITY;
 Result.components.g:=VK_COMPONENT_SWIZZLE_IDENTITY;
 Result.components.b:=VK_COMPONENT_SWIZZLE_IDENTITY;
 Result.components.a:=VK_COMPONENT_SWIZZLE_IDENTITY;

 Result.subresourceRange.aspectMask    :=GetAspectMaskByFormat(FFormat);
 Result.subresourceRange.baseMipLevel  :=0;
 Result.subresourceRange.levelCount    :=1;
 Result.subresourceRange.baseArrayLayer:=0;
 Result.subresourceRange.layerCount    :=1;
end;

Function GetAspectMaskByFormat(cformat:TVkFormat):DWORD;
begin
 Case cformat of
  VK_FORMAT_S8_UINT:
   Result  :=ord(VK_IMAGE_ASPECT_STENCIL_BIT);

  VK_FORMAT_D16_UNORM,
  VK_FORMAT_X8_D24_UNORM_PACK32,
  VK_FORMAT_D32_SFLOAT:
   Result  :=ord(VK_IMAGE_ASPECT_DEPTH_BIT);

  VK_FORMAT_D16_UNORM_S8_UINT,
  VK_FORMAT_D24_UNORM_S8_UINT,
  VK_FORMAT_D32_SFLOAT_S8_UINT:
   Result  :=ord(VK_IMAGE_ASPECT_DEPTH_BIT) or ord(VK_IMAGE_ASPECT_STENCIL_BIT);

  else
   Result  :=ord(VK_IMAGE_ASPECT_COLOR_BIT);
 end;
end;

{
WW  VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL
RR  VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL

RW  VK_IMAGE_LAYOUT_DEPTH_READ_ONLY_STENCIL_ATTACHMENT_OPTIMAL
WR  VK_IMAGE_LAYOUT_DEPTH_ATTACHMENT_STENCIL_READ_ONLY_OPTIMAL

W_  VK_IMAGE_LAYOUT_DEPTH_ATTACHMENT_OPTIMAL
R_  VK_IMAGE_LAYOUT_DEPTH_READ_ONLY_OPTIMAL

_W  VK_IMAGE_LAYOUT_STENCIL_ATTACHMENT_OPTIMAL
_R  VK_IMAGE_LAYOUT_STENCIL_READ_ONLY_OPTIMAL
}

Function GetDepthStencilInitLayout(DEPTH_USAGE,STENCIL_USAGE:Byte):TVkImageLayout;
var
 IMAGE_USAGE:Byte;
begin
 IMAGE_USAGE:=(DEPTH_USAGE or STENCIL_USAGE);
 //
 if ((IMAGE_USAGE and TM_READ)=0) then
 begin
  Result:=VK_IMAGE_LAYOUT_UNDEFINED;
 end else
 if ((IMAGE_USAGE and (TM_WRITE or TM_CLEAR))<>0) then
 begin
  Result:=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
 end else
 begin
  Result:=VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL;
 end;
end;

Function GetDepthStencilSendLayout(DEPTH_USAGE,STENCIL_USAGE:Byte):TVkImageLayout;
var
 IMAGE_USAGE:Byte;
begin
 IMAGE_USAGE:=(DEPTH_USAGE or STENCIL_USAGE);
 //
 if ((IMAGE_USAGE and (TM_WRITE or TM_CLEAR))<>0) then
 begin
  Result:=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
 end else
 begin
  Result:=VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL;
 end;
end;

Function GetDepthStencilAccessAttachMask(DEPTH_USAGE,STENCIL_USAGE:Byte):TVkAccessFlags;
var
 IMAGE_USAGE:Byte;
begin
 IMAGE_USAGE:=(DEPTH_USAGE or STENCIL_USAGE);
 //
 Result:=(ord(VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT) *ord((IMAGE_USAGE and TM_READ               )<>0) ) or
         (ord(VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT)*ord((IMAGE_USAGE and (TM_WRITE or TM_CLEAR))<>0) );
end;

function GetColorSendLayout(IMAGE_USAGE:Byte):TVkImageLayout;
begin
 if ((IMAGE_USAGE and TM_MIXED)<>0) then
 begin
  Result:=VK_IMAGE_LAYOUT_GENERAL;
 end else
 begin
  Result:=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
 end;
end;

Function GetColorAccessAttachMask(IMAGE_USAGE:Byte):TVkAccessFlags;
begin
 Result:=(ord(VK_ACCESS_COLOR_ATTACHMENT_READ_BIT) *ord((IMAGE_USAGE and TM_READ               )<>0) ) or
         (ord(VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT)*ord((IMAGE_USAGE and (TM_WRITE or TM_CLEAR))<>0) );
end;

Procedure TvImageBarrier.Init({_image:TVkImage;_sub:TVkImageSubresourceRange});
begin
 //image     :=_image;
 //range     :=_sub;
 AccessMask:=ord(VK_ACCESS_NONE_KHR);
 ImgLayout :=VK_IMAGE_LAYOUT_UNDEFINED;
 StageMask :=ord(VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT);
end;

function IsRead(dstAccessMask:TVkAccessFlags):Boolean; inline;
begin
 Result:=dstAccessMask and
         (
          ord(VK_ACCESS_INDIRECT_COMMAND_READ_BIT) or
          ord(VK_ACCESS_INDEX_READ_BIT) or
          ord(VK_ACCESS_VERTEX_ATTRIBUTE_READ_BIT) or
          ord(VK_ACCESS_UNIFORM_READ_BIT) or
          ord(VK_ACCESS_INPUT_ATTACHMENT_READ_BIT) or
          ord(VK_ACCESS_SHADER_READ_BIT) or
          ord(VK_ACCESS_COLOR_ATTACHMENT_READ_BIT) or
          ord(VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT) or
          ord(VK_ACCESS_TRANSFER_READ_BIT) or
          ord(VK_ACCESS_HOST_READ_BIT) or
          ord(VK_ACCESS_MEMORY_READ_BIT)
         )<>0;
end;

function IsWrite(dstAccessMask:TVkAccessFlags):Boolean; inline;
begin
 Result:=dstAccessMask and
         (
          ord(VK_ACCESS_SHADER_WRITE_BIT) or
          ord(VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT) or
          ord(VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT) or
          ord(VK_ACCESS_TRANSFER_WRITE_BIT) or
          ord(VK_ACCESS_HOST_WRITE_BIT) or
          ord(VK_ACCESS_MEMORY_WRITE_BIT)
         )<>0;
end;

const
 ALL_GRAPHICS_STAGE:TVkPipelineStageFlags=(
  ord(VK_PIPELINE_STAGE_DRAW_INDIRECT_BIT) or
  ord(VK_PIPELINE_STAGE_TASK_SHADER_BIT_EXT) or
  ord(VK_PIPELINE_STAGE_MESH_SHADER_BIT_EXT) or
  ord(VK_PIPELINE_STAGE_VERTEX_INPUT_BIT) or
  ord(VK_PIPELINE_STAGE_VERTEX_SHADER_BIT) or
  ord(VK_PIPELINE_STAGE_TESSELLATION_CONTROL_SHADER_BIT) or
  ord(VK_PIPELINE_STAGE_TESSELLATION_EVALUATION_SHADER_BIT) or
  ord(VK_PIPELINE_STAGE_GEOMETRY_SHADER_BIT) or
  ord(VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT) or
  ord(VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT) or
  ord(VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT) or
  ord(VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT) or
  ord(VK_PIPELINE_STAGE_CONDITIONAL_RENDERING_BIT_EXT) or
  ord(VK_PIPELINE_STAGE_TRANSFORM_FEEDBACK_BIT_EXT) or
  ord(VK_PIPELINE_STAGE_FRAGMENT_SHADING_RATE_ATTACHMENT_BIT_KHR) or
  ord(VK_PIPELINE_STAGE_FRAGMENT_DENSITY_PROCESS_BIT_EXT)
 );

function ChangeStage(curr,next:TVkPipelineStageFlags):Boolean;
begin
 if ((curr and ord(VK_PIPELINE_STAGE_ALL_GRAPHICS_BIT))<>0) then
 begin
  curr:=(curr and (not ord(VK_PIPELINE_STAGE_ALL_GRAPHICS_BIT))) or ALL_GRAPHICS_STAGE;
 end;

 if ((next and ord(VK_PIPELINE_STAGE_ALL_GRAPHICS_BIT))<>0) then
 begin
  next:=(next and (not ord(VK_PIPELINE_STAGE_ALL_GRAPHICS_BIT))) or ALL_GRAPHICS_STAGE;
 end;

 Result:=((curr and next)<>next);
end;

procedure _test_and_set_to(var str :RawByteString;
                           test    :TVkAccessFlags;
                           bit_test:TVkAccessFlagBits;
                           bit_str :RawByteString);
begin
 if ((test and ord(bit_test))<>0) then
 begin
  if (str='') then
  begin
   str:=bit_str;
  end else
  begin
   str:=str + '|' + bit_str;
  end;
 end;
end;

function GetAccessMaskStr(AccessMask:TVkAccessFlags):RawByteString;
begin
 if (AccessMask=0) then Exit('NONE');

 Result:='';

 _test_and_set_to(Result,AccessMask,VK_ACCESS_INDIRECT_COMMAND_READ_BIT         ,'ICR');
 _test_and_set_to(Result,AccessMask,VK_ACCESS_INDEX_READ_BIT                    ,'IR' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_VERTEX_ATTRIBUTE_READ_BIT         ,'VAR');
 _test_and_set_to(Result,AccessMask,VK_ACCESS_UNIFORM_READ_BIT                  ,'UR' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_INPUT_ATTACHMENT_READ_BIT         ,'IAR');
 _test_and_set_to(Result,AccessMask,VK_ACCESS_SHADER_READ_BIT                   ,'SR' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_SHADER_WRITE_BIT                  ,'SW' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_COLOR_ATTACHMENT_READ_BIT         ,'CAR');
 _test_and_set_to(Result,AccessMask,VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT        ,'CAW');
 _test_and_set_to(Result,AccessMask,VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT ,'DAR');
 _test_and_set_to(Result,AccessMask,VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT,'DAW');
 _test_and_set_to(Result,AccessMask,VK_ACCESS_TRANSFER_READ_BIT                 ,'TR' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_TRANSFER_WRITE_BIT                ,'TW' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_HOST_READ_BIT                     ,'HR' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_HOST_WRITE_BIT                    ,'HW' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_MEMORY_READ_BIT                   ,'MR' );
 _test_and_set_to(Result,AccessMask,VK_ACCESS_MEMORY_WRITE_BIT                  ,'MW' );
end;

function TvImageBarrier.Push(cmd:TVkCommandBuffer;
                             cb:t_push_cb;
                             image:TVkImage;
                             range:TVkImageSubresourceRange;
                             dstAccessMask:TVkAccessFlags;
	                     newImageLayout:TVkImageLayout;
	                     dstStageMask:TVkPipelineStageFlags):Boolean;
var
 info:TVkImageMemoryBarrier;
begin
 Result:=False;

 //Writeln('Push:0x',HexStr(image,16),' ',HexStr(dstAccessMask,8),' ',(newImageLayout),' ',HexStr(dstStageMask,8));

 //RAW
 //WAR
 //WAW

 if (AccessMask<>dstAccessMask ) or
    (ImgLayout <>newImageLayout) or
    (ImgLayout     =VK_IMAGE_LAYOUT_GENERAL) or
    (newImageLayout=VK_IMAGE_LAYOUT_GENERAL) or
    ChangeStage(StageMask,dstStageMask) or

    (IsRead (AccessMask) and IsWrite(dstAccessMask)) or
    (IsWrite(AccessMask) and IsRead (dstAccessMask)) or
    (IsWrite(AccessMask) and IsWrite(dstAccessMask))

    then
 begin
  Result:=True;

  if (cb<>nil) then
  begin
   cmd:=cb();
  end;

  if (cmd=0) then Exit;

  if (image=VK_NULL_HANDLE) then
  begin
   print_backtrace(StdErr,Get_pc_addr,get_frame,0);
  end;

  Writeln('Barrier:'#13#10,
          ' image        =0x',HexStr(image,16),#13#10,
          ' srcAccessMask=',GetAccessMaskStr(AccessMask),#13#10,
          ' dstAccessMask=',GetAccessMaskStr(dstAccessMask),#13#10,
          ' oldLayout    ='  ,ImgLayout,#13#10,
          ' newLayout    ='  ,newImageLayout
         );

  info:=Default(TVkImageMemoryBarrier);
  info.sType           :=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
  info.srcAccessMask   :=AccessMask;
  info.dstAccessMask   :=dstAccessMask;
  info.oldLayout       :=ImgLayout;
  info.newLayout       :=newImageLayout;
  info.image           :=image;
  info.subresourceRange:=range;

  vkCmdPipelineBarrier(cmd,
                       StageMask,
                       dstStageMask,
                       ord(VK_DEPENDENCY_BY_REGION_BIT),
                       0, nil,
                       0, nil,
                       1, @info);

  AccessMask:=dstAccessMask;
  ImgLayout :=newImageLayout;
  StageMask :=dstStageMask;
 end;
end;

end.


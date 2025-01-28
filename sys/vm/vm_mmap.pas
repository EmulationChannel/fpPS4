unit vm_mmap;

{$mode ObjFPC}{$H+}
{$CALLING SysV_ABI_CDecl}

interface

uses
 vm,
 vm_map,
 sys_vm_object;

type
 p_query_memory_prot=^t_query_memory_prot;
 t_query_memory_prot=packed record
  start:Pointer;
  __end:Pointer;
  prot  :Integer;
  eflags:Integer;
 end;
 {$IF sizeof(t_query_memory_prot)<>24}{$STOP sizeof(t_query_memory_prot)<>24}{$ENDIF}

 function sys_mlock(addr:Pointer;len:QWORD):Integer;

 function sys_mmap(vaddr:Pointer;
                   vlen :QWORD;
                   prot :Integer;
                   flags:Integer;
                   fd   :Integer;
                   pos  :QWORD):Pointer;

function sys_munmap(addr:Pointer;len:QWORD):Integer;
function sys_msync(addr:Pointer;len:QWORD;flags:Integer):Integer;
function sys_mprotect(addr:Pointer;len:QWORD;prot:Integer):Integer;
function sys_madvise(addr:Pointer;len:QWORD;behav:Integer):Integer;
function sys_mname(addr:Pointer;len:QWORD;name:PChar):Integer;
function sys_query_memory_protection(addr:Pointer;info:Pointer):Integer;
function sys_get_page_table_stats(vm_container,cpu_gpu:Integer;p_total,p_available:PInteger):Integer;

function vm_mmap_to_errno(rv:Integer):Integer; inline;

function vm_mmap2(map        :vm_map_t;
                  addr       :p_vm_offset_t;
                  size       :vm_size_t;
                  prot       :vm_prot_t;
                  maxprot    :vm_prot_t;
                  flags      :Integer;
                  handle_type:objtype_t;
                  handle     :Pointer;
                  foff       :vm_ooffset_t;
                  anon       :Pointer):Integer;

function  mirror_map  (paddr,psize:QWORD):Pointer;
procedure mirror_unmap(base:Pointer;size:QWORD);

implementation

uses
 vcapability,
 md_systm,
 systm,
 errno,
 kern_thr,
 kern_proc,
 vmparam,
 vm_pmap,
 sys_resource,
 kern_resource,
 kern_mtx,
 kern_descrip,
 kern_authinfo,
 vmount,
 vstat,
 vfile,
 vfcntl,
 vnode,
 vfs_subr,
 vnode_if,
 sys_conf,
 vm_pager;

function sys_mlock(addr:Pointer;len:QWORD):Integer;
var
 _adr,_end,last,start,size:vm_offset_t;
 map:vm_map_t;
 error:Integer;
begin
 _adr :=vm_offset_t(addr);
 size :=len;
 last :=_adr + size;
 start:=trunc_page(_adr);
 _end :=round_page(last);

 if (last < _adr) or (_end < _adr) then
 begin
  Exit(EINVAL);
 end;

 map:=p_proc.p_vmspace;

 error:=0;
 //error:=vm_map_wire(map, start, _end, VM_MAP_WIRE_USER or VM_MAP_WIRE_NOHOLES);

 if (error=KERN_SUCCESS) then
 begin
  Result:=0;
 end else
 begin
  Result:=ENOMEM;
 end;
end;

function vm_mmap_cdev(objsize     :vm_size_t;
                      prot        :vm_prot_t;
                      maxprotp    :p_vm_prot_t;
                      flagsp      :PInteger;
                      cdev        :p_cdev;
                      foff        :p_vm_ooffset_t;
                      objp        :p_vm_object_t):Integer;
var
 obj:vm_object_t;
 dsw:p_cdevsw;
 error,flags,ref:Integer;
begin
 flags:=flagsp^;

 dsw:=dev_refthread(cdev, @ref);
 if (dsw=nil) then
 begin
  Exit(ENXIO);
 end;

 if ((dsw^.d_flags and D_MMAP_ANON)<>0) then
 begin
  dev_relthread(cdev, ref);
  maxprotp^:=$33;
  flagsp^:=flagsp^ or MAP_ANON;
  Exit(0);
 end;
 {
  * cdevs do not provide private mappings of any kind.
  }
 if ((maxprotp^ and VM_PROT_WRITE)=0) and
    ((prot and VM_PROT_WRITE)<>0) then
 begin
  dev_relthread(cdev, ref);
  Exit(EACCES);
 end;

 if ((flags and MAP_PRIVATE)<>0) then
 begin
  dev_relthread(cdev, ref);
  Exit(EINVAL);
 end;

 {
  * Force device mappings to be shared.
  }
 flags:=flags or MAP_SHARED;

 error:=dsw^.d_mmap_single2(cdev, foff, objsize, objp, prot, maxprotp, @flags);

 if (error<>ENODEV) then
 begin
  dev_relthread(cdev, ref);
  flagsp^:=flags;
  Exit(error);
 end;

 error:=dsw^.d_mmap_single(cdev, foff, objsize, objp, prot);

 dev_relthread(cdev, ref);

 if (error<>ENODEV) then
 begin
  Exit(error);
 end;

 obj:=vm_pager_allocate(OBJT_DEVICE, cdev, objsize, prot, foff^);

 if (obj=nil) then
 begin
  Exit(EINVAL);
 end;

 objp^:=obj;
 flagsp^:=flags;
 Exit(0);
end;

function vm_mmap_vnode(objsize     :vm_size_t;
                       prot        :vm_prot_t;
                       maxprotp    :p_vm_prot_t;
                       flagsp      :PInteger;
                       vp          :p_vnode;
                       foffp       :p_vm_ooffset_t;
                       objp        :p_vm_object_t;
                       writecounted:PBoolean):Integer;
label
 mark_atime,
 done;
var
 va:t_vattr;
 obj:vm_object_t;
 foff:vm_offset_t;
 mp:p_mount;
 error,flags,locktype,vfslocked:Integer;
begin
 mp:=vp^.v_mount;

 if ((maxprotp^ and VM_PROT_WRITE)<>0) and ((flagsp^ and MAP_SHARED)<>0) then
  locktype:=LK_EXCLUSIVE
 else
  locktype:=LK_SHARED;

 vfslocked:=VFS_LOCK_GIANT(mp);
 error:=vget(vp, locktype);
 if (error<>0) then
 begin
  VFS_UNLOCK_GIANT(vfslocked);
  Exit(error);
 end;
 foff :=foffp^;
 flags:=flagsp^;

 obj:=vp^.v_object;

 case vp^.v_type of
  VREG:
       begin
        {
         * Get the proper underlying object
         }
        if (obj=nil) then
        begin
         error:=EINVAL;
         goto done;
        end;
        if (obj^.handle<>vp) then
        begin
         vput(vp);
         vp:=obj^.handle;
         {
          * Bypass filesystems obey the mpsafety of the
          * underlying fs.
          }
         error:=vget(vp, locktype);
         if (error<>0) then
         begin
          VFS_UNLOCK_GIANT(vfslocked);
          Exit(error);
         end;
        end;
        if (locktype=LK_EXCLUSIVE) then
        begin
         writecounted^:=TRUE;
         //vnode_pager_update_writecount(obj, 0, objsize);
        end;
       end;
  VCHR:
       begin
        error:=vm_mmap_cdev(objsize, prot, maxprotp, flagsp, vp^.v_rdev, foffp, objp);
        if (error=0) then goto mark_atime;
        goto done;
       end

  else
       begin
        error:=EINVAL;
        goto done;
       end;
 end;

 error:=VOP_GETATTR(vp, @va);
 if (error<>0) then
 begin
  goto done;
 end;

 if ((flags and MAP_SHARED)<>0) then
 begin
  if ((va.va_flags and (SF_SNAPSHOT or IMMUTABLE or APPEND))<>0) then
  begin
   if ((prot and VM_PROT_WRITE)<>0) then
   begin
    error:=EPERM;
    goto done;
   end;
   maxprotp^:=maxprotp^ and (not VM_PROT_WRITE);
  end;
 end;
 {
  * If it is a regular file without any references
  * we do not need to sync it.
  * Adjust object size to be the size of actual file.
  }
 objsize:=round_page(va.va_size);
 if (va.va_nlink=0) then
 begin
  flags:=flags or MAP_NOSYNC;
 end;

 obj:=vm_pager_allocate(OBJT_VNODE, vp, objsize, prot, foff);
 if (obj=nil) then
 begin
  error:=ENOMEM;
  goto done;
 end;

 objp^:=obj;
 flagsp^:=flags;

mark_atime:
 vfs_mark_atime(vp);

done:
 if (error<>0) and writecounted^ then
 begin
  writecounted^:=FALSE;
  //vnode_pager_update_writecount(obj, objsize, 0);
 end;

 vput(vp);

 VFS_UNLOCK_GIANT(vfslocked);
 Result:=(error);
end;

function vm_mmap_shm(objsize     :vm_size_t;
                     prot        :vm_prot_t;
                     maxprotp    :p_vm_prot_t;
                     flagsp      :PInteger;
                     shmfd       :Pointer; //shmfd
                     foff        :p_vm_ooffset_t;
                     objp        :p_vm_object_t):Integer;
var
 error:Integer;
begin
 if ((flagsp^ and MAP_SHARED)<>0) and
    ((maxprotp^ and VM_PROT_WRITE)=0) and
    ((prot and VM_PROT_WRITE)<>0) then
 begin
  Exit(EACCES);
 end;

 //error:=shm_mmap(shmfd, objsize, foff, objp);
 error:=EOPNOTSUPP;

 Exit(error);
end;

function IDX_TO_OFF(x:DWORD):QWORD; inline;
begin
 Result:=QWORD(x) shl PAGE_SHIFT;
end;

function vm_mmap_dmem(handle      :Pointer;
                      objsize     :vm_size_t;
                      foff        :vm_ooffset_t;
                      objp        :p_vm_object_t):Integer;
var
 obj:vm_object_t;
 len:vm_size_t;
begin
 obj:=handle; //t_physhmfd *

 len:=IDX_TO_OFF(obj^.size);

 if (foff<0) or
    (len<foff) or
    ((len-foff)<objsize) then
 begin
  Exit(EINVAL);
 end;

 vm_object_reference(obj);

 objp^:=obj;
 Result:=0;
end;

function vm_mmap_to_errno(rv:Integer):Integer; inline;
begin
 Case rv of
  KERN_SUCCESS           :Result:=0;
  KERN_INVALID_ADDRESS,
  KERN_NO_SPACE          :Result:=ENOMEM;
  KERN_PROTECTION_FAILURE:Result:=EACCES;
  KERN_RESOURCE_SHORTAGE :
   begin
    Result:=ENOMEM;
    if (p_proc.p_sdk_version < $3500000) then
    begin
     Result:=EINVAL;
    end;
   end;
  else
   Result:=EINVAL;
 end;
end;

function VMFS_ALIGNED_SPACE(x:QWORD):QWORD; inline; // find a range with fixed alignment
begin
 Result:=x shl 8;
end;

function vm_mmap2(map        :vm_map_t;
                  addr       :p_vm_offset_t;
                  size       :vm_size_t;
                  prot       :vm_prot_t;
                  maxprot    :vm_prot_t;
                  flags      :Integer;
                  handle_type:objtype_t;
                  handle     :Pointer;
                  foff       :vm_ooffset_t;
                  anon       :Pointer):Integer;
var
 obj:vm_object_t;
 docow,error,findspace,rv:Integer;
 fitit:Boolean;
 writecounted:Boolean;
begin
 Result:=0;
 if (size=0) then Exit;

 obj:=nil;

 size:=round_page(size);

 if (map^.size + size) > lim_cur(RLIMIT_VMEM) then
 begin
  Exit(ENOMEM);
 end;

 if (foff and PAGE_MASK)<>0 then
 begin
  Exit(EINVAL);
 end;

 if ((flags and MAP_FIXED)=0) then
 begin
  fitit:=TRUE;
  addr^:=round_page(addr^);
 end else
 begin
  if (addr^<>trunc_page(addr^)) then
  begin
   Exit(EINVAL);
  end;
  fitit:=FALSE;
 end;
 writecounted:=False;

 Case handle_type of
  OBJT_DEVICE:
   begin
    error:=vm_mmap_cdev(size,prot,@maxprot,@flags,handle,@foff,@obj);
   end;
  OBJT_VNODE:
   begin
    error:=vm_mmap_vnode(size,prot,@maxprot,@flags,handle,@foff,@obj,@writecounted);
   end;
  OBJT_SWAP:
   begin
    error:=vm_mmap_shm(size,prot,@maxprot,@flags,handle,@foff,@obj);
   end;
  OBJT_PHYSHM:
   begin
    error:=EACCES;
    if ((prot and (VM_PROT_WRITE or VM_PROT_GPU_WRITE))=0) or
       ((maxprot and VM_PROT_WRITE)<>0) then
    begin
     error:=vm_mmap_dmem(handle,size,foff,@obj);
    end;
   end;

  OBJT_SELF,  //same as default
  OBJT_DEFAULT:
   begin
    if (handle=nil) then
    begin
     error:=0;
    end else
    begin
     error:=EINVAL;
    end;
   end;
  else
   error:=EINVAL;
 end;

 if (error<>0) then Exit(error);

 if ((flags and MAP_ANON)<>0) then
 begin
  obj:=nil;
  docow:=0;
  if (handle=nil) then foff:=0;
 end else
 if ((flags and MAP_PREFAULT_READ)<>0) then
  docow:=MAP_PREFAULT
 else
  docow:=MAP_PREFAULT_PARTIAL;

 if ((flags and (MAP_ANON or MAP_SHARED))=0) then
 begin
  docow:=docow or MAP_COPY_ON_WRITE;
 end;

 if ((flags and MAP_NOSYNC)<>0) then
 begin
  docow:=docow or MAP_DISABLE_SYNCER;
 end;

 if ((flags and MAP_NOCORE)<>0) then
 begin
  docow:=docow or MAP_DISABLE_COREDUMP;
 end;

 // Shared memory is also shared with children.
 if ((flags and MAP_SHARED)<>0) then
 begin
  docow:=docow or MAP_INHERIT_SHARE;
 end;

 if (writecounted) then
 begin
  docow:=docow or MAP_VN_WRITECOUNT;
 end;

 if (handle_type=OBJT_BLOCKPOOL) then
 begin
  docow:=docow or (MAP_COW_NO_BUDGET or MAP_COW_NO_COALESCE);
 end else
 begin
  docow:=docow or (flags and MAP_NO_COALESCE);
 end;

 rv:=KERN_PROTECTION_FAILURE;

 if ((maxprot and prot)=prot) or
    ((addr^ shr 34) < 63) or
    ((addr^ + size) < QWORD($fc00000001)) then
 begin

  if ((flags and MAP_STACK)<>0) then
  begin
   rv:=vm_map_stack(map, addr^, size,
                    prot, maxprot,
                    docow or MAP_STACK_GROWS_DOWN,
                    anon);
  end else
  if (fitit) then
  begin
   if ((flags and MAP_ALIGNMENT_MASK)=MAP_ALIGNED_SUPER) then
   begin
    findspace:=VMFS_SUPER_SPACE;
   end else
   if ((flags and MAP_ALIGNMENT_MASK)<>0) then
   begin
    findspace:=VMFS_ALIGNED_SPACE(flags shr MAP_ALIGNMENT_SHIFT);
   end else
   begin
    findspace:=VMFS_OPTIMAL_SPACE;
   end;
   rv:=vm_map_find(map, obj, foff, addr, size, findspace,
                   prot, maxprot,
                   docow,
                   anon);
  end else
  begin
   rv:=vm_map_fixed(map, obj, foff, addr^, size,
        prot, maxprot,
        docow,
        ord((flags and MAP_NO_OVERWRITE)=0),
        anon);
  end;

 end;

 if (rv=KERN_SUCCESS) then
 begin
  //vm_map_wire
 end else
 begin
  if (writecounted) then
  begin
   //vnode_pager_release_writecount(vm_obj, 0, size);
  end;

  vm_object_deallocate(obj);

  addr^:=0;
 end;

 Exit(vm_mmap_to_errno(rv));
end;

procedure vm_map_set_name_str(map:vm_map_t;start,__end:vm_offset_t;const name:RawByteString); inline;
begin
 vm_map_set_name(map,start,__end,PChar(name));
end;

function sys_mmap(vaddr:Pointer;
                  vlen :QWORD;
                  prot :Integer;
                  flags:Integer;
                  fd   :Integer;
                  pos  :QWORD):Pointer;
label
 _map,
 _done;
var
 td:p_kthread;
 map:vm_map_t;
 fp:p_file;
 vp:p_vnode;
 addr:vm_offset_t;
 size,pageoff:vm_size_t;
 cap_maxprot,maxprot:vm_prot_t;
 handle:Pointer;
 handle_type:obj_type;
 align:Integer;
 rights:cap_rights_t;

 rbp:PPointer;
 rip:Pointer;
 stack_addr:Pointer;
begin
 td:=curkthread;
 if (td=nil) then Exit(Pointer(-1));

 map:=p_proc.p_vmspace;
 addr:=vm_offset_t(vaddr);
 size:=vlen;
 prot:=prot and VM_PROT_ALL;

 //backtrace
 rbp:=Pointer(td^.td_frame.tf_rbp);
 stack_addr:=nil;

 while (QWORD(rbp) < QWORD($800000000000)) do
 begin
  rip:=md_fuword(rbp[1]);
  rbp:=md_fuword(rbp[0]);

  if (QWORD(rip)=QWORD(-1)) or
     (QWORD(rbp)=QWORD(-1)) then
  begin
   Break;
  end;

  if (p_proc.p_libkernel_start_addr >  rip) or
     (p_proc.p_libkernel___end_addr <= rip) then
  begin
   stack_addr:=rip;
   Break;
  end;

 end;
 //backtrace

 fp:=nil;

 if ((flags and MAP_SANITIZER)<>0) {and (devkit_parameter(0)=0)} then
 begin
  Exit(Pointer(EINVAL));
 end;

 if (size = 0) and
    {(sv_flags > -1) and}
    (p_proc.p_osrel > $c3567) then
 begin
  Exit(Pointer(EINVAL));
 end;

 if ((flags and (MAP_VOID or MAP_ANON))<>0) then
 begin
  if (pos<>0) or (fd<>-1) then
  begin
   Exit(Pointer(EINVAL));
  end;
 end;

 if ((flags and MAP_ANON)<>0) then
 begin
  pos:=0;
 end;

 if ((flags and MAP_STACK)<>0) then
 begin
  if (fd<>-1) or
     ((prot and (VM_PROT_READ or VM_PROT_WRITE))<>(VM_PROT_READ or VM_PROT_WRITE)) then
  begin
   Exit(Pointer(EINVAL));
  end;
  flags:=flags or MAP_ANON;
  pos:=0;
 end;

 pageoff:=(pos and PAGE_MASK);
 pos:=pos-pageoff;

 // Adjust size for rounding (on both ends).
 size:=size+pageoff;     // low end...
 size:=round_page(size); // hi end

 // Ensure alignment is at least a page and fits in a pointer.
 align:=flags and MAP_ALIGNMENT_MASK;
 if (align<>0) and
    (align<>Integer(MAP_ALIGNED_SUPER)) and
    (((align shr MAP_ALIGNMENT_SHIFT)>=sizeof(Pointer)*NBBY) or
    ((align shr MAP_ALIGNMENT_SHIFT) < PAGE_SHIFT)) then
 begin
  Exit(Pointer(EINVAL));
 end;

 if ((flags and MAP_FIXED)<>0) then
 begin
  addr:=addr-pageoff;
  if (addr and PAGE_MASK)<>0 then
  begin
   Exit(Pointer(EINVAL));
  end;

  //Address range must be all in user VM space.
  if (addr < vm_map_min(map)) or
     (addr + size > vm_map_max(map)) then
  begin
   Exit(Pointer(EINVAL));
  end;

  if (addr+size<addr) then
  begin
   Exit(Pointer(EINVAL));
  end;
 end else
 begin
  if (addr=0) then
  begin
   if ((g_appinfo.mmap_flags and 2)=0) then
   begin
    addr:=SCE_USR_HEAP_START;
   end;
  end else
  if ((addr and QWORD($fffffffdffffffff))=0) then
  begin
   addr:=SCE_USR_HEAP_START;
  end else
  if (addr=QWORD($880000000)) then
  begin
   addr:=SCE_SYS_HEAP_START;
  end;
 end;

 if ((flags and MAP_VOID)<>0) then
 begin
  //MAP_VOID
  handle:=nil;
  handle_type:=OBJT_DEFAULT;
  maxprot:=0;
  cap_maxprot:=0;
  flags:=flags or MAP_ANON;
  rights:=0;
  prot:=0;
  goto _map;
 end;

 if ((flags and MAP_ANON)<>0) then
 begin
  //Mapping blank space is trivial.
  handle:=nil;
  handle_type:=OBJT_DEFAULT;
  maxprot:=VM_PROT_ALL;
  cap_maxprot:=VM_PROT_ALL;
  goto _map;
 end;

 //Mapping file
 rights:=CAP_MMAP;
 if ((prot and (VM_PROT_READ or VM_PROT_GPU_READ))<>0) then
 begin
  rights:=rights or CAP_READ;
 end;
 if ((flags and MAP_SHARED)<>0) then
 begin
  if ((prot and (VM_PROT_WRITE or VM_PROT_GPU_WRITE))<>0) then
  begin
   rights:=rights or CAP_WRITE;
  end;
 end;
 if ((prot and VM_PROT_EXECUTE)<>0) then
 begin
  rights:=rights or CAP_MAPEXEC;
 end;

 Result:=Pointer(fget_mmap(fd,rights,@cap_maxprot,@fp));
 if (Result<>nil) then goto _done;

 case fp^.f_type of
  DTYPE_VNODE:
    begin
     vp:=fp^.f_vnode;

     maxprot:=VM_PROT_EXECUTE;

     if (vp^.v_mount<>nil) then
     if ((p_mount(vp^.v_mount)^.mnt_flag and MNT_NOEXEC)<>0) then
     begin
      maxprot:=VM_PROT_NONE;
     end;

     if ((fp^.f_flag and FREAD)<>0) then
     begin
      maxprot:=maxprot or VM_PROT_READ;
     end else
     if ((prot and VM_PROT_READ)<>0) then
     begin
      Result:=Pointer(EACCES);
      goto _done;
     end;

     if ((flags and MAP_SHARED)<>0) then
     begin
      if ((fp^.f_flag and FWRITE)<>0) then
      begin
       maxprot:=maxprot or VM_PROT_WRITE;
      end else
      if ((prot and VM_PROT_WRITE)<>0) then
      begin
       Result:=Pointer(EACCES);
       goto _done;
      end;
     end else
     if (vp^.v_type<>VCHR) or ((fp^.f_flag and FWRITE)<>0) then
     begin
      maxprot:=maxprot or VM_PROT_WRITE;
      cap_maxprot:=cap_maxprot or VM_PROT_WRITE;
     end;

     handle:=vp;
     handle_type:=OBJT_VNODE;
    end;

  DTYPE_SHM:
    begin
     handle:=fp^.f_data;
     handle_type:=OBJT_SWAP;
     maxprot:=VM_PROT_NONE;

     // FREAD should always be set.
     if ((fp^.f_flag and FREAD)<>0) then
     begin
      maxprot:=maxprot or (VM_PROT_EXECUTE or VM_PROT_READ);
     end;
     if ((fp^.f_flag and FWRITE)<>0) then
     begin
      maxprot:=maxprot or VM_PROT_WRITE;
     end;
     goto _map;
    end;

  DTYPE_PHYSHM:
    begin
     handle:=fp^.f_data;
     handle_type:=OBJT_PHYSHM;

     prot:=VM_PROT_READ or VM_PROT_GPU_READ;

     if ((fp^.f_flag and FREAD)=0) then
     begin
      prot:=VM_PROT_NONE;
     end;

     maxprot:=prot or (VM_PROT_WRITE or VM_PROT_GPU_WRITE);

     if ((fp^.f_flag and FWRITE)=0) then
     begin
      maxprot:=prot;
     end;
    end;

  DTYPE_BLOCKPOOL:
    begin
     handle:=fp^.f_data;
     handle_type:=OBJT_BLOCKPOOL;
     maxprot:=VM_PROT_ALL;
    end;

  else
    begin
     Writeln('DTYPE_',fp^.f_type,' TODO');
     Result:=Pointer(ENODEV);
     goto _done;
    end;
 end;

_map:
 td^.td_fpop:=fp;
 maxprot:=maxprot and cap_maxprot;

 if (((flags and MAP_SANITIZER) <> 0) and (addr < QWORD($800000000000))) then
 begin
  if (QWORD($fc00000000) < (addr + size)) then
  begin
   prot:=prot and $cf;
  end;
  if ((addr shr 34) > 62) then
  begin
   prot:=prot and $cf;
  end;
 end;

 if (addr=0) and ((g_appinfo.mmap_flags and 2)<>0) then
 begin
  addr:=SCE_REPLAY_EXEC_START;
 end;

 Result:=Pointer(vm_mmap2(map,@addr,size,prot,maxprot,flags,handle_type,handle,pos,stack_addr));
 td^.td_fpop:=nil;

 td^.td_retval[0]:=(addr+pageoff);

 if (Result=nil) then
 if (stack_addr<>nil) then
 begin
  //Do you really need it?
  vm_map_set_name_str(map,addr,size + addr,'anon:'+HexStr(QWORD(stack_addr),10));
 end;

 Writeln('0x',HexStr(QWORD(stack_addr),10),'->',
         'sys_mmap(','0x',HexStr(QWORD(vaddr),10),
                    ',0x',HexStr(vlen,10),
                    ',0x',HexStr(prot,1),
                    ',0x',HexStr(flags,6),
                      ',',fd,
                    ',0x',HexStr(pos,10),
                     '):',Integer(Result),
                    ':0x',HexStr(td^.td_retval[0],10),'..0x',HexStr(td^.td_retval[0]+size,10));


_done:
 if (fp<>nil) then
 begin
  fdrop(fp);
 end;
end;

function sys_munmap(addr:Pointer;len:QWORD):Integer;
var
 map:vm_map_t;
 size,pageoff:vm_size_t;
begin
 size:=len;
 if (size=0) then
 begin
  Exit(EINVAL);
 end;

 pageoff:=(vm_size_t(addr) and PAGE_MASK);
 addr:=addr-pageoff;
 size:=size+pageoff;
 size:=round_page(size);

 if (addr + size < addr) then
 begin
  Exit(EINVAL);
 end;

 map:=p_proc.p_vmspace;

 {
  * Check for illegal addresses.  Watch out for address wrap...
  }
 if (qword(addr) < vm_map_min(map)) or (qword(addr) + size > vm_map_max(map)) then
 begin
  Exit(EINVAL);
 end;

 Result:=vm_map_remove(map, qword(addr), qword(addr) + size);

 Writeln('sys_munmap(','0x',HexStr(QWORD(addr),10),
                      ',0x',HexStr(len,10),
                       '):',Integer(Result)
                     );

 Result:=vm_mmap_to_errno(Result);
end;

function sys_msync(addr:Pointer;len:QWORD;flags:Integer):Integer;
var
 map:vm_map_t;
 _addr:vm_offset_t;
 pageoff:vm_size_t;
begin
 _addr:=vm_offset_t(addr);

 pageoff:=(_addr and PAGE_MASK);
 _addr:=_addr-pageoff;
 len:=len+pageoff;

 len:=round_page(len);

 if ((_addr + len) < _addr) then
 begin
  Exit(EINVAL);
 end;

 if ((flags and (MS_ASYNC or MS_INVALIDATE))=(MS_ASYNC or MS_INVALIDATE)) then
 begin
  Exit(EINVAL);
 end;

 map:=p_proc.p_vmspace;

 // Clean the pages and interpret the Exit value.
 Result:=vm_map_sync(map,
                     _addr,
                     _addr + len,
                     (flags and MS_ASYNC)=0,
                     (flags and MS_INVALIDATE)<>0);

 case Result of
  KERN_SUCCESS         :Result:=0;
  KERN_INVALID_ADDRESS :Result:=ENOMEM;
  KERN_INVALID_ARGUMENT:Result:=EBUSY;
  KERN_FAILURE         :Result:=EIO;
  else
                        Result:=EINVAL;
 end;

end;

function sys_mprotect(addr:Pointer;len:QWORD;prot:Integer):Integer;
var
 size,pageoff:vm_size_t;
begin
 size:=len;
 prot:=prot and VM_PROT_ALL;

 pageoff:=(vm_size_t(addr) and PAGE_MASK);
 addr:=addr-pageoff;
 size:=size+pageoff;
 size:=round_page(size);

 if (addr + size < addr) then
 begin
  Exit(EINVAL);
 end;

 Result:=vm_map_protect(p_proc.p_vmspace, QWORD(addr), QWORD(addr) + size, prot, FALSE);

 case Result of
  KERN_SUCCESS           :Exit(0);
  KERN_PROTECTION_FAILURE:Exit(EACCES);
  KERN_RESOURCE_SHORTAGE :Exit(ENOMEM);
  else
                          Exit(EINVAL);
 end;
end;

function sys_madvise(addr:Pointer;len:QWORD;behav:Integer):Integer;
var
 map:vm_map_t;
 start,__end:vm_offset_t;
begin
 {
  * Check for our special case, advising the swap pager we are
  * "immortal."
  }
 if (behav=MADV_PROTECT) then
 begin
  Exit(0);
 end;

 {
  * Check for illegal behavior
  }
 if (behav < 0) or (behav > MADV_CORE) then
 begin
  Exit(EINVAL);
 end;

 map:=p_proc.p_vmspace;

 {
  * Check for illegal addresses.  Watch out for address wrap... Note
  * that VM_*_ADDRESS are not constants due to casts (argh).
  }
 if (vm_offset_t(addr) < vm_map_min(map)) or
    (vm_offset_t(addr) + len > vm_map_max(map)) then
 begin
  Exit(EINVAL);
 end;

 if (vm_offset_t(addr) + len) < vm_offset_t(addr) then
 begin
  Exit(EINVAL);
 end;

 {
  * Since this routine is only advisory, we default to conservative
  * behavior.
  }
 start:=trunc_page(vm_offset_t(addr));
 __end:=round_page(vm_offset_t(addr) + len);

 if (vm_map_madvise(map, start, __end, behav))<>0 then
 begin
  Exit(EINVAL);
 end;

 Exit(0);
end;

function sys_mname(addr:Pointer;len:QWORD;name:PChar):Integer;
var
 map:vm_map_t;
 start,__end:vm_offset_t;
 _name:array[0..31] of Char;
begin
 map:=p_proc.p_vmspace;

 if (vm_offset_t(addr) < vm_map_min(map)) or
    (vm_offset_t(addr) + len > vm_map_max(map)) then
 begin
  Exit(EINVAL);
 end;

 if (vm_offset_t(addr) + len) < vm_offset_t(addr) then
 begin
  Exit(EINVAL);
 end;

 Result:=copyinstr(name,@_name,32,nil);
 if (Result<>0) then Exit;

 start:=trunc_page(vm_offset_t(addr));
 __end:=round_page(vm_offset_t(addr) + len);

 vm_map_set_name(map,start,__end,@_name);

 Writeln('sys_mname(','0x',HexStr(QWORD(addr),10),
                     ',0x',HexStr(len,10),
                       ',','"',name,'"',
                       ')'
                     );

end;

function sys_query_memory_protection(addr:Pointer;info:Pointer):Integer;
var
 map:vm_map_t;
 _addr:vm_offset_t;
 __end:vm_offset_t;
 entry:vm_map_entry_t;
 data:t_query_memory_prot;
begin
 Result:=EINVAL;
 _addr:=trunc_page(vm_offset_t(addr));
 map:=p_proc.p_vmspace;
 __end:=vm_map_max(map);
 if (_addr<__end) or (_addr=__end) then
 begin
  vm_map_lock(map);
  if not vm_map_lookup_entry(map,_addr,@entry) then
  begin
   vm_map_unlock(map);
   Result:=EACCES;
  end else
  begin
   data.start:=Pointer(entry^.start);
   data.__end:=Pointer(entry^.__end);
   data.prot:=(entry^.max_protection and entry^.protection);
   data.eflags:=entry^.eflags;
   vm_map_unlock(map);
   Result:=copyout(@data,info,SizeOf(t_query_memory_prot));
  end;
 end;
end;

function sys_get_page_table_stats(vm_container,cpu_gpu:Integer;p_total,p_available:PInteger):Integer;
begin
 Exit(ENOENT); //devkit_parameter(0)=0
end;

function mirror_map(paddr,psize:QWORD):Pointer;
var
 map:vm_map_t;
begin
 map:=p_proc.p_vmspace;

 //prevent deadlock
 vm_map_lock(map);

 Result:=pmap_mirror_map(map^.pmap,paddr,paddr+psize);

 vm_map_unlock(map);
end;

procedure mirror_unmap(base:Pointer;size:QWORD);
var
 map:vm_map_t;
begin
 map:=p_proc.p_vmspace;

 //Deadlock protection is not needed yet

 pmap_mirror_unmap(map^.pmap,base,size);
end;

end.


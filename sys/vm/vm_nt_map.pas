unit vm_nt_map;

{$mode ObjFPC}{$H+}
{$CALLING SysV_ABI_CDecl}

interface

uses
 sysutils,
 vm,
 kern_mtx,
 systm,
 vm_pmap_prot,
 vm_nt_sub_map;

const
 NT_FILE_FREE=1;
 NT_MOBJ_FREE=2;
 NT_UNION_OBJ=4;

 MAX_UNION_SIZE=256*1024*1024;

type
 t_danger_range=packed record
  start:DWORD;
  __end:DWORD;
 end;

 t_danger_zone=object
  Flock :mtx;
  Frange:t_danger_range;
  procedure Init;
  procedure Done;
  function  in_range(addr,size:vm_offset_t):Boolean;
  procedure d_wait(addr,size:vm_offset_t);
  procedure lock(start,__end:vm_offset_t);
  procedure unlock;
 end;

 pp_vm_nt_file_obj=^p_vm_nt_file_obj;
 p_vm_nt_file_obj=^vm_nt_file_obj;
 vm_nt_file_obj=packed record
  hfile:THandle;
  refs :QWORD;
  flags:Byte;
  maxp :Byte;
 end;

 ///

 pp_vm_nt_entry=^p_vm_nt_entry;
 p_vm_nt_entry=^vm_nt_entry;
 vm_nt_entry=packed object
  prev  :p_vm_nt_entry;     // previous entry
  next  :p_vm_nt_entry;     // next entry
  left  :p_vm_nt_entry;     // left child in binary search tree
  right :p_vm_nt_entry;     // right child in binary search tree
  usize :vm_offset_t;       // unaligned size
  offset:vm_ooffset_t;      // offset into object
  obj   :p_vm_nt_file_obj;  // object I point to
  sub   :t_vm_nt_sub_map;
  property start:vm_offset_t read sub.header.start write sub.header.start; // start address
  property __end:vm_offset_t read sub.header.__end write sub.header.__end; // end address
 end;

 p_vm_nt_map=^t_vm_nt_map;
 t_vm_nt_map=object
  header     :vm_nt_entry;   // List of entries
  lock       :mtx;           // Lock for map data
  root       :p_vm_nt_entry; // Root of a binary search tree
  danger_zone:t_danger_zone;
  property min_offset:vm_offset_t read header.sub.header.start write header.sub.header.start;
  property max_offset:vm_offset_t read header.sub.header.__end write header.sub.header.__end;
 end;

function  vm_nt_file_obj_allocate  (hfile:THandle;maxp:Byte):p_vm_nt_file_obj;
procedure vm_nt_file_obj_destroy   (obj:p_vm_nt_file_obj);
procedure vm_nt_file_obj_reference (obj:p_vm_nt_file_obj);
procedure vm_nt_file_obj_deallocate(obj:p_vm_nt_file_obj);

function  vm_nt_map_max(map:p_vm_nt_map):vm_offset_t;
function  vm_nt_map_min(map:p_vm_nt_map):vm_offset_t;

procedure vm_nt_map_init(map:p_vm_nt_map;min,max:vm_offset_t);

function  vm_nt_map_insert(
             map   :p_vm_nt_map;
             obj   :p_vm_nt_file_obj;
             offset:vm_ooffset_t;
             start :vm_offset_t;
             __end :vm_offset_t;
             usize :vm_offset_t;
             prot  :Integer):Integer;

function  vm_nt_map_delete(map:p_vm_nt_map;start:vm_offset_t;__end:vm_offset_t):Integer;

//Change protection taking into account tracking
procedure vm_nt_map_protect(map  :p_vm_nt_map;
                            start:vm_offset_t;
                            __end:vm_offset_t;
                            prot :Integer);

//Change protection tracking
procedure vm_nt_map_tracking(map  :p_vm_nt_map;
                             start:vm_offset_t;
                             __end:vm_offset_t;
                             prot :Integer);

//Update page protection by mode
procedure vm_nt_map_prot_fix(map  :p_vm_nt_map;
                             start:vm_offset_t;
                             __end:vm_offset_t;
                             mode :Integer);

procedure vm_nt_map_madvise(map   :p_vm_nt_map;
                            start :vm_offset_t;
                            __end :vm_offset_t;
                            advise:Integer);

//Create a memory mirror of the current state of the pages
function  vm_nt_map_mirror(map  :p_vm_nt_map;
                           start:vm_offset_t;
                           __end:vm_offset_t):Pointer;

implementation

uses
 time,
 kern_param,
 md_map;

type
 p_range=^t_range;
 t_range=record
  start:vm_offset_t;
  __end:vm_offset_t;
 end;

 t_range_stat=record
  obj:p_vm_nt_file_obj;
  //
  case Byte of
   0:(
      rprev:t_range;
      rcurr:t_range;
      rnext:t_range;
     );
   1:(
      range:array[0..2] of t_range;
     );
 end;

function vm_nt_file_obj_allocate(hfile:THandle;maxp:Byte):p_vm_nt_file_obj;
begin
 Assert(maxp<>0);

 Result:=AllocMem(SizeOf(vm_nt_file_obj));

 Result^.hfile:=hfile;
 Result^.refs :=1;
 Result^.flags:=NT_FILE_FREE or NT_MOBJ_FREE or NT_UNION_OBJ;
 Result^.maxp :=maxp;
end;

procedure vm_nt_file_obj_destroy(obj:p_vm_nt_file_obj);
var
 r:Integer;
begin
 if ((obj^.flags and NT_FILE_FREE)<>0) then
 if (obj^.hfile<>0) then
 begin
  r:=md_memfd_close(obj^.hfile);
  if (r<>0) then
  begin
   Writeln('failed md_memfd_close(',obj^.hfile,'):0x',HexStr(r,8));
   Assert(false,'vm_nt_file_obj_destroy');
  end;
  obj^.hfile:=0;
 end;

 if ((obj^.flags and NT_MOBJ_FREE)<>0) then
 begin
  FreeMem(obj);
 end;
end;

procedure vm_nt_file_obj_reference(obj:p_vm_nt_file_obj);
begin
 if (obj=nil) then Exit;

 System.InterlockedIncrement64(obj^.refs);
end;

procedure vm_nt_file_obj_deallocate(obj:p_vm_nt_file_obj);
begin
 if (obj=nil) then Exit;

 if (System.InterlockedDecrement64(obj^.refs)=0) then
 begin
  vm_nt_file_obj_destroy(obj);
 end;
end;

//

procedure vm_init_stat(var stat:t_range_stat;entry:p_vm_nt_entry); inline;
begin
 stat:=Default(t_range_stat);
 stat.obj        :=entry^.obj;
 stat.rcurr.start:=entry^.start;
 stat.rcurr.__end:=entry^.__end;
end;

procedure vm_get_space(map:p_vm_nt_map;entry:p_vm_nt_entry;var start,__end:vm_offset_t);
var
 prev:p_vm_nt_entry;
 next:p_vm_nt_entry;
begin
 prev:=entry^.prev;
 next:=entry^.next;

 if (prev=@map^.header) then
 begin
  start:=map^.min_offset;
 end else
 begin
  start:=prev^.__end;
 end;

 if (next=@map^.header) then
 begin
  __end:=map^.max_offset;
 end else
 begin
  __end:=next^.start;
 end;
end;

procedure vm_map(map:p_vm_nt_map;
                 entry:p_vm_nt_entry;
                 prot:Integer);
var
 start:vm_offset_t;
 __end:vm_offset_t;
 size:vm_size_t;
 max:Integer;
 r:Integer;
begin
 if (entry^.obj<>nil) then
 begin
  size:=entry^.__end-entry^.start;

  vm_get_space(map,entry,start,__end);

  if (start<>__end) then
  if (entry^.start<>start) or
     (entry^.__end<>__end) then
  begin
   r:=md_split(Pointer(entry^.start),size);
   if (r<>0) then
   begin
    Writeln('failed md_split(',HexStr(entry^.start,11),',',HexStr(entry^.start+size,11),'):0x',HexStr(r,8));
    Assert(false,'vm_map');
   end;
  end;

  max:=entry^.obj^.maxp;

  if (entry^.obj^.hfile<>0) then
  begin
   r:=md_file_mmap_ex(entry^.obj^.hfile,
                      Pointer(entry^.start),
                      entry^.offset,
                      entry^.usize, //unaligned size
                      (max and VM_RW));
   if (r<>0) then
   begin
    Writeln('failed md_file_mmap_ex(',HexStr(entry^.start,11),',',HexStr(entry^.start+size,11),'):0x',HexStr(r,8));
    Assert(false,'vm_map');
   end;
  end;

  if ((prot and VM_RW)<>(max and VM_RW)) then
  begin
   r:=md_protect(Pointer(entry^.start),size,(prot and VM_RW));
   if (r<>0) then
   begin
    Writeln('failed md_protect(',HexStr(entry^.start,11),',',HexStr(entry^.start+size,11),'):0x',HexStr(r,8));
    Assert(false,'vm_map');
   end;
  end;

  //Writeln('md_file_mmap(',HexStr(entry^.start,11),',',HexStr(entry^.start+size,11),'):0x',HexStr(r,8));
 end;
end;

//

function MD_IDX_TO_OFF(x:DWORD):QWORD; inline;
begin
 Result:=QWORD(x) shl MD_PAGE_SHIFT;
end;

function MD_OFF_TO_IDX(x:QWORD):DWORD; inline;
begin
 Result:=QWORD(x) shr MD_PAGE_SHIFT;
end;

//

procedure t_danger_zone.Init;
begin
 mtx_init(Flock,'danger_zone');
end;

procedure t_danger_zone.Done;
begin
 mtx_destroy(Flock);
end;

function t_danger_zone.in_range(addr,size:vm_offset_t):Boolean;
var
 range:t_danger_range;
begin
 QWORD(range):=System.InterlockedExchangeAdd64(QWORD(Frange),0);

 Result:=(addr<MD_IDX_TO_OFF(range.__end)) and ((addr+size)>MD_IDX_TO_OFF(range.start));
end;

procedure t_danger_zone.d_wait(addr,size:vm_offset_t);
begin
 mtx_lock(Flock);

  if in_range(addr,size) then
  begin
   msleep(@Self,@Flock,PCATCH,'danger_zone',hz);
  end;

 mtx_unlock(Flock);
end;

procedure t_danger_zone.lock(start,__end:vm_offset_t);
var
 range:t_danger_range;
begin
 range.start:=MD_OFF_TO_IDX(start);
 range.__end:=MD_OFF_TO_IDX(__end);

 System.InterlockedExchange64(QWORD(Frange),QWORD(range));

 mtx_lock(Flock);
end;

procedure t_danger_zone.unlock;
begin
 System.InterlockedExchange64(QWORD(Frange),0);

 mtx_unlock(Flock);

 wakeup(@Self);
end;

//

function vm_remap(map:p_vm_nt_map;
                  entry1:p_vm_nt_entry;
                  entry2:p_vm_nt_entry;
                  entry3:p_vm_nt_entry;
                  var stat:t_range_stat):Boolean;
var
 ets:array[0..2] of p_vm_nt_entry;
 first:p_vm_nt_entry;

 e_count:Integer;
 r_count:Integer;

 start:vm_offset_t;
 __end:vm_offset_t;
 size:vm_size_t;

 max:Integer;

 p:p_range;
 i,r:Integer;
begin
 Result:=False;

 if (stat.obj=nil) then Exit(False);

 ets[0]:=entry1;
 ets[1]:=entry2;
 ets[2]:=entry3;

 //get first entry
 first:=nil;
 For i:=Low(ets) to High(ets) do
 begin
  if (ets[i]<>nil) then
  begin
   first:=ets[i];
   Break;
  end;
 end;

 if (first=nil) then Exit(False);

 if (stat.rcurr.start=first^.start) and
    (stat.rcurr.__end=first^.__end) then Exit(False);

 start:=0;
 __end:=0;
 e_count:=0;
 r_count:=0;

 //get range
 For i:=Low(ets) to High(ets) do
 begin
  if (ets[i]<>nil) then
  begin
   if (start=0) or (start>ets[i]^.start) then
   begin
    start:=ets[i]^.start;
   end;

   if (__end=0) or (__end<ets[i]^.__end) then
   begin
    __end:=ets[i]^.__end;
   end;

   Inc(e_count);
  end;
 end;

 //union size
 size:=__end-start;

 //danger zone
 map^.danger_zone.lock(start,__end);

 //unmap all
 For i:=Low(stat.range) to High(stat.range) do
 begin
  p:=@stat.range[i];
  //
  if (p^.start<>0) and
     (p^.start<>p^.__end) then
  begin
   //
   if (stat.obj^.hfile<>0) then
   begin
    r:=md_file_unmap_ex(Pointer(p^.start));
    if (r<>0) then
    begin
     Writeln('failed md_file_unmap_ex(',HexStr(p^.start,11),',',HexStr(p^.__end,11),'):0x',HexStr(r,8));
     Assert(false,'vm_remap');
    end;
   end;
   //
   //Writeln('md_file_unmap_ex(',HexStr(p^.start,11),',',HexStr(p^.__end,11),'):0x',HexStr(r,8));
   //
   Inc(r_count);
  end;
 end;

 //union parts
 if (r_count>1) then
 begin
  r:=md_union(Pointer(start),size);
  if (r<>0) then
  begin
   Writeln('failed md_union(',HexStr(start,11),',',HexStr(__end,11),'):0x',HexStr(r,8));
   Assert(false,'vm_remap');
  end;
  //Writeln('md_union(',HexStr(start,11),',',HexStr(__end,11),'):0x',HexStr(r,8));
 end;

 //split to parts
 if (e_count>1) then
 For i:=Low(ets) to High(ets) do
 begin
  if (ets[i]<>nil) and (ets[i]<>first) then
  begin
   size:=ets[i]^.__end-ets[i]^.start;

   r:=md_split(Pointer(ets[i]^.start),size);
   if (r<>0) then
   begin
    Writeln('failed md_split(',HexStr(ets[i]^.start,11),',',HexStr(ets[i]^.__end,11),'):0x',HexStr(r,8));

    Writeln('(',HexStr(start,11),',',HexStr(__end,11),')');

    Assert(false,'vm_remap');
   end;

   //Writeln('md_split(',HexStr(ets[i]^.start,11),',',HexStr(ets[i]^.__end,11),'):0x',HexStr(r,8));

   Break; //middle or last splt
  end;
 end;

 max:=stat.obj^.maxp;

 //map new parts
 For i:=Low(ets) to High(ets) do
 begin
  if (ets[i]<>nil) then
  begin
   //map new
   if (ets[i]^.obj<>nil) then
   if (stat.obj^.hfile<>0) then
   begin
    r:=md_file_mmap_ex(stat.obj^.hfile,
                       Pointer(ets[i]^.start),
                       ets[i]^.offset,
                       ets[i]^.usize, //unaligned size
                       (max and VM_RW));
    if (r<>0) then
    begin
     Writeln('failed md_file_mmap_ex(',HexStr(ets[i]^.start,11),',',HexStr(ets[i]^.__end,11),'):0x',HexStr(r,8));
     Assert(false,'vm_remap');
    end;

    //Writeln('md_file_mmap_ex(',HexStr(ets[i]^.start,11),',',HexStr(ets[i]^.__end,11),'):0x',HexStr(r,8));
   end;
  end;
 end;

 //fix prot

 For i:=Low(ets) to High(ets) do
 begin
  if (ets[i]<>nil) then
  begin
   if (ets[i]^.obj<>nil) then
   if (stat.obj^.hfile<>0) then
   begin
    vm_nt_sub_map_prot_fixup(@ets[i]^.sub,
                             ets[i]^.start,
                             ets[i]^.__end,
                             TRACK_PROT or REMAP_PROT //untrack trigger or restore track?
                            );
   end;
  end;
 end;

 //danger zone
 map^.danger_zone.unlock;

 Result:=True;
end;

procedure vm_unmap(map:p_vm_nt_map;entry:p_vm_nt_entry);
var
 start:vm_offset_t;
 __end:vm_offset_t;
 r:Integer;
begin
 if (entry^.obj<>nil) then
 if (entry^.obj^.hfile<>0) then
 begin
  r:=md_file_unmap_ex(Pointer(entry^.start));
  if (r<>0) then
  begin
   Writeln('failed md_file_unmap_ex(',HexStr(entry^.start,11),',',HexStr(entry^.__end,11),'):0x',HexStr(r,8));
   Assert(false,'vm_unmap');
  end;
  //Writeln('md_file_unmap_ex(',HexStr(entry^.start,11),',',HexStr(entry^.__end,11),'):0x',HexStr(r,8));
 end;

 vm_get_space(map,entry,start,__end);

 if (start<>__end) then
 if (entry^.start<>start) or
    (entry^.__end<>__end) then
 begin
  r:=md_union(Pointer(start),__end-start);
  if (r<>0) then
  begin
   Writeln('failed md_union(',HexStr(start,11),',',HexStr(__end,11),'):0x',HexStr(r,8));

   Writeln('(',HexStr(entry^.start,11),',',HexStr(entry^.__end,11),'):0x',HexStr(r,8));

   Assert(false,'vm_unmap');
  end;
 end;
end;

//

function vm_nt_map_max(map:p_vm_nt_map):vm_offset_t; inline;
begin
 Result:=map^.max_offset;
end;

function vm_nt_map_min(map:p_vm_nt_map):vm_offset_t; inline;
begin
 Result:=map^.min_offset;
end;

procedure VM_NT_MAP_RANGE_CHECK(map:p_vm_nt_map;var start,__end:vm_offset_t);
begin
 if (start<vm_nt_map_min(map)) then
 begin
  start:=vm_nt_map_min(map);
 end;
 if (__end>vm_nt_map_max(map)) then
 begin
  __end:=vm_nt_map_max(map);
 end;
 if (start>__end) then
 begin
  start:=__end;
 end;
end;

procedure vm_nt_map_init(map:p_vm_nt_map;min,max:vm_offset_t);
begin
 map^.header.next:=@map^.header;
 map^.header.prev:=@map^.header;
 map^.min_offset:=min;
 map^.max_offset:=max;
 map^.root:=nil;
 map^.danger_zone.Init;
 mtx_init(map^.lock,'vm_nt_map');
end;

procedure vm_nt_map_lock(map:p_vm_nt_map); inline;
begin
 mtx_lock(map^.lock);
end;

procedure vm_nt_map_unlock(map:p_vm_nt_map); inline;
begin
 mtx_unlock(map^.lock);
end;

procedure vm_nt_entry_dispose(map:p_vm_nt_map;entry:p_vm_nt_entry); inline;
begin
 FreeMem(entry);
end;

procedure vm_nt_entry_deallocate(map:p_vm_nt_map;entry:p_vm_nt_entry); inline;
begin
 vm_nt_sub_map_free       (@entry^.sub);
 vm_nt_file_obj_deallocate(entry^.obj);
 vm_nt_entry_dispose      (map,entry);
end;

function vm_nt_entry_create(map:p_vm_nt_map):p_vm_nt_entry;
var
 new_entry:p_vm_nt_entry;
begin
 new_entry:=AllocMem(SizeOf(vm_nt_entry));
 Assert((new_entry<>nil),'vm_nt_entry_create: kernel resources exhausted');
 Result:=new_entry;
end;

function vm_nt_entry_splay(addr:vm_offset_t;root:p_vm_nt_entry):p_vm_nt_entry;
var
 llist,rlist:p_vm_nt_entry;
 ltree,rtree:p_vm_nt_entry;
 y          :p_vm_nt_entry;
begin
 if (root=nil) then Exit(root);

 llist:=nil;
 rlist:=nil;
 repeat
  if (addr<root^.start) then
  begin
   y:=root^.left;
   if (y=nil) then break;
   if (addr<y^.start) and (y^.left<>nil) then
   begin
    root^.left:=y^.right;
    y^.right:=root;
    root:=y^.left;
    y^.left:=rlist;
    rlist:=y;
   end else
   begin
    root^.left:=rlist;
    rlist:=root;
    root:=y;
   end;
  end else
  if (addr>=root^.__end) then
  begin
   y:=root^.right;
   if (y=nil) then break;
   if (addr>=y^.__end) and (y^.right<>nil) then
   begin
    root^.right:=y^.left;
    y^.left:=root;
    root:=y^.right;
    y^.right:=llist;
    llist:=y;
   end else
   begin
    root^.right:=llist;
    llist:=root;
    root:=y;
   end;
  end else
  begin
   break;
  end;
 until false;

 ltree:=root^.left;
 while (llist<>nil) do
 begin
  y:=llist^.right;
  llist^.right:=ltree;
  ltree:=llist;
  llist:=y;
 end;
 rtree:=root^.right;
 while (rlist<>nil) do
 begin
  y:=rlist^.left;
  rlist^.left:=rtree;
  rtree:=rlist;
  rlist:=y;
 end;

 root^.left:=ltree;
 root^.right:=rtree;

 Result:=(root);
end;

procedure vm_nt_entry_link(
           map        :p_vm_nt_map;
           after_where:p_vm_nt_entry;
           entry      :p_vm_nt_entry);
begin
 entry^.prev:=after_where;
 entry^.next:=after_where^.next;
 entry^.next^.prev:=entry;
 after_where^.next:=entry;

 if (after_where<>@map^.header) then
 begin
  if (after_where<>map^.root) then
  begin
   vm_nt_entry_splay(after_where^.start, map^.root);
  end;
  entry^.right:=after_where^.right;
  entry^.left:=after_where;
  after_where^.right:=nil;
 end else
 begin
  entry^.right:=map^.root;
  entry^.left:=nil;
 end;
 map^.root:=entry;
end;

procedure vm_nt_entry_unlink(
           map        :p_vm_nt_map;
           entry      :p_vm_nt_entry);
var
 next,prev,root:p_vm_nt_entry;
begin
 if (entry<>map^.root) then
 begin
  vm_nt_entry_splay(entry^.start, map^.root);
 end;
 if (entry^.left=nil) then
 begin
  root:=entry^.right;
 end else
 begin
  root:=vm_nt_entry_splay(entry^.start, entry^.left);
  root^.right:=entry^.right;
 end;
 map^.root:=root;

 prev:=entry^.prev;
 next:=entry^.next;
 next^.prev:=prev;
 prev^.next:=next;
end;

function vm_nt_map_lookup_entry(
           map        :p_vm_nt_map;
           address    :vm_offset_t;
           entry      :pp_vm_nt_entry):Boolean;
var
 cur:p_vm_nt_entry;
begin
 cur:=map^.root;
 if (cur=nil) then
 begin
  entry^:=@map^.header;
 end else
 if (address>=cur^.start) and (cur^.__end>address) then
 begin
  entry^:=cur;
  Exit(TRUE);
 end else
 begin

  cur:=vm_nt_entry_splay(address,cur);
  map^.root:=cur;

  if (address>=cur^.start) then
  begin
   entry^:=cur;
   if (cur^.__end>address) then
   begin
    Exit(TRUE);
   end;
  end else
  begin
   entry^:=cur^.prev;
  end;
 end;
 Result:=(FALSE);
end;

function vm_nt_map_simplify_entry(map:p_vm_nt_map;entry:p_vm_nt_entry;var sb:t_range_stat):Boolean; forward;

function _vm_nt_map_insert(
           map   :p_vm_nt_map;
           obj   :p_vm_nt_file_obj;
           offset:vm_ooffset_t;
           start :vm_offset_t;
           __end :vm_offset_t;
           usize :vm_offset_t; //unaligned size
           prot  :Integer):Integer;
var
 new_entry :p_vm_nt_entry;
 prev_entry:p_vm_nt_entry;
 temp_entry:p_vm_nt_entry;
 stat      :t_range_stat;
begin
 if (start<map^.min_offset) or (__end>map^.max_offset) or (start>=__end) then
 begin
  Exit(KERN_INVALID_ADDRESS);
 end;

 if vm_nt_map_lookup_entry(map,start,@temp_entry) then
 begin
  Exit(KERN_NO_SPACE);
 end;

 prev_entry:=temp_entry;

 if (prev_entry^.next<>@map^.header) and
    (prev_entry^.next^.start<__end) then
 begin
  Exit(KERN_NO_SPACE);
 end;

 new_entry:=vm_nt_entry_create(map);
 new_entry^.start :=start;
 new_entry^.__end :=__end;
 new_entry^.usize :=usize; //unaligned size
 new_entry^.obj   :=obj;
 new_entry^.offset:=offset;

 vm_nt_sub_map_init  (@new_entry^.sub,start,__end);

 //fill full map
 vm_nt_sub_map_insert(@new_entry^.sub,start,__end,prot);

 vm_nt_entry_link(map, prev_entry, new_entry);

 vm_map(map,new_entry,prot);

 vm_nt_map_simplify_entry(map,new_entry,stat);

 vm_remap(map,new_entry,nil,nil,stat);

 Result:=KERN_SUCCESS;
end;

function vm_nt_map_insert(
           map   :p_vm_nt_map;
           obj   :p_vm_nt_file_obj;
           offset:vm_ooffset_t;
           start :vm_offset_t;
           __end :vm_offset_t;
           usize :vm_offset_t; //unaligned size
           prot  :Integer):Integer;
begin
 if (start=__end) then
 begin
  Exit(KERN_SUCCESS);
 end;

 vm_nt_map_lock(map);

 Result:=_vm_nt_map_insert(
           map   ,
           obj   ,
           offset,
           start ,
           __end ,
           usize ,
           prot  );

 vm_nt_map_unlock(map);
end;

function vm_nt_map_simplify_entry(map:p_vm_nt_map;entry:p_vm_nt_entry;var sb:t_range_stat):Boolean;
var
 next,prev:p_vm_nt_entry;
 prevsize,esize:vm_size_t;
 stat:t_range_stat;
begin
 vm_init_stat(stat,entry);

 if (stat.obj<>nil) then
 if ((stat.obj^.flags and NT_UNION_OBJ)=0) then
 begin
  sb:=stat;
  Exit(False);
 end;

 if ((stat.rcurr.__end-stat.rcurr.start)>MAX_UNION_SIZE) then
 begin
  sb:=stat;
  Exit(False);
 end;

 prev:=entry^.prev;
 if (prev<>@map^.header) then
 begin
  prevsize:=prev^.__end - prev^.start;
  if (prev^.__end=stat.rcurr.start) and
     (prevsize<=MAX_UNION_SIZE) and
     (prev^.obj=stat.obj) and
     ((prev^.obj=nil) or (prev^.offset + prevsize=entry^.offset))
     then
  begin
   vm_nt_entry_unlink(map, prev);

   stat.rprev.start:=prev^.start;
   stat.rprev.__end:=prev^.__end;

   entry^.start :=prev^.start;
   entry^.offset:=prev^.offset;
   entry^.usize :=entry^.usize+prev^.usize; //unaligned size

   //update (implicitly)
   //entry^.sub.min_offset:=entry^.start;

   //move
   vm_nt_sub_map_move(@entry^.sub,@prev^.sub);

   vm_nt_entry_deallocate(map,prev);
  end;
 end;

 next:=entry^.next;
 if (next<>@map^.header) then
 begin
  esize:=stat.rcurr.__end - entry^.start;
  if (stat.rcurr.__end=next^.start) and
     (esize<=MAX_UNION_SIZE) and
     (next^.obj=stat.obj) and
     ((stat.obj=nil) or (entry^.offset + esize=next^.offset))
     then
  begin
   vm_nt_entry_unlink(map, next);

   stat.rnext.start:=next^.start;
   stat.rnext.__end:=next^.__end;

   entry^.__end:=next^.__end;
   entry^.usize:=entry^.usize+next^.usize; //unaligned size

   //update (implicitly)
   //entry^.sub.max_offset:=entry^.__end;

   //move
   vm_nt_sub_map_move(@entry^.sub,@next^.sub);

   vm_nt_entry_deallocate(map,next);
  end;
 end;

 sb:=stat;
 Result:=True;
end;

procedure vm_nt_map_simplify_entry(map:p_vm_nt_map;entry:p_vm_nt_entry);
var
 stat:t_range_stat;
begin
 vm_nt_map_simplify_entry(map,entry,stat);

 vm_remap(map,entry,nil,nil,stat);
end;

procedure vm_nt_map_clip_start_end(map:p_vm_nt_map;entry:p_vm_nt_entry;start,__end:vm_offset_t);
var
 prev:p_vm_nt_entry;
 next:p_vm_nt_entry;
 stat:t_range_stat;
begin
 prev:=nil;
 next:=nil;

 vm_nt_map_simplify_entry(map,entry,stat);

 //entry[start           ,end]
 //prev [start  |   entry[end]

 if (start>entry^.start) then
 begin
  prev:=vm_nt_entry_create(map);
  prev^:=entry^;

  prev^.__end:=start;
  prev^.usize:=(prev^.__end-prev^.start); //unaligned size

  //new map
  vm_nt_sub_map_init(@prev^.sub,prev^.start,prev^.__end);

  //move
  vm_nt_sub_map_clip(@prev^.sub,@entry^.sub);

  entry^.offset:=entry^.offset + (start - entry^.start);
  entry^.start :=start;
  entry^.usize :=entry^.usize-prev^.usize; //unaligned size

  //update (implicitly)
  //prev ^.sub.max_offset:=start;
  //entry^.sub.min_offset:=start;

  vm_nt_entry_link(map, entry^.prev, prev);
  vm_nt_file_obj_reference(prev^.obj);
 end;

 //entry[start          ,end]
 //entry[start  |   next[end]

 if (__end<entry^.__end) then
 begin
  next:=vm_nt_entry_create(map);
  next^:=entry^;

  next^.start :=__end;

  //new map
  vm_nt_sub_map_init(@next^.sub,next^.start,next^.__end);

  //move
  vm_nt_sub_map_clip(@next^.sub,@entry^.sub);

  entry^.__end:=__end;
  entry^.usize:=(entry^.__end-entry^.start); //unaligned size

  next^.offset:=next^.offset + (__end - entry^.start);
  next^.usize :=next^.usize-entry^.usize; //unaligned size

  //update (implicitly)
  //next ^.sub.min_offset:=__end;
  //entry^.sub.max_offset:=__end;

  vm_nt_entry_link(map, entry, next);
  vm_nt_file_obj_reference(next^.obj);
 end;

 //

 if (prev<>nil) or (next<>nil) then
 begin
  //exclude entry
  vm_nt_file_obj_deallocate(entry^.obj);
  entry^.obj:=nil;
 end;

 vm_remap(map,prev,entry,next,stat);

end;

procedure vm_nt_map_clip_end(map:p_vm_nt_map;entry:p_vm_nt_entry;__end:vm_offset_t);
var
 next:p_vm_nt_entry;
 stat:t_range_stat;
begin
 next:=nil;

 vm_init_stat(stat,entry);

 //

 //entry[start          ,end]
 //entry[start  |   next[end]

 if (__end<entry^.__end) then
 begin
  next:=vm_nt_entry_create(map);
  next^:=entry^;

  next^.start :=__end;

  //new map
  vm_nt_sub_map_init(@next^.sub,next^.start,next^.__end);

  //move
  vm_nt_sub_map_clip(@next^.sub,@entry^.sub);

  entry^.__end:=__end;
  entry^.usize:=(entry^.__end-entry^.start); //unaligned size

  next^.offset:=next^.offset + (__end - entry^.start);
  next^.usize :=next^.usize-entry^.usize; //unaligned size

  //update (implicitly)
  //next ^.sub.min_offset:=__end;
  //entry^.sub.max_offset:=__end;

  vm_nt_entry_link(map, entry, next);
  vm_nt_file_obj_reference(next^.obj);
 end;

 //

 if (next<>nil) then
 begin
  //exclude entry
  vm_nt_file_obj_deallocate(entry^.obj);
  entry^.obj:=nil;
 end;

 vm_remap(map,nil,entry,next,stat);

end;

procedure vm_nt_entry_delete(map:p_vm_nt_map;entry:p_vm_nt_entry); inline;
begin
 vm_nt_entry_unlink    (map, entry);
 vm_nt_entry_deallocate(map, entry);
end;

function vm_nt_map_delete(map:p_vm_nt_map;start:vm_offset_t;__end:vm_offset_t):Integer;
var
 entry      :p_vm_nt_entry;
 first_entry:p_vm_nt_entry;
 next       :p_vm_nt_entry;
begin
 if (start=__end) then
 begin
  Exit(KERN_SUCCESS);
 end;

 vm_nt_map_lock(map);

 if (not vm_nt_map_lookup_entry(map, start, @first_entry)) then
 begin
  entry:=first_entry^.next;

 end else
 begin
  entry:=first_entry;

  vm_nt_map_clip_start_end(map, entry, start, __end);
 end;

 while (entry<>@map^.header) and (entry^.start<__end) do
 begin

  vm_nt_map_clip_end(map, entry, __end);

  next:=entry^.next;

  vm_unmap(map,entry);

  vm_nt_entry_delete(map, entry);

  entry:=next;
 end;

 vm_nt_map_unlock(map);

 Result:=(KERN_SUCCESS);
end;

procedure vm_nt_map_protect(map  :p_vm_nt_map;
                            start:vm_offset_t;
                            __end:vm_offset_t;
                            prot :Integer);
var
 entry:p_vm_nt_entry;
 e_start:vm_offset_t;
 e___end:vm_offset_t;
 max:Integer;
begin
 if (start=__end) then Exit;

 vm_nt_map_lock(map);

 if (not vm_nt_map_lookup_entry(map, start, @entry)) then
 begin
  entry:=entry^.next;
 end else
 begin
  //
 end;

 while (entry<>@map^.header) and (entry^.start<__end) do
 begin
  e_start:=entry^.start;
  e___end:=entry^.__end;

  if (e_start<start) then
  begin
   e_start:=start;
  end;

  if (e___end>__end) then
  begin
   e___end:=__end;
  end;

  if (e___end>e_start) then
  begin

   if (entry^.obj<>nil) then
   begin
    max:=entry^.obj^.maxp;
   end else
   begin
    max:=0;
   end;

   vm_nt_sub_map_protect(@entry^.sub,e_start,e___end,(prot and max and VM_RW));
  end;

  entry:=entry^.next;
 end;

 vm_nt_map_unlock(map);
end;

procedure vm_nt_map_tracking(map  :p_vm_nt_map;
                             start:vm_offset_t;
                             __end:vm_offset_t;
                             prot :Integer);
var
 entry:p_vm_nt_entry;
 e_start:vm_offset_t;
 e___end:vm_offset_t;
begin
 if (start=__end) then Exit;

 vm_nt_map_lock(map);

 if (not vm_nt_map_lookup_entry(map, start, @entry)) then
 begin
  entry:=entry^.next;
 end else
 begin
  //
 end;

 while (entry<>@map^.header) and (entry^.start<__end) do
 begin
  e_start:=entry^.start;
  e___end:=entry^.__end;

  if (e_start<start) then
  begin
   e_start:=start;
  end;

  if (e___end>__end) then
  begin
   e___end:=__end;
  end;

  if (e___end>e_start) then
  begin
   vm_nt_sub_map_tracking(@entry^.sub,e_start,e___end,prot);
  end;

  entry:=entry^.next;
 end;

 vm_nt_map_unlock(map);
end;




procedure vm_nt_map_prot_fix(map  :p_vm_nt_map;
                             start:vm_offset_t;
                             __end:vm_offset_t;
                             mode :Integer);
var
 entry:p_vm_nt_entry;
 e_start:vm_offset_t;
 e___end:vm_offset_t;
begin
 if (start=__end) then Exit;

 vm_nt_map_lock(map);

 if (not vm_nt_map_lookup_entry(map, start, @entry)) then
 begin
  entry:=entry^.next;
 end else
 begin
  entry:=entry;
 end;

 while (entry<>@map^.header) and (entry^.start<__end) do
 begin

  if (entry^.obj<>nil) then
  begin
   e_start:=entry^.start;
   e___end:=entry^.__end;

   if (e_start<start) then
   begin
    e_start:=start;
   end;

   if (e___end>__end) then
   begin
    e___end:=__end;
   end;

   if (e___end>e_start) then
   begin
    vm_nt_sub_map_prot_fixup(@entry^.sub,e_start,e___end,mode);
   end;
  end;

  entry:=entry^.next;
 end;

 vm_nt_map_unlock(map);
end;

//rdi, rsi
procedure ZeroPages(addr:Pointer;size:Ptruint); assembler nostackframe SysV_ABI_CDecl;
label
 _exit,
 _rep;
asm
 shr $5, %rsi // div 32
 jz _exit

  vpxor %ymm0, %ymm0, %ymm0 //zero

  _rep:

   vmovaps %ymm0, (%rdi)

   lea 32(%rdi),%rdi
   dec %rsi

  jnz _rep

 _exit:
end;

procedure vm_nt_map_madvise(map   :p_vm_nt_map;
                            start :vm_offset_t;
                            __end :vm_offset_t;
                            advise:Integer);
var
 entry:p_vm_nt_entry;
 base,size:vm_size_t;
 mirror:Pointer;
begin
 if (start=__end) then Exit;

 vm_nt_map_lock(map);

 if (not vm_nt_map_lookup_entry(map, start, @entry)) then
 begin
  entry:=entry^.next;
 end else
 begin
  entry:=entry;
 end;

 while (entry<>@map^.header) and (entry^.start<__end) do
 begin
  base:=entry^.start;
  size:=entry^.__end;

  if (base<start) then
  begin
   base:=start;
  end;

  if (size>__end) then
  begin
   size:=__end;
  end;

  size:=size-base;

  case advise of
   MADV_WILLNEED:md_activate(Pointer(base),size);
   //
   MADV_DONTNEED:md_dontneed(Pointer(base),size);
   MADV_FREE    :md_dontneed(Pointer(base),size);
   //
   MADV_NORMAL: //internal only
    if (md_activate(Pointer(base),size)=0) then
    begin
     //page is restored, zero it

     mirror:=vm_nt_map_mirror(map,base,base+size);
     if (mirror<>nil) then
     begin
      ZeroPages  (mirror,size);
      md_unmap_ex(mirror,size);
     end;

    end;
   else;
  end;

  //ignore errors

  entry:=entry^.next;
 end;

 vm_nt_map_unlock(map);
end;


function vm_nt_map_mirror(map  :p_vm_nt_map;
                          start:vm_offset_t;
                          __end:vm_offset_t):Pointer;
var
 entry:p_vm_nt_entry;
 base,b_end,size,prev:vm_size_t;
 offset:vm_ooffset_t;
 curr:Pointer;
 obj:p_vm_nt_file_obj;
 max:Integer;
 r:Integer;
begin
 Result:=nil;
 if (start=__end) then Exit;

 r:=md_reserve_ex(Result,__end-start);
 if (r<>0) then
 begin
  Writeln('failed md_reserve_ex(',HexStr(__end-start,11),'):0x',HexStr(r,8));
  Assert(false,'vm_map');
  Exit;
 end;

 vm_nt_map_lock(map);

 if (not vm_nt_map_lookup_entry(map, start, @entry)) then
 begin
  entry:=entry^.next;
 end else
 begin
  entry:=entry;
 end;

 prev:=0;

 while (entry<>@map^.header) and (entry^.start<__end) do
 begin
  obj:=entry^.obj;

  if (obj<>nil) then
  if (obj^.hfile<>0) then
  begin
   base  :=entry^.start;
   b_end :=entry^.__end;
   offset:=entry^.offset;

   if (base<start) then
   begin
    base:=start;
    offset:=offset+(start-base);
   end;

   if (b_end>__end) then
   begin
    b_end:=__end;
   end;

   size:=b_end-base;

   //addr in mirror
   curr:=Result+(base-start);

   if ((base<>start) and (base<>prev)) or
      (b_end<>__end) then
   begin
    r:=md_split(curr,size);
    if (r<>0) then
    begin
     Writeln('failed md_split(',HexStr(curr),',',HexStr(curr+size),'):0x',HexStr(r,8));
     Assert(false,'vm_map');
    end;
   end;

   prev:=b_end;

   max:=obj^.maxp;

   r:=md_file_mmap_ex(obj^.hfile,
                      curr,
                      offset,
                      size,
                      (max and VM_RW));
   if (r<>0) then
   begin
    Writeln('failed md_file_mmap_ex(',HexStr(curr),',',HexStr(curr+size),'):0x',HexStr(r,8));
    Assert(false,'vm_map');
   end;

  end;

  entry:=entry^.next;
 end;

 vm_nt_map_unlock(map);
end;



end.


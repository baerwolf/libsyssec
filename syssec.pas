unit syssec;
{ syssec.pas                                           Version 20240224Z2320SB }
{ This Unit enabled extra security under linux by disabling unneeded syscalls. }
{ by S. Bärwolf, Rudolstadt 2024                                               }



{$mode objfpc}{$H+}

interface
uses
  Classes, SysUtils, cTypes;

const
  version             = '20240224Z2320SB';
  syssecLibName       = 'libsyssec';


type
    ESyssecException             = Class(Exception);

    Tsyssec_initialize           = function : cint; cdecl;
    Tsyssec_finalize             = function : cint; cdecl;
    Tsyssec_version              = function : PChar; cdecl;
    Tsyssec_install              = function(bpfprog : pointer) : cint; cdecl;
    Tsyssec_installEx            = function(bpfprog : pointer; newprivs : cbool) : cint; cdecl;
    Tsyssec_getBuildArch         = function : cint; cdecl;
    Tsyssec_syscallname          = function(SYS_nr : clong) : PChar; cdecl;
    Tsyssec_syscallnr            = function(SYS_name : PChar) : clong; cdecl;
    Tsyssec_allocateprog         = function : pointer; cdecl;
    Tsyssec_freeprog             = procedure(bpfprog : pointer); cdecl;
    Tsyssec_freebpf              = procedure(bpfprog : pointer); cdecl;
    Tsyssec_buildbpf             = function(bpfprog : pointer; SYS_list : pclong; supported_arch : cint; seccompreturn : cint) : cint; cdecl;
    Tsyssec_buildbpfEx           = function(bpfprog : pointer; SYS_list : pclong; supported_arch : cint; seccompreturn : cint; rejectlast : cbool) : cint; cdecl;
    Tsyssec_bpf_add_opcode       = function(bpfprog : pointer) : cint; cdecl;
    Tsyssec_combinebpf           = function(appended_to : pointer; appended_from : pointer; skip_header : cbool) :cint; cdecl;
    Tsyssec_SECCOMP_RET_ERRNO    = function(returncode : cuint16) : cint; cdecl;
    Tsyssec_SECCOMP_RET_TRAP     = function(returncode : cuint16) : cint; cdecl;
    Tsyssec_SECCOMP_RET_ERRNO_EPERM = function : cint; cdecl; 
    Tsyssec_SECCOMP_RET_KILL_PROCESS = function : cint; cdecl;



var
    EXIT_FAILURE                : cint                         = -1;
    EXIT_SUCCESS                : cint                         = 0;
    syssec_initialize           : Tsyssec_initialize           = Nil;
    syssec_finalize             : Tsyssec_finalize             = Nil;
    syssec_version              : Tsyssec_version              = Nil;
    syssec_install              : Tsyssec_install              = Nil;
    syssec_installEx            : Tsyssec_installEx            = Nil;
    syssec_getBuildArch         : Tsyssec_getBuildArch         = Nil;
    syssec_syscallname          : Tsyssec_syscallname          = Nil;
    syssec_syscallnr            : Tsyssec_syscallnr            = Nil;
    syssec_allocateprog         : Tsyssec_allocateprog         = Nil;
    syssec_freeprog             : Tsyssec_freeprog             = Nil;
    syssec_freebpf              : Tsyssec_freebpf              = Nil;
    syssec_buildbpf             : Tsyssec_buildbpf             = Nil;
    syssec_buildbpfEx           : Tsyssec_buildbpfEx           = Nil;
    syssec_bpf_add_opcode       : Tsyssec_bpf_add_opcode       = Nil;
    syssec_combinebpf           : Tsyssec_combinebpf           = Nil;
    syssec_SECCOMP_RET_ERRNO    : Tsyssec_SECCOMP_RET_ERRNO    = Nil;
    syssec_SECCOMP_RET_TRAP     : Tsyssec_SECCOMP_RET_TRAP     = Nil;
    syssec_SECCOMP_RET_ERRNO_EPERM:Tsyssec_SECCOMP_RET_ERRNO_EPERM=Nil;
    syssec_SECCOMP_RET_KILL_PROCESS:Tsyssec_SECCOMP_RET_KILL_PROCESS=Nil;

function CheckEntryPoints : boolean;

implementation

uses
  dynlibs;

var
  syssec_enabled : boolean = false;
  hlib           : tlibhandle;


function CheckEntryPoints : boolean;
begin
  result:=true;
  if (result) then result:=Assigned(syssec_initialize);
  if (result) then result:=Assigned(syssec_finalize);
  if (result) then result:=Assigned(syssec_version);
  if (result) then result:=Assigned(syssec_install);
  if (result) then result:=Assigned(syssec_installEx);
  if (result) then result:=Assigned(syssec_getBuildArch);
  if (result) then result:=Assigned(syssec_syscallname);
  if (result) then result:=Assigned(syssec_syscallnr);
  if (result) then result:=Assigned(syssec_allocateprog);
  if (result) then result:=Assigned(syssec_freeprog);
  if (result) then result:=Assigned(syssec_freebpf);
  if (result) then result:=Assigned(syssec_buildbpf);
  if (result) then result:=Assigned(syssec_buildbpfEx);
  if (result) then result:=Assigned(syssec_bpf_add_opcode);
  if (result) then result:=Assigned(syssec_combinebpf);
  if (result) then result:=Assigned(syssec_SECCOMP_RET_ERRNO);
  if (result) then result:=Assigned(syssec_SECCOMP_RET_TRAP);
  if (result) then result:=Assigned(syssec_SECCOMP_RET_ERRNO_EPERM);
  if (result) then result:=Assigned(syssec_SECCOMP_RET_KILL_PROCESS);
end;

Procedure CleanEntryPoints;
begin
  syssec_initialize           :=NiL;
  syssec_finalize             :=Nil;
  syssec_version              :=Nil;
  syssec_install              :=NiL;
  syssec_installEx            :=Nil;
  syssec_getBuildArch         :=NiL;
  syssec_syscallname          :=Nil;
  syssec_syscallnr            :=NiL;
  syssec_allocateprog         :=Nil;
  syssec_freeprog             :=NiL;
  syssec_freebpf              :=Nil;
  syssec_buildbpf             :=NiL;
  syssec_buildbpfEx           :=Nil;
  syssec_bpf_add_opcode       :=NiL;
  syssec_combinebpf           :=Nil;
  syssec_SECCOMP_RET_ERRNO    :=NiL;
  syssec_SECCOMP_RET_TRAP     :=Nil;
  syssec_SECCOMP_RET_ERRNO_EPERM:=Nil;
  syssec_SECCOMP_RET_KILL_PROCESS:=Nil;
end;

procedure FreeSyssec;
begin
  if (hlib <> dynlibs.NilHandle) then FreeLibrary(hlib);
  hlib:=dynlibs.NilHandle;
  CleanEntryPoints();
end;


Procedure LoadEntryPoints;
begin
  syssec_initialize           :=Tsyssec_initialize           (GetProcAddress(hlib,'syssec_initialize'));
  syssec_finalize             :=Tsyssec_finalize             (GetProcAddress(hlib,'syssec_finalize'));
  syssec_version              :=Tsyssec_version              (GetProcAddress(hlib,'syssec_version'));
  syssec_install              :=Tsyssec_install              (GetProcAddress(hlib,'syssec_install'));
  syssec_installEx            :=Tsyssec_installEx            (GetProcAddress(hlib,'syssec_installEx'));
  syssec_getBuildArch         :=Tsyssec_getBuildArch         (GetProcAddress(hlib,'syssec_getBuildArch'));
  syssec_syscallname          :=Tsyssec_syscallname          (GetProcAddress(hlib,'syssec_syscallname'));
  syssec_syscallnr            :=Tsyssec_syscallnr            (GetProcAddress(hlib,'syssec_syscallnr'));
  syssec_allocateprog         :=Tsyssec_allocateprog         (GetProcAddress(hlib,'syssec_allocateprog'));
  syssec_freeprog             :=Tsyssec_freeprog             (GetProcAddress(hlib,'syssec_freeprog'));
  syssec_freebpf              :=Tsyssec_freebpf              (GetProcAddress(hlib,'syssec_freebpf'));
  syssec_buildbpf             :=Tsyssec_buildbpf             (GetProcAddress(hlib,'syssec_buildbpf'));
  syssec_buildbpfEx           :=Tsyssec_buildbpfEx           (GetProcAddress(hlib,'syssec_buildbpfEx'));
  syssec_bpf_add_opcode       :=Tsyssec_bpf_add_opcode       (GetProcAddress(hlib,'syssec_bpf_add_opcode'));
  syssec_combinebpf           :=Tsyssec_combinebpf           (GetProcAddress(hlib,'syssec_combinebpf'));
  syssec_SECCOMP_RET_ERRNO    :=Tsyssec_SECCOMP_RET_ERRNO    (GetProcAddress(hlib,'syssec_SECCOMP_RET_ERRNO'));
  syssec_SECCOMP_RET_TRAP     :=Tsyssec_SECCOMP_RET_TRAP     (GetProcAddress(hlib,'syssec_SECCOMP_RET_TRAP'));
  syssec_SECCOMP_RET_ERRNO_EPERM:=Tsyssec_SECCOMP_RET_ERRNO_EPERM(GetProcAddress(hlib,'syssec_SECCOMP_RET_ERRNO_EPERM'));
  syssec_SECCOMP_RET_KILL_PROCESS:=Tsyssec_SECCOMP_RET_KILL_PROCESS(GetProcAddress(hlib,'syssec_SECCOMP_RET_KILL_PROCESS'));
end;

procedure LoadSyssec;
var
  s: ansistring;
begin
  FreeSyssec;
  {$if defined(linux)}
    if (hlib = dynlibs.NilHandle) then hlib := LoadLibrary('/opt/baerwolf/'+syssecLibName+'.'+SharedSuffix);
    if (hlib = dynlibs.NilHandle) then
      begin
        s:=GetEnvironmentVariable('HOME');
        if (s<>'') then hlib := LoadLibrary(s+'/local/opt/baerwolf/'+syssecLibName+'.'+SharedSuffix);
      end;
    if (hlib = dynlibs.NilHandle) then hlib := LoadLibrary('./'+syssecLibName+'.'+SharedSuffix);
    if (hlib = dynlibs.NilHandle) then raise ESyssecException.Create('unable to load "'+syssecLibName+'.'+SharedSuffix+'" !');
  {$else}
    //libsyssec is only supported on linux - raise exception on all other systems
    raise ESyssecException.Create('unsupported operating system - "'+syssecLibName+'.'+SharedSuffix+'" not available!');
  {$endif}

  LoadEntryPoints();
end;


function InitSyssecInterface: Boolean;
begin
  if (NOT(syssec_enabled)) then
    begin
      LoadSyssec();
      if (hlib <> dynlibs.NilHandle) then
        if (CheckEntryPoints()) then
          begin
            EXIT_FAILURE:=syssec_finalize();
            EXIT_SUCCESS:=syssec_initialize();
            syssec_enabled:=(EXIT_SUCCESS<>EXIT_FAILURE);
          end;
    end;
  if (NOT(syssec_enabled)) then raise ESyssecException.Create('syssec not properly initialized !');
  result:=syssec_enabled;
end;

procedure CleanupExtra;
begin
  FreeSyssec();
  syssec_enabled:=false;
end;

procedure InstallDefaultFilter;
var
    i          : cint;
    SYSCALLEOL : clong;
    syscalls   : array[0..15] of clong;
    prog       : pointer;
    problems   : ESyssecException;

begin
  i:=0;
  problems:=Nil;
  SYSCALLEOL:=syssec_syscallnr('SYSCALLEOL');
  syscalls[i]:=syssec_syscallnr('SYS_execve');      if (syscalls[i]<>SYSCALLEOL) then inc(i);
  syscalls[i]:=syssec_syscallnr('SYS_unshare');     if (syscalls[i]<>SYSCALLEOL) then inc(i);
  syscalls[i]:=syssec_syscallnr('SYS_setns');       if (syscalls[i]<>SYSCALLEOL) then inc(i);
  syscalls[i]:=syssec_syscallnr('SYS_setpriority'); if (syscalls[i]<>SYSCALLEOL) then inc(i);
  syscalls[i]:=SYSCALLEOL;
  if (i=4) then
    begin
      prog:=syssec_allocateprog();
      if Assigned(prog) then
        begin
          i:=syssec_buildbpf(prog, @syscalls, syssec_getBuildArch(), syssec_SECCOMP_RET_ERRNO_EPERM());
          if (i=EXIT_SUCCESS)then
            begin
              if (syssec_install(prog)<>EXIT_SUCCESS) then
                begin
                  problems:=ESyssecException.Create('syssec_install failed - syssec aborted!');
                end;
            end              else problems:=ESyssecException.Create('syssec_buildbpf failed - syssec aborted!');
          syssec_freeprog(prog);
        end             else problems:=ESyssecException.Create('syssec_allocateprog failed - syssec aborted!');
    end    else problems:=ESyssecException.Create('syssec-filter incomplete - syssec aborted!');

  if Assigned(problems) then raise problems;
end;

initialization
  if (InitSyssecInterface()) then
    begin
{$IFNDEF CONFIG_SYSSEC_NODEFAULTFILTER}
      InstallDefaultFilter();
{$ENDIF}
    end;

finalization
 if Assigned(syssec_finalize) then syssec_finalize();
 CleanupExtra();

end.


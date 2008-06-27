// LightWeight Delphi Library For MySQL.
// Copyright (C) 2008 Miroslav Marchev

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

unit SockClient;

interface

uses Windows;

// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //

type
  u_int    = Integer;
  u_short  = Word;
  u_long   = Longint;

  WSAEVENT = THandle;
  TSocket  = u_int;

const
  WSADESCRIPTION_LEN = 256;
  WSASYS_STATUS_LEN  = 128;

  AF_INET     = 2;
  SOCK_STREAM = 1;
  FIONBIO     = $8004667e;

  SOCKET_ERROR      = -1;
  WSA_INVALID_EVENT = WSAEVENT(nil);
  INVALID_SOCKET    = TSocket(not(0));
  INADDR_NONE       = $FFFFFFFF;
  WSABASEERR        = 10000;
  WSAEWOULDBLOCK    = (WSABASEERR + 35);

  FD_CONNECT = $10;
  FD_WRITE   = $02;
  FD_READ    = $01;
  FD_CLOSE   = $20;

  SD_SEND    = $01;

type
  PInAddr = ^TInAddr;
  TInAddr = packed record
    case Integer of
      0: (S_bytes: packed array [0..3] of Byte);
      1: (S_addr: u_long);
  end;

  TSockAddrIn = packed record
    case Integer of
      0: (sin_family: u_short;
          sin_port: u_short;
          sin_addr: TInAddr;
          sin_zero: array[0..7] of Char);
      1: (sa_family: u_short;
          sa_data: array[0..13] of Char)
  end;

  TSockAddr = TSockAddrIn;
  PSockAddr = ^TSockAddr;

  TWSAData = packed record
    wVersion: Word;
    wHighVersion: Word;
    szDescription: array[0..WSADESCRIPTION_LEN] of Char;
    szSystemStatus: array[0..WSASYS_STATUS_LEN] of Char;
    iMaxSockets: Word;
    iMaxUdpDg: Word;
    lpVendorInfo: PChar;
  end;

  PHostEnt = ^THostEnt;
  THostEnt = packed record
    h_name: PChar;
    h_aliases: ^PChar;
    h_addrtype: Smallint;
    h_length: Smallint;
    case Integer of
     0: (h_addr_list: ^PChar);
     1: (h_addr: ^PInAddr);
  end;

type
  TWSAStartup = function(wVersionRequested: Word; var lpWSAData: TWSAData): Integer; stdcall;
  TWSACleanup = function: Integer; stdcall;
  TWSAGetLastError = function: Integer; stdcall;
  TTSocket = function(af, _type, protocol: Integer): TSocket; stdcall;
  TIoctlSocket = function(s: TSocket; cmd: DWORD; var argp: Integer): Integer; stdcall;
  TConnect = function(s: TSocket; name: PSockAddr; namelen: Integer): Integer; stdcall;
  TSend = function(s: TSocket; const buf; len, flags: Integer): Integer; stdcall;
  TRecv = function(s: TSocket; var buf; len, flags: Integer): Integer; stdcall;
  TShutdown = function(s: TSocket; how: Integer): Integer; stdcall;
  TCloseSocket = function(s: TSocket): Integer; stdcall;
  TWSACreateEvent = function: WSAEVENT; stdcall;
  TWSAEventSelect = function(s: TSOCKET; hEventObject: WSAEVENT;
    lNetworkEvents: u_long): u_int; stdcall;
  TWSACloseEvent = function(hEvent: WSAEVENT):BOOL; stdcall;
  Thtons = function(hostshort: u_short): u_short; stdcall;
  TInet_addr = function(cp: PChar): u_long; stdcall;
  TGetHostByName = function(name: PChar): PHostEnt; stdcall;

const
  LIB_WIN_SOCK           = 'ws2_32.dll';

  FUN_WSA_STARTUP        = 'WSAStartup';
  FUN_WSA_CLEANUP        = 'WSACleanup';
  FUN_WSA_GET_LAST_ERROR = 'WSAGetLastError';
  FUN_SOCKET             = 'socket';
  FUN_IO_CTL_SOCKET      = 'ioctlsocket';
  FUN_CONNECT            = 'connect';
  FUN_SEND               = 'send';
  FUN_RECV               = 'recv';
  FUN_SHUTDOWN           = 'shutdown';
  FUN_CLOSE_SOCKET       = 'closesocket';
  FUN_WSA_CREATE_EVENT   = 'WSACreateEvent';
  FUN_WSA_EVENT_SELECT   = 'WSAEventSelect';
  FUN_WSA_CLOSE_EVENT    = 'WSACloseEvent';
  FUN_HTONS              = 'htons';
  FUN_INET_ADDR          = 'inet_addr';
  FUN_GET_HOST_BY_NAME   = 'gethostbyname';

// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //

const
  INET_BUFF_LEN = 4096;
  CHUN_BUFF_LEN = 1024;
  TROTTLE_WAIT  = 10;
  PROBE_WAIT    = 0;
  SOCK_NO_ERROR = 0;

type
  // Custom Buffers
  TBufferRec = record
    Buffer  : Pointer; // Buffer Pointer
    Length  : Integer; // Alloc Buffer Len
    Actual  : Integer; // Actual Data Len
    Initial : Integer; // Initial Buffer Len
  end;

  // Event Stuff
  THandleArray = array of THandle;

type
  TSockClient = class
  private
    FSocket     : TSocket;
    FChunkBuff  : TBufferRec;
    FDocument   : TBufferRec;
    FEventArray : THandleArray;
    FTimeout    : Integer;
    FTargetHost : string;
    FTargetPort : Word;

    // Check Class Init
    function CheckInit: Boolean;
    function CheckSocket: Boolean;
    // Timeout Control
    function TimerStart(Timeout: Integer): Boolean;
    procedure TimerAbort;
    // Socket Stuff
    function SocketConnect: Boolean;
    function SocketWrite: Boolean;
    function SocketRead: Boolean;
    procedure SocketClose;
    // Read Document Result
    function GetDocument: string;
  public
    constructor Create;
    destructor Destroy; override;

    // Simple Request Routines
    function SocketRequest(const Request: string): Boolean;
    function SocketError: Integer;
    procedure SocketAbort;

    property Timeout: Integer read FTimeout write FTimeout;
    property TargetHost: string read FTargetHost write FTargetHost;
    property TargetPort: Word read FTargetPort write FTargetPort;
    property Document: string read GetDocument;
  end;

  // Buffer Routines
  procedure ResizeBuffer(var BufferRec: TBufferRec; Needed: Integer; Initial: Integer = 0);
  procedure WriteBuffer(var BufferRec: TBufferRec; const BuffData: string; WritePos: Integer = 0); overload;
  procedure WriteBuffer(var BufferRec, ChunkBuff: TBufferRec; WritePos: Integer = 0); overload;
  function ReadBuffer(BufferRec: TBufferRec; ChunkSize: Integer; ChunkPos: Integer = 0): string;

  // Loader Routines
  function LoadLib(var LibHandle: THandle; const LibName: string): Boolean;
  function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC; const FuncName: string): Boolean;
  function ReleaseLib(var LibHandle: THandle): Boolean;

  function InitLib: Boolean;
  procedure FreeLib;

var
  IsWinSockOk : Boolean;
  WSAData     : TWSAData;

  WSLibHandle : THandle = 0;

  WSAStartup: TWSAStartup = nil;
  WSACleanup: TWSACleanup = nil;
  WSAGetLastError: TWSAGetLastError = nil;
  socket: TTSocket = nil;
  ioctlsocket: TIoctlSocket = nil;
  connect: TConnect = nil;
  send: TSend = nil;
  recv: TRecv = nil;
  shutdown: TShutdown = nil;
  closesocket: TCloseSocket = nil;
  WSACreateEvent: TWSACreateEvent = nil;
  WSAEventSelect: TWSAEventSelect = nil;
  WSACloseEvent: TWSACloseEvent = nil;
  htons: Thtons = nil;
  inet_addr: TInet_addr = nil;
  gethostbyname: TGetHostByName = nil;

implementation

uses SysUtils;

{ TSockClient }

constructor TSockClient.Create;
begin
  inherited Create;

  SetLength(FEventArray, 2);
  FEventArray[0] := CreateWaitableTimer(nil, True, nil);
  FEventArray[1] := WSA_INVALID_EVENT;

  ResizeBuffer(FDocument, INET_BUFF_LEN, INET_BUFF_LEN);
  ResizeBuffer(FChunkBuff, CHUN_BUFF_LEN, CHUN_BUFF_LEN);

  FTimeout := 60000;
  FSocket := INVALID_SOCKET;
  FTargetHost := '127.0.0.1';
  FTargetPort := 0;
end;

destructor TSockClient.Destroy;
begin
  // Force Request Abort
  SocketAbort;
  // Destroy Socket, Events
  SocketClose;

  // Release Events
  CloseHandle(FEventArray[0]);
  SetLength(FEventArray, 0);

  // Free Buffers
  ResizeBuffer(FDocument, 0);
  ResizeBuffer(FChunkBuff, 0);

  inherited Destroy;
end;

function TSockClient.CheckInit: Boolean;
begin
  try
    Result := False;

    // Check WinSock2 Init
    if (IsWinSockOk = False) then Exit;

    // Check Array
    if (High(FEventArray) <> 1) then Exit;

    // Check Timeout Timer
    if (FEventArray[0] = INVALID_HANDLE_VALUE) or (FEventArray[0] = 0) then Exit;

    // Check Timeout;
    if (FTimeout <= 0) then Exit;

    // Check Connect Settings
    if (Length(Trim(FTargetHost)) <= 0) or (FTargetPort <= 0) then Exit;

    // Check Buffers
    if (Assigned(FDocument.Buffer) = False) or (FDocument.Length <= 0) then Exit;
    if (Assigned(FChunkBuff.Buffer) = False) or (FChunkBuff.Length <= 0) then Exit;

    Result := True;
  except
    Result := False;
  end;
end;

function TSockClient.CheckSocket: Boolean;
begin
  try
    Result := False;

    // Check Socket
    if (FSocket = INVALID_SOCKET) or (FSocket = 0) then Exit;

    // Check Async Socket Event
    if (FEventArray[1] = WSA_INVALID_EVENT) or (FEventArray[1] = 0) then Exit;

    Result := True;
  except
    Result := False;
  end;
end;

function TSockClient.TimerStart(Timeout: Integer): Boolean;
var
  TimerDue : LARGE_INTEGER;

begin
  try
    // Set Timeout
    TimerDue.QuadPart := -10000000 * (Timeout div 1000);
    // Start Timeout Timer
    Result := SetWaitableTimer(FEventArray[0], TLargeInteger(TimerDue), 0, nil, nil, False);
  except
    Result := False;
  end;
end;

procedure TSockClient.TimerAbort;
begin
  try
    // Reset Timer Abort All
    CancelWaitableTimer(FEventArray[0]);
  except
    //
  end;
end;

function TSockClient.SocketConnect: Boolean;
var
  argp     : Longint;
  SockAddr : TSockAddr;
  HostEnt  : PHostEnt;
  SockRes  : Integer;

begin
  try
    Result := False;

    // Get Socket
    FSocket := socket(AF_INET, SOCK_STREAM, 0);
    // Create Async Event
    FEventArray[1] := WSACreateEvent;

    // Just To Be Sure
    if CheckSocket then
    begin
      // Enable Non Block Mode
      argp := 1;

      // Check Results To Be Sure
      if (ioctlsocket(FSocket, FIONBIO, argp) = SOCK_NO_ERROR) then
      begin
        // Connect To Target Machine
        SockAddr.sin_port := htons(FTargetPort);
        SockAddr.sa_family := AF_INET;
        // Make More Bullet Proof
        SockAddr.sin_addr.S_addr := inet_addr(PChar(FTargetHost));
        if (SockAddr.sin_addr.S_addr = u_long(INADDR_NONE)) then
        begin
          HostEnt := gethostbyname(PChar(FTargetHost));
          SockAddr.sin_addr.S_addr := LongInt(PLongint(HostEnt.h_addr_list^)^);
        end;

        SockRes := connect(FSocket, @SockAddr, SizeOf(SockAddr));

        // Check Return Values To Be Sure
        if (SockRes = SOCKET_ERROR) and (SocketError = WSAEWOULDBLOCK) then
        begin
          // Attach Event
          WSAEventSelect(FSocket, FEventArray[1], FD_CONNECT);
          try
            // Success On Connect Event Fail On Timer Elapse
            Result := (WaitForMultipleObjects(2, Pointer(FEventArray), False, INFINITE)
              = (WAIT_OBJECT_0 + 1));
          finally
            // Detach Event
            WSAEventSelect(FSocket, FEventArray[1], 0);
          end;
        end;
      end;
    end;
  except
    Result := False;
  end;
end;

function TSockClient.SocketWrite: Boolean;
var
  BytesSent  : Integer;
  BytesTotal : Integer;

begin
  try
    Result := False;
    // Total Bytes Recieved
    BytesTotal := 0;

    // Attach Event
    WSAEventSelect(FSocket, FEventArray[1], FD_WRITE);
    try
      // Check Request Length
      if (FDocument.Actual > 0) then
      begin
        // SlowDown Do Not Drain CPU. Watch For Abort
        while (WaitForSingleObject(FEventarray[0], TROTTLE_WAIT) = WAIT_TIMEOUT) do
        begin
          // Only Probe Event
          if (WaitForSingleObject(FEventArray[1], PROBE_WAIT) = WAIT_OBJECT_0) then
          begin
            // Send Always Right Data
            BytesSent := send(FSocket, Pointer(DWORD(FDocument.Buffer) + DWORD(BytesTotal))^,
              (FDocument.Actual - BytesTotal), 0);
            // Caclulate Total Bytes Send
            Inc(BytesTotal, BytesSent);

            // Stop When Done
            if ((BytesSent = SOCKET_ERROR) and (SocketError <> WSAEWOULDBLOCK))
              or (BytesSent = 0) then
            begin
              Break;
            end;
          end;
        end;

        // Check Send All
        Result := (BytesTotal >= FDocument.Actual);
      end;
    finally
      // Detach Event
      WSAEventSelect(FSocket, FEventArray[1], 0);
    end;
  except
    Result := False;
  end;
end;

function TSockClient.SocketRead: Boolean;
begin
  try
    // Attach Event
    WSAEventSelect(FSocket, FEventArray[1], FD_READ);
    try
      // Reset Output Buffer
      FDocument.Actual := 0;

      // SlowDown Do Not Drain CPU. Watch For Abort
      while (WaitForSingleObject(FEventarray[0], TROTTLE_WAIT) = WAIT_TIMEOUT) do
      begin
        // Only Probe Event
        if (WaitForSingleObject(FEventarray[1], PROBE_WAIT) = WAIT_OBJECT_0) then
        begin
          FChunkBuff.Actual := recv(FSocket, Pointer(FChunkBuff.Buffer)^, FChunkBuff.Length, 0);
          // Check Recieved
          if (FChunkBuff.Actual > 0) then
          begin
            // Move Chunks To Buffer
            WriteBuffer(FDocument, FChunkBuff, FDocument.Actual);
          end;

          // Stop When Done
          if ((FChunkBuff.Actual = SOCKET_ERROR) and (SocketError <> WSAEWOULDBLOCK))
            or (FChunkBuff.Actual = 0) then
          begin
            Break;
          end;
        end;
      end;

      Result := (FDocument.Actual > 0);
    finally
      // Detach Event
      WSAEventSelect(FSocket, FEventArray[1], 0);
    end;
  except
    Result := False;
  end;
end;

procedure TSockClient.SocketClose;
begin
  try
    // Check Socket, Events
    if CheckSocket then
    begin
      // Attach Event
      WSAEventSelect(FSocket, FEventArray[1], FD_CLOSE);
      try
        // Disable Socket Operations
        shutdown(FSocket, SD_SEND);

        // SlowDown Do Not Drain CPU. Watch For Abort
        while (WaitForSingleObject(FEventarray[0], TROTTLE_WAIT) = WAIT_TIMEOUT) do
        begin
          // Only Probe Event
          if (WaitForSingleObject(FEventarray[1], PROBE_WAIT) = WAIT_OBJECT_0) then
          begin
            FChunkBuff.Actual := recv(FSocket, Pointer(FChunkBuff.Buffer)^, FChunkBuff.Length, 0);

            // Stop When Done
            if ((FChunkBuff.Actual = SOCKET_ERROR) and (SocketError <> WSAEWOULDBLOCK))
              or (FChunkBuff.Actual = 0) then
            begin
              Break;
            end;
          end;
        end;
      finally
        // Detach Event
        WSAEventSelect(FSocket, FEventArray[1], 0);
      end;

      // Free Event
      WSACloseEvent(FEventArray[1]);
      // Close Graceful I Hope
      closesocket(FSocket);
    end;

    // Reset To Invalid
    FEventArray[1] := WSA_INVALID_EVENT;
    FSocket := INVALID_SOCKET;
  except
    FSocket := INVALID_SOCKET;
  end;
end;

function TSockClient.SocketRequest(const Request: string): Boolean;
var
  TimerRes: Boolean;

begin
  try
    Result := False;

    // Just To Be Sure
    if CheckInit then
    begin
      // Trigger Timeout Timer
      TimerRes := TimerStart(FTimeout);
      try
        // Check Timer Triggered
        if TimerRes then
        begin
          // Write Request To Buffer
          WriteBuffer(FDocument, Request);

          // Connect To Target Host
          if (SocketConnect = False) then Exit;
          // Send Request
          if (SocketWrite = False) then Exit;
          // Recieve Result
          if (SocketRead = False) then Exit;

          Result := True;
        end;
      finally
        // Disconnect Close Socket
        SocketClose;
        // Abort Timeout Timer
        TimerAbort;
      end;
    end;
  except
    Result := False;
  end;
end;

function TSockClient.SocketError: Integer;
begin
  try
    if IsWinSockOk then
      Result := WSAGetLastError
    else
      Result := WSABASEERR;
  except
    Result := WSABASEERR;
  end;
end;

procedure TSockClient.SocketAbort;
begin
  try
    if CheckInit then
    begin
      TimerAbort;
    end;
  except
    //
  end;
end;

function TSockClient.GetDocument: string;
begin
  if CheckInit then
    Result := ReadBuffer(FDocument, FDocument.Actual)
  else
    Result := '';
end;

// Buffer Routines
procedure ResizeBuffer(var BufferRec: TBufferRec; Needed: Integer; Initial: Integer);
var
  NewSize: Integer;

begin
  try
    // Must Always Init Buffers
    if (Initial > 0) then
    begin
      BufferRec.Buffer := nil;
      BufferRec.Initial := Initial;
      BufferRec.Actual := 0;
      BufferRec.Length := 0;
    end;

    // Must Always Init Buffers
    if (BufferRec.Initial > 0) then
    begin
      // Calculate New Size
      if (Needed > BufferRec.Initial) then
        NewSize := ((Needed div BufferRec.Initial) + 1) * BufferRec.Initial
      else
        NewSize := BufferRec.Initial;

      // Check Needed To Resize
      if (Needed > BufferRec.Length) then
      begin
        ReallocMem(BufferRec.Buffer, NewSize);
        BufferRec.Length := NewSize;
      end;

      // FreeBuffer
      if (Needed = 0) then
      begin
        ReallocMem(BufferRec.Buffer, Needed);
        BufferRec.Actual := 0;
        BufferRec.Length := 0;
      end;
    end;
  except
    BufferRec.Actual := 0;
    BufferRec.Length := 0;
  end;
end;

function ReadBuffer(BufferRec: TBufferRec; ChunkSize: Integer; ChunkPos: Integer = 0): string;
begin
  try
    if Assigned(BufferRec.Buffer) then
    begin
      if (ChunkPos < BufferRec.Actual) and (ChunkSize <= (BufferRec.Actual - ChunkPos)) then
      begin
        SetLength(Result, ChunkSize);
        Move(Pointer(DWORD(BufferRec.Buffer) + DWORD(ChunkPos))^, Pointer(Result)^, ChunkSize);
      end;
    end;
  except
    //
  end;
end;

procedure WriteBuffer(var BufferRec: TBufferRec; const BuffData: string; WritePos: Integer = 0);
var
  NeededLen: Integer;

begin
  try
    if Assigned(BufferRec.Buffer) then
    begin
      // Calculate Buffer Resize
      if ((BufferRec.Length - WritePos) < Length(BuffData)) then
        NeededLen := BufferRec.Length + (Length(BuffData) - (BufferRec.Length - WritePos))
      else
        NeededLen := Length(BuffData);

      // Resize If Needed
      ResizeBuffer(BufferRec, NeededLen);

      // Move Chunk, Adjust Position Marker
      Move(Pointer(BuffData)^, Pointer(DWORD(BufferRec.Buffer) + DWORD(WritePos))^, Length(BuffData));
      BufferRec.Actual := WritePos + Length(BuffData);
    end;
  except
    //
  end;
end;

procedure WriteBuffer(var BufferRec, ChunkBuff: TBufferRec; WritePos: Integer = 0);
var
  NeededLen: Integer;

begin
  try
    if Assigned(BufferRec.Buffer) and Assigned(ChunkBuff.Buffer) then
    begin
      // Calculate Buffer Resize
      if ((BufferRec.Length - WritePos) < ChunkBuff.Actual) then
        NeededLen := BufferRec.Length + (ChunkBuff.Actual - (BufferRec.Length - WritePos))
      else
        NeededLen := ChunkBuff.Actual;

      // Resize If Needed
      ResizeBuffer(BufferRec, NeededLen);

      // Move Chunk, Adjust Position Marker
      Move(Pointer(ChunkBuff.Buffer)^, Pointer(DWORD(BufferRec.Buffer) + DWORD(WritePos))^, ChunkBuff.Actual);
      BufferRec.Actual := WritePos + ChunkBuff.Actual;
    end;
  except
    //
  end;
end;

// Loader Routines
function LoadLib(var LibHandle: THandle; const LibName: string): Boolean;
begin
  LibHandle := 0;

  LibHandle := LoadLibrary(PChar(LibName));
  if (LibHandle <> 0) then
    Result := True
  else
    Result := False;
end;

function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC; const FuncName: string): Boolean;
begin
  FuncPtr := nil;

  if (LibHandle <> 0) then
  begin
    FuncPtr := GetProcAddress(LibHandle, PChar(FuncName));
    if Assigned(FuncPtr) then
      Result := True
    else
      Result := False;
  end
  else
  begin
    Result := False;
  end;
end;

function ReleaseLib(var LibHandle: THandle): Boolean;
begin
  Result := False;

  if (LibHandle <> 0) then
  begin
    Result := FreeLibrary(LibHandle);
    LibHandle := 0;
  end;
end;

function InitLib: Boolean;
begin
  try
    Result := False;

    if (LoadLib(WSLibHandle, LIB_WIN_SOCK) = False) then Exit;
    if (LoadFunc(WSLibHandle, @WSAStartup, FUN_WSA_STARTUP) = False) then Exit;
    if (LoadFunc(WSLibHandle, @WSACleanup, FUN_WSA_CLEANUP) = False) then Exit;
    if (LoadFunc(WSLibHandle, @WSAGetLastError, FUN_WSA_GET_LAST_ERROR) = False) then Exit;
    if (LoadFunc(WSLibHandle, @socket, FUN_SOCKET) = False) then Exit;
    if (LoadFunc(WSLibHandle, @ioctlsocket, FUN_IO_CTL_SOCKET) = False) then Exit;
    if (LoadFunc(WSLibHandle, @connect, FUN_CONNECT) = False) then Exit;
    if (LoadFunc(WSLibHandle, @send, FUN_SEND) = False) then Exit;
    if (LoadFunc(WSLibHandle, @recv, FUN_RECV) = False) then Exit;
    if (LoadFunc(WSLibHandle, @shutdown, FUN_SHUTDOWN) = False) then Exit;
    if (LoadFunc(WSLibHandle, @closesocket, FUN_CLOSE_SOCKET) = False) then Exit;
    if (LoadFunc(WSLibHandle, @WSACreateEvent, FUN_WSA_CREATE_EVENT) = False) then Exit;
    if (LoadFunc(WSLibHandle, @WSAEventSelect, FUN_WSA_EVENT_SELECT) = False) then Exit;
    if (LoadFunc(WSLibHandle, @WSACloseEvent, FUN_WSA_CLOSE_EVENT) = False) then Exit;
    if (LoadFunc(WSLibHandle, @htons, FUN_HTONS) = False) then Exit;
    if (LoadFunc(WSLibHandle, @inet_addr, FUN_INET_ADDR) = False) then Exit;
    if (LoadFunc(WSLibHandle, @gethostbyname, FUN_GET_HOST_BY_NAME) = False) then Exit;

    Result := (WSAStartup(MakeWord(2, 2), WSAData) = 0);
  except
    Result := False;
  end;
end;

procedure FreeLib;
begin
  try
    IsWinSockOk := False;

    WSACleanup;

    WSAStartup := nil;
    WSACleanup := nil;
    WSAGetLastError := nil;
    socket := nil;
    ioctlsocket := nil;
    connect := nil;
    send := nil;
    recv := nil;
    shutdown := nil;
    closesocket := nil;
    WSACreateEvent := nil;
    WSAEventSelect := nil;
    WSACloseEvent := nil;
    htons := nil;
    inet_addr := nil;
    gethostbyname := nil;

    ReleaseLib(WSLibHandle);
  except
    IsWinSockOk := False;
  end;
end;

initialization
  IsWinSockOk := InitLib;

finalization
  FreeLib;

end.

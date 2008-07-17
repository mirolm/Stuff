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
  u_int              = Integer;
  u_short            = Word;
  u_long             = Longint;

  WSAEVENT           = THandle;
  TSocket            = u_int;

const
  WSADESCRIPTION_LEN = 256;
  WSASYS_STATUS_LEN  = 128;

  AF_INET            = 2;
  SOCK_STREAM        = 1;
  IPPROTO_TCP        = 6;
  FIONREAD           = $4004667F;
  FIONBIO            = $8004667E;

  SOCKET_ERROR       = -1;
  WSA_INVALID_EVENT  = WSAEVENT(nil);
  INVALID_SOCKET     = TSocket(not(0));
  INADDR_NONE        = $FFFFFFFF;
  WSABASEERR         = 10000;
  WSAEWOULDBLOCK     = (WSABASEERR + 35);

  FD_CONNECT         = $10;
  FD_WRITE           = $02;
  FD_READ            = $01;
  FD_CLOSE           = $20;

  SD_SEND            = $01;

  SOL_SOCKET         = $FFFF;
  SO_ERROR           = $1007;

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

// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //

type
  TWSAStartup = function(wVersionRequested: Word; var lpWSAData: TWSAData): Integer; stdcall;
  TWSACleanup = function: Integer; stdcall;
  TWSAGetLastError = function: Integer; stdcall;
  TWSASetLastError = procedure(iError: Integer); stdcall;
  TGetSockOpt = function(s: TSocket; level, optname: Integer; optval: PChar;
    var optlen: Integer): Integer; stdcall;
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
  FUN_WSA_SET_LAST_ERROR = 'WSASetLastError';
  FUN_GET_SOCK_OPT       = 'getsockopt';
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
  INET_BUFF_LEN = 1024;      // Buffer Resize Step
  SOCK_MAX_CHUN = 65535;     // Max Packet Size
  TROTTLE_WAIT  = 10;        // Trottle Loop Timeout
  SOCK_NO_ERROR = 0;         // WinSock Success

  SOCKS_VERSION = $04;       // SOCKS4 Protocol Ident
  SOCKS_CONNECT = $01;       // SOCKS4 CONNECT Command
  SOCKS_GRANTED = $5A;       // SOCKS4 Proxy Success
  SOCKS_USER_ID = 'nobody';  // SOCKS4 Default UserId
  SOCKS_HOST    = '0.0.0.1'; // SOCKS4A Default Host

type
  // Custom Buffers
  TBufferRec = packed record
    Buffer   : Pointer; // Buffer Pointer
    Length   : Integer; // Alloc Buffer Len
    Actual   : Integer; // Actual Data Len
    Initial  : Integer; // Initial Buffer Len
  end;

  // SOCKS4 Request Stuff
  TSocksReq = packed record
    Version  : Byte;  // SOCKS Protocol Version
    Cmd      : Byte;  // SOCKS Command
    Port     : Word;  // Network Byte Order Port Number
    HostAddr : DWORD; // Network Byte Order IP Address
  end;

  TSocksResp = packed record
    Zero     : Byte;  // Always $00
    Status   : Byte;  // SOCKS Result Code
    Dummy2   : Word;  // Ignored
    Dummy3   : DWORD; // Ignored
  end;

type
  TSockClient = class
  private
    FSocket     : TSocket;
    FDocument   : TBufferRec;
    FTimerHwnd  : THandle;
    FTimeout    : Integer;
    FTargetHost : string;
    FTargetPort : Word;
    FProxyHost  : string;
    FProxyPort  : Word;
    FResultCode : Integer;
    FProxyCode  : Integer;
    FResolver   : Boolean;

    // Timeout Control
    function TimerStart(Timeout: Integer): Boolean;
    procedure TimerAbort;
    // Socket Connect
    function SocketConnect(const ConnectHost: string; ConnectPort: Word): Boolean;
    function ProxyConnect(const ConnectHost: string; ConnectPort: Word): Boolean;
    function SocketResolve(const TargetHost: string): Longint;
    procedure SocketClose(CloseGraceful: Boolean = False);
    // Socket Operations
    function SocketWrite: Boolean;
    function SocketRead(ReadBytes: Integer = 0; SockShut: Boolean = False): Boolean;
    // Socket Errors
    function SocketError: Integer;
    procedure SocketReset;
    // Read Document Result
    function GetDocument: string;
  public
    constructor Create;
    destructor Destroy; override;

    // Simple Request Routines
    function SocketRequest(const Request: string): Boolean;
    procedure SocketAbort;

    // Socket Connect Stuff
    property Timeout: Integer read FTimeout write FTimeout;
    property TargetHost: string read FTargetHost write FTargetHost;
    property TargetPort: Word read FTargetPort write FTargetPort;
    property ProxyHost: string read FProxyHost write FProxyHost;
    property ProxyPort: Word read FProxyPort write FProxyPort;
    // SOCKS4, SOCKS4A Toggle
    property Resolver: Boolean read FResolver write FResolver;
    // Request Result
    property Document: string read GetDocument;
    // Socket, Proxy Error Codes
    property ResultCode: Integer read FResultCode;
    property ProxyCode: Integer read FProxyCode;
  end;

  // Buffer Routines
  procedure ResizeBuffer(var BufferRec: TBufferRec; Needed: Integer; Initial: Integer = 0);
  procedure WriteBuffer(var BufferRec: TBufferRec; BuffData: Pointer; BuffLen: Integer; WritePos: Integer = 0);
  function ReadBuffer(BufferRec: TBufferRec; ChunkSize: Integer): string; overload;
  procedure ReadBuffer(BufferRec: TBufferRec; BuffData: Pointer; ChunkSize: Integer); overload;

  // Loader Routines
  function LoadLib(var LibHandle: THandle; const LibName: string): Boolean;
  function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC; const FuncName: string): Boolean;
  function ReleaseLib(var LibHandle: THandle): Boolean;

  // Init Routines
  function InitLib: Boolean;
  procedure FreeLib;

var
  IsWinSockOk: Boolean = False;
  WSAData: TWSAData;

  WSLibHandle: THandle = 0;

  WSAStartup: TWSAStartup = nil;
  WSACleanup: TWSACleanup = nil;
  WSAGetLastError: TWSAGetLastError = nil;
  WSASetLastError: TWSASetLastError = nil;
  getsockopt: TGetSockOpt = nil;
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

  FTimeout := 60000;
  FTargetHost := '';
  FTargetPort := 0;

  FProxyHost := '';
  FProxyPort := 1080;
  FResolver := False;

  // Init Buffers
  ResizeBuffer(FDocument, INET_BUFF_LEN, INET_BUFF_LEN);

  // Init Socket
  SocketReset;
end;

destructor TSockClient.Destroy;
begin
  // Force Request Abort
  SocketAbort;
  // Destroy Socket
  SocketClose;

  // Free Buffers
  ResizeBuffer(FDocument, 0);

  inherited Destroy;
end;

function TSockClient.TimerStart(Timeout: Integer): Boolean;
var
  TimerDue: LARGE_INTEGER;

begin
  try
    Result := False;

    // Check Timeout Valid
    if (Timeout <= 0) then Exit;

    FTimerHwnd := CreateWaitableTimer(nil, True, nil);
    // Check Timer Created
    if (FTimerHwnd = 0) then Exit;

    // Set Timeout
    TimerDue.QuadPart := -10000000 * (Timeout div 1000);
    // Start Timeout Timer
    Result := SetWaitableTimer(FTimerHwnd, TLargeInteger(TimerDue), 0, nil, nil, False);
  except
    FTimerHwnd := INVALID_HANDLE_VALUE;
    Result := False;
  end;
end;

procedure TSockClient.TimerAbort;
begin
  try
    // Check Handle
    if (FTimerHwnd = INVALID_HANDLE_VALUE) then Exit;

    try
      // Reset Timer Abort All
      CancelWaitableTimer(FTimerHwnd);
    finally
      // Release Timer
      CloseHandle(FTimerHwnd);
      // Reset Handle
      FTimerHwnd := INVALID_HANDLE_VALUE;
    end;
  except
    FTimerHwnd := INVALID_HANDLE_VALUE;
  end;
end;

function TSockClient.SocketConnect(const ConnectHost: string; ConnectPort: Word): Boolean;
var
  argp       : Longint;
  SockAddr   : TSockAddr;
  SockRes    : Integer;
  EventArray : array[0..1] of THandle;
  EventHwnd  : WSAEVENT;

begin
  try
    Result := False;

    // Check Machine Data
    if (Length(Trim(ConnectHost)) <= 0) or (ConnectPort <= 0) then Exit;

    // Check Timer
    if (FTimerHwnd = 0) then Exit;

    // Get Socket
    FSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Check Socket
    if (FSocket = INVALID_SOCKET) then Exit;

    // Enable Non Block Mode
    argp := 1;

    // Check Results To Be Sure
    if (ioctlsocket(FSocket, FIONBIO, argp) <> SOCK_NO_ERROR) then Exit;

    // Create Async Event
    EventHwnd := WSACreateEvent;
    // Check Event
    if (EventHwnd = WSA_INVALID_EVENT) then Exit;

    try
      // Attach Event, Check Attached
      if (WSAEventSelect(FSocket, EventHwnd, FD_CONNECT) <> SOCK_NO_ERROR) then Exit;

      // Populate Struct
      SockAddr.sin_port := htons(ConnectPort);
      SockAddr.sa_family := AF_INET;
      SockAddr.sin_addr.S_addr := SocketResolve(ConnectHost);

      // Connect To Target Machine
      SockRes := connect(FSocket, @SockAddr, SizeOf(SockAddr));
      // Check Return Values To Be Sure
      if (SockRes = SOCKET_ERROR) and (SocketError = WSAEWOULDBLOCK) then
      begin
        // Attach Events
        EventArray[0] := FTimerHwnd;
        EventArray[1] := EventHwnd;

        // Success On Connect Event Fail On Timer Elapse
        if (WaitForMultipleObjects(2, @EventArray, False, INFINITE) = (WAIT_OBJECT_0 + 1)) then
        begin
          // Check Socket Errors
          // Detect Connection Reset
          Result := (SocketError = SOCK_NO_ERROR);
        end;
      end;
    finally
      // Detach Event
      WSAEventSelect(FSocket, EventHwnd, 0);
      // Close Event
      WSACloseEvent(EventHwnd);
    end;
  except
    Result := False;
  end;
end;

function TSockClient.ProxyConnect(const ConnectHost: string; ConnectPort: Word): Boolean;
var
  SocksIn  : TSocksReq;
  SocksOut : TSocksResp;
  ZeroTerm : Byte;

begin
  try
    Result := False;

    // Check Machine Data
    if (Length(Trim(ConnectHost)) <= 0) or (ConnectPort <= 0) then Exit;

    // Clear Records Populate With $00
    ZeroMemory(@SocksIn, SizeOf(SocksIn));
    // Clear Terminator
    ZeroTerm := 0;

    // Populate SOCKS4 Request
    SocksIn.Version := SOCKS_VERSION;
    SocksIn.Cmd := SOCKS_CONNECT;
    SocksIn.Port := htons(ConnectPort);

    // Use SOCKS4A Resolve In Proxy
    // Add Invalid IP(0.0.0.x) In Strtuct
    if Resolver then
      SocksIn.HostAddr := SocketResolve(SOCKS_HOST)
    else
      SocksIn.HostAddr := SocketResolve(ConnectHost);

    // Write To Temporary Buffer
    WriteBuffer(FDocument, @SocksIn, SizeOf(SocksIn));

    // Write UserId
    WriteBuffer(FDocument, PChar(SOCKS_USER_ID), Length(SOCKS_USER_ID), FDocument.Actual);
    // Write Separator
    WriteBuffer(FDocument, @ZeroTerm, SizeOf(ZeroTerm), FDocument.Actual);

    // Use SOCKS4A Resolve In Proxy
    // Add Additional Field For Host Resolve
    if Resolver then
    begin
      // Write Resolve Host
      WriteBuffer(FDocument, PChar(ConnectHost), Length(ConnectHost), FDocument.Actual);
      // Write Separator
      WriteBuffer(FDocument, @ZeroTerm, SizeOf(ZeroTerm), FDocument.Actual);
    end;

    // Send Request
    if (SocketWrite = False) then Exit;
    // Recieve Only Result Struct
    if (SocketRead(SizeOf(SocksOut)) = False) then Exit;

    // Clear Records
    ZeroMemory(@SocksOut, SizeOf(SocksOut));
    // Read SOCKS4 Result
    ReadBuffer(FDocument, @SocksOut, FDocument.Actual);

    // Check First Byte Good
    if (SocksOut.Zero = 0) then
    begin
      // Set Proxy Status
      FProxyCode := SocksOut.Status;
      // Check Wish Granted :F
      Result := (SocksOut.Status = SOCKS_GRANTED);
    end;
  except
    Result := False;
  end;
end;

function TSockClient.SocketWrite: Boolean;
var
  BytesSent  : Integer;
  BytesTotal : Integer;
  EventHwnd  : WSAEVENT;
  BuffLen    : Integer;

begin
  try
    Result := False;
    // Total Bytes Send
    BytesTotal := 0;

    // Check Request Length
    if (FDocument.Actual <= 0) then Exit;

    // Check Timer
    if (FTimerHwnd = 0) then Exit;

    // Check Socket
    if (FSocket = INVALID_SOCKET) then Exit;

    // Create Event
    EventHwnd := WSACreateEvent;
    // Check Event
    if (EventHwnd = WSA_INVALID_EVENT) then Exit;

    try
      // Attach Event, Check Attached
      if (WSAEventSelect(FSocket, EventHwnd, FD_WRITE) <> SOCK_NO_ERROR) then Exit;

      // SlowDown Do Not Drain CPU. Watch For Abort
      while (WaitForSingleObject(FTimerHwnd, TROTTLE_WAIT) = WAIT_TIMEOUT) do
      begin
        // SlowDown Do Not Drain CPU
        if (WaitForSingleObject(EventHwnd, TROTTLE_WAIT) = WAIT_OBJECT_0) then
        begin
          // Send Max SOCK_MAX_CHUN Len
          BuffLen := FDocument.Actual - BytesTotal;
          if (BuffLen > SOCK_MAX_CHUN) then
          begin
            BuffLen := SOCK_MAX_CHUN;
          end;

          // Send Always Right Data
          BytesSent := send(FSocket, Pointer(DWORD(FDocument.Buffer) + DWORD(BytesTotal))^, BuffLen, 0);
          // Caclulate Total Bytes Send
          if (BytesSent > 0) then
          begin
            Inc(BytesTotal, BytesSent);
          end;

          // Stop When Done
          if ((BytesSent = SOCKET_ERROR) and (SocketError <> WSAEWOULDBLOCK))
            or (BytesSent = 0) or (BytesTotal = FDocument.Actual) then
          begin
            Break;
          end;
        end;
      end;

      // Check Send All
      Result := (BytesTotal = FDocument.Actual);
    finally
      // Detach Event
      WSAEventSelect(FSocket, EventHwnd, 0);
      // Close Event
      WSACloseEvent(EventHwnd);
    end;
  except
    Result := False;
  end;
end;

function TSockClient.SocketRead(ReadBytes: Integer = 0; SockShut: Boolean = False): Boolean;
var
  EventHwnd  : WSAEVENT;
  BuffLen    : Integer;
  BuffMax    : Integer;
  BytesRead  : Integer;
  BytesTotal : Integer;
  WritePoint : Integer;

begin
  try
    Result := False;
    // Botal Bytes Recv
    BytesTotal := 0;

    // Check Timer
    if (FTimerHwnd = 0) then Exit;

    // Check Socket
    if (FSocket = INVALID_SOCKET) then Exit;

    // Create Event
    EventHwnd := WSACreateEvent;
    // Check Event
    if (EventHwnd = WSA_INVALID_EVENT) then Exit;

    try
      // Attach Event, Check Attached
      // Check Operation Type
      if SockShut then
      begin
        if (WSAEventSelect(FSocket, EventHwnd, FD_CLOSE) <> SOCK_NO_ERROR) then Exit;
        // Disable Socket Operations
        if (shutdown(FSocket, SD_SEND) <> SOCK_NO_ERROR) then Exit;
      end
      else
      begin
        if (WSAEventSelect(FSocket, EventHwnd, FD_READ) <> SOCK_NO_ERROR) then Exit;
        // Reset Output Buffer
        FDocument.Actual := 0;
      end;

      // SlowDown Do Not Drain CPU. Watch For Abort
      while (WaitForSingleObject(FTimerHwnd, TROTTLE_WAIT) = WAIT_TIMEOUT) do
      begin
        // SlowDown Do Not Drain CPU
        if (WaitForSingleObject(EventHwnd, TROTTLE_WAIT) = WAIT_OBJECT_0) then
        begin
          // Reset To Be Sure
          BytesRead := SOCKET_ERROR;
          // Stream Bigger Chunks
          if (ioctlsocket(FSocket, FIONREAD, BuffMax) = SOCK_NO_ERROR) then
          begin
            // Check Recv Read Len
            if (BuffMax > 0) then
            begin
              // Recv Max SOCK_MAX_CHUN Len
              if (BuffMax > SOCK_MAX_CHUN) then
              begin
                BuffMax := SOCK_MAX_CHUN;
              end;
            end
            else
            begin
              // FallBack To Default
              BuffMax := FDocument.Initial;
            end;

            // Read Exactly That Count Of Bytes Then Stop
            // BytesTotal Bytes Recv In This Routine Call
            if (ReadBytes > 0) then
            begin
              // Calculate Remaining
              BuffLen := ReadBytes - BytesTotal;
              if (BuffLen > BuffMax) then
              begin
                BuffLen := BuffMax;
              end;
            end
            else
            begin
              BuffLen := BuffMax;
            end;

            // Write Position Mainly For ShutDown Case
            // Reset Only On Receive. ShutDown Appends Buffer
            WritePoint := FDocument.Actual + BytesTotal;
            // Resize Buffer If Needed
            ResizeBuffer(FDocument, WritePoint + BuffLen);

            BytesRead := recv(FSocket, Pointer(DWORD(FDocument.Buffer) + DWORD(WritePoint))^, BuffLen, 0);
            // Caclulate Total Bytes Received
            if (BytesRead > 0) then
            begin
              Inc(BytesTotal, BytesRead);
            end;
          end;

          // Stop When Done
          if ((BytesRead = SOCKET_ERROR) and (SocketError <> WSAEWOULDBLOCK))
            or (BytesRead = 0) or ((ReadBytes > 0) and (ReadBytes = BytesTotal)) then
          begin
            Break;
          end;
        end;
      end;

      // Check Receive Success
      Result := (BytesTotal > 0);
    finally
      // Set Buffer Actual Fill
      Inc(FDocument.Actual, BytesTotal);
      // Detach Event
      WSAEventSelect(FSocket, EventHwnd, 0);
      // Close Event
      WSACloseEvent(EventHwnd);
    end;
  except
    Result := False;
  end;
end;

procedure TSockClient.SocketClose(CloseGraceful: Boolean = False);
begin
  try
    // Check Socket
    if (FSocket = INVALID_SOCKET) then Exit;

    try
      // Connect Failed Skip ShutDown
      if (CloseGraceful = False) then Exit;

      // ShutDown Graceful Read Before Close
      SocketRead(0, True);
    finally
      // Close Graceful I Hope
      closesocket(FSocket);
      // Reset Socket Value
      FSocket := INVALID_SOCKET;
    end;
  except
    FSocket := INVALID_SOCKET;
  end;
end;

function TSockClient.SocketResolve(const TargetHost: string): Longint;
var
  HostEnt: PHostEnt;

begin
  try
    Result := 0;

    // Check WinSock2 Init
    if (IsWinSockOk = False) then Exit;

    // Convert IP To Network Byte Order
    Result := inet_addr(PChar(TargetHost));
    // Convert Failed This Is Host
    if (Result = u_long(INADDR_NONE)) then
    begin
      // Convert Host To Network Byte Order
      HostEnt := gethostbyname(PChar(TargetHost));
      Result := LongInt(PLongint(HostEnt.h_addr_list^)^);
    end;
  except
    Result := 0;
  end;
end;

function TSockClient.SocketRequest(const Request: string): Boolean;
var
  CloseGraceful: Boolean;

begin
  try
    Result := False;

    // Force Hard Socket Close
    CloseGraceful := False;

    // Prepare Socket
    SocketReset;

    // Just To Be Sure
    if (IsWinSockOk = False) then Exit;

    try
      // Trigger Timeout Timer
      if (TimerStart(FTimeout) = False) then Exit;

      // Check SOCKS Proxy Attached
      if (Length(Trim(FProxyHost)) > 0) and (FProxyPort > 0) then
      begin
        // Connect To SOCKS Proxy
        if (SocketConnect(FProxyHost, FProxyPort) = False) then Exit;
        // Create Tunnel To Target Host
        if (ProxyConnect(FTargetHost, FTargetPort) = False) then Exit;
      end
      else
      begin
        // Connect To Target Host
        if (SocketConnect(FTargetHost, FTargetPort) = False) then Exit;
      end;

      // Connected Close Graceful
      CloseGraceful := True;

      // Write Request To Buffer
      WriteBuffer(FDocument, Pointer(Request), Length(Request));

      // Send Request
      if (SocketWrite = False) then Exit;
      // Recieve Result
      if (SocketRead = False) then Exit;

      Result := True;
    finally
      // Disconnect Close Socket
      SocketClose(CloseGraceful);
      // Abort Timeout Timer
      TimerAbort;
    end;
  except
    Result := False;
  end;
end;

function TSockClient.SocketError: Integer;
var
  SockErr : Integer;
  OptLen  : Integer;

begin
  try
    // Set Default Error
    Result := WSABASEERR;

    // Check WinSock2 Init
    if IsWinSockOk then
    begin
      // Errors Returned From WSAGetLastError And getsockopt(SO_ERROR)
      // Are Two Different Things. Do Not Rely To WSAGetLastError
      // WSAGetLastError - WinSock2 Specific Errors
      // getsockopt(SO_ERROR) - Socket Errors
      Result := WSAGetLastError;

      // Reset Error Code
      SockErr := SOCK_NO_ERROR;
      // Get Correct Buffer Size
      OptLen := SizeOf(SockErr);

      // Even If Failed Socket Will Signal Event
      if (getsockopt(FSocket, SOL_SOCKET, SO_ERROR, @SockErr, OptLen) = SOCK_NO_ERROR) then
      begin
        // Reset Only On Socket Error
        if (SockErr <> SOCK_NO_ERROR) then
        begin
          Result := SockErr;
          // Reset WinSock2 Error Too
          WSASetLastError(SockErr);
        end;
      end;
    end;
  except
    Result := WSABASEERR;
  end;

  FResultCode := Result;
end;

procedure TSockClient.SocketReset;
begin
  // Reset Socket
  FSocket := INVALID_SOCKET;

  // Reset Timer
  FTimerHwnd := INVALID_HANDLE_VALUE;

  // Reset Error Vars
  FResultCode := SOCK_NO_ERROR;
  FProxyCode := SOCK_NO_ERROR;

  // Reset Document Buffer
  if Assigned(FDocument.Buffer) and (FDocument.Length > 0) then
  begin
    ZeroMemory(FDocument.Buffer, FDocument.Length);
  end;

  // Reset Errors
  if IsWinSockOk then
  begin
    WSASetLastError(SOCK_NO_ERROR);
  end;
end;

procedure TSockClient.SocketAbort;
begin
  try
    TimerAbort;
  except
    //
  end;
end;

function TSockClient.GetDocument: string;
begin
  try
    Result := ReadBuffer(FDocument, FDocument.Actual);
  except
    Result := '';
  end;
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
    if (BufferRec.Initial <= 0) then Exit;

    // Check Needed To Resize, Free Buffer
    if (Needed > BufferRec.Length) or (Needed = 0) then
    begin
      // Calculate New Size
      if (Needed > BufferRec.Initial) then
        NewSize := ((Needed div BufferRec.Initial) + 1) * BufferRec.Initial
      else if (Needed = 0) then
        NewSize := Needed
      else
        NewSize := BufferRec.Initial;

      ReallocMem(BufferRec.Buffer, NewSize);
      BufferRec.Length := NewSize;

      // FreeBuffer
      if (Needed = 0) then
      begin
        BufferRec.Actual := 0;
      end;
    end;
  except
    BufferRec.Actual := 0;
    BufferRec.Length := 0;
  end;
end;

function ReadBuffer(BufferRec: TBufferRec; ChunkSize: Integer): string;
begin
  try
    Result := '';

    // Check Valid
    if Assigned(BufferRec.Buffer) and (BufferRec.Actual >= ChunkSize) and (ChunkSize > 0) then
    begin
      // Resize Result String
      SetLength(Result, ChunkSize);
      Move(Pointer(BufferRec.Buffer)^, Pointer(Result)^, ChunkSize);
    end;
  except
    Result := '';
  end;
end;

procedure ReadBuffer(BufferRec: TBufferRec; BuffData: Pointer; ChunkSize: Integer); overload;
begin
  try
    // Check Valid
    if Assigned(BufferRec.Buffer) and (BufferRec.Actual >= ChunkSize)
      and Assigned(BuffData) and (ChunkSize > 0) then
    begin
      // Watch For BuffData Size
      Move(Pointer(BufferRec.Buffer)^, BuffData^, ChunkSize);
    end;
  except
    //
  end;
end;

procedure WriteBuffer(var BufferRec: TBufferRec; BuffData: Pointer; BuffLen: Integer; WritePos: Integer = 0);
var
  NeededLen: Integer;

begin
  try
    // Check Valid
    if Assigned(BufferRec.Buffer) and (BufferRec.Length > 0)
      and Assigned(BuffData) and (BuffLen > 0) then
    begin
      // Calculate Buffer Resize
      if ((BufferRec.Length - WritePos) < BuffLen) then
        NeededLen := BufferRec.Length + (BuffLen - (BufferRec.Length - WritePos))
      else
        NeededLen := BuffLen;

      // Resize If Needed
      ResizeBuffer(BufferRec, NeededLen);

      // Check Resized
      if (BufferRec.Length >= NeededLen) then
      begin
        // Move Chunk, Adjust Position Marker
        Move(BuffData^, Pointer(DWORD(BufferRec.Buffer) + DWORD(WritePos))^, BuffLen);
        BufferRec.Actual := WritePos + BuffLen;
      end;
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
  Result := (LibHandle <> 0);
end;

function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC; const FuncName: string): Boolean;
begin
  FuncPtr := nil;
  Result := False;

  if (LibHandle <> 0) then
  begin
    FuncPtr := GetProcAddress(LibHandle, PChar(FuncName));
    Result := Assigned(FuncPtr);
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
    if (LoadFunc(WSLibHandle, @WSASetLastError, FUN_WSA_SET_LAST_ERROR) = False) then Exit;
    if (LoadFunc(WSLibHandle, @getsockopt, FUN_GET_SOCK_OPT) = False) then Exit;
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

    // Init Struct
    ZeroMemory(@WSAData, SizeOf(WSAData));
    // Startup WinSock2
    Result := (WSAStartup(MakeWord(2, 2), WSAData) = SOCK_NO_ERROR);
  except
    Result := False;
  end;
end;

procedure FreeLib;
begin
  try
    IsWinSockOk := False;

    // Shut Down WinSock2
    WSACleanup;

    WSAStartup := nil;
    WSACleanup := nil;
    WSAGetLastError := nil;
    WSASetLastError := nil;
    getsockopt := nil;
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

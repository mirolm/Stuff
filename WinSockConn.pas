unit WinSockConn;

interface

uses Windows, WinSock2, WinInet, SysUtils;

const
  INET_USER_AGENT = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)';
  INET_REQ_VER    = 'HTTP/1.0';
  INET_REQ_ACC    = 'text/html, */*';
  INET_REQ_POST   = 'POST';
  INET_REQ_GET    = 'GET';
  INET_REQ_ERR    = 0;
  INET_REQ_STR    = 'No Status Text';
  INET_BUFF_LEN   = 8192;

type
  // Cookie Jar
  TCookieRecord = packed record
    Name   : string;  // Parsed Name
    Value  : string;  // Parsed Value
    Domain : string;  // Distinct By Domain
    Path   : string;  // Distinct By Path
  end;
  PCookieRecord = ^TCookieRecord;
  TCookieArray = array of PCookieRecord;

  // Header Jar
  THeaderRecord = packed record
    Name   : string;  // Parsed Name
    Value  : string;  // Parsed Value
  end;
  PHeaderRecord = ^THeaderRecord;
  THeaderArray = array of PHeaderRecord;

  // Custom Buffers
  TBufferRec = packed record
    Buffer : Pointer; // Buffer Pointer
    Length : DWORD;   // Alloc Buffer Len
    Actual : DWORD;   // Actual Data Len
  end;

  // Event Stuff
  THandleArray = array of THandle;

type
  TWinSockSend = class
  private
    FDocument     : TBufferRec;
    FChunkBuff    : TBufferRec;
    FCookies      : TCookieArray;
    FHeaders      : THeaderArray;
    FHeaderData   : TBufferRec;
    FUserAgent    : string;
    FReferer      : string;
    FAccTypes     : string;
    FResultCode   : Integer;
    FResultString : string;
    FProxyServer  : string;
    FProxyPort    : Integer;
    FEventArray   : THandleArray;
    FTimeout      : DWORD;

    // Header Jar
    procedure ConstructHeaders(Headers: THeaderArray; HeaderBuff: TBufferRec);
    // Cookie Jar
    procedure ConstructCookies(const Url: string; Cookies: TCookieArray; Headers: THeaderArray);
    // Custom Buffers
    procedure ResizeBuffer(var BufferRec: TBufferRec; Initial, Needed: DWORD;
      InitBuff: Boolean = False);
    // Socket Stuff
    function SocketCreate: TSocket;
    function SocketConnect(WorkSocket: TSocket; const Url, Proxy: string; Port: Integer): Boolean;
    function SocketRequest(WorkSocket: TSocket; WorkBuffer: TBufferRec): Boolean;
    function SocketRead(WorkSocket: TSocket; WorkBuffer: TBufferRec): Boolean;
    function SocketFree(WorkSocket: TSocket): Boolean;
    // WinInetStuff
    function InetGetDomain(const Url: string; var Server, Address: string;
      var Port: INTERNET_PORT; AddScheme: Boolean = False): Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    // Header Jar
    function AddHeader(const Header: string; Headers: THeaderArray): Boolean;
    function GetHeader(const Name: string; Headers: THeaderArray): THeaderRecord;
    // Cookie Jar
    function AddCookie(const Cookie: string; Cookies: TCookieArray): Boolean;
    function GetCookie(const Name, Domain, Path: string; Cookies: TCookieArray): TCookieRecord;
    // Main Stuff
    function HTTPMethod(const Method, Url: string): Boolean;
    procedure Abort;
  end;

  function InitLib: Boolean;
  procedure FreeLib;

var
  WinSockOk : Boolean;
  WSAData   : TWSAData;

implementation

{ TWinSockSend }

function TWinSockSend.AddCookie(const Cookie: string; Cookies: TCookieArray): Boolean;
begin
  //
end;

function TWinSockSend.AddHeader(const Header: string; Headers: THeaderArray): Boolean;
begin
  //
end;

procedure TWinSockSend.ConstructCookies(const Url: string; Cookies: TCookieArray; Headers: THeaderArray);
begin
  //
end;

procedure TWinSockSend.ConstructHeaders(Headers: THeaderArray; HeaderBuff: TBufferRec);
begin
  //
end;

constructor TWinSockSend.Create;
begin
  inherited;

  SetLength(FEventArray, 2);
  FEventArray[0] := CreateEvent(nil, True, False, nil);
  FEventArray[1] := 0;
end;

destructor TWinSockSend.Destroy;
begin
  CloseHandle(FEventArray[0]);
  SetLength(FEventArray, 0);

  inherited;
end;

function TWinSockSend.GetCookie(const Name, Domain, Path: string; Cookies: TCookieArray): TCookieRecord;
begin
  //
end;

function TWinSockSend.GetHeader(const Name: string; Headers: THeaderArray): THeaderRecord;
begin
  //
end;

function TWinSockSend.HTTPMethod(const Method, Url: string): Boolean;
begin
  //
end;

procedure TWinSockSend.ResizeBuffer(var BufferRec: TBufferRec; Initial, Needed: DWORD; InitBuff: Boolean);
var
  NewSize: Integer;

begin
  try
    // Init Record
    if InitBuff then
    begin
      BufferRec.Buffer := nil;
      BufferRec.Length := 0;
      BufferRec.Actual := 0;
    end;

    // Calculate New Size
    if (Needed > Initial) then
      NewSize := ((Needed div Initial) + 1) * Initial
    else
      NewSize := Initial;

    if Assigned(BufferRec.Buffer) then
    begin
      // Check Needed To Resize
      if (Needed > BufferRec.Length) then
      begin
        ReallocMem(BufferRec.Buffer, NewSize);
        BufferRec.Length := NewSize;
      end;
    end
    else
    begin
      GetMem(BufferRec.Buffer, NewSize);
      BufferRec.Length := NewSize;
      BufferRec.Actual := 0;
    end;
  except
    //
  end;
end;

function TWinSockSend.SocketCreate: TSocket;
var
  argp: u_long;

begin
  try
    Result := Socket(AF_INET, SOCK_STREAM, 0);

    argp := 1;
    ioctlsocket(Result, Integer(FIONBIO), argp);
    if (Result = INVALID_SOCKET) then
    begin
      Result := 0;
    end;
  except
    Result := 0;
  end;
end;

function TWinSockSend.SocketConnect(WorkSocket: TSocket; const Url, Proxy: string; Port: Integer): Boolean;
var
  WorkHost : string;
  WorkPort : INTERNET_PORT;
  WorkAddr : string;
  SockAddr : TSockAddr;
  HostEnt  : PHostEnt;
  WSAEvent : THandle;
  WaitRes  : DWORD;

begin
  try
    Result := False;
    WorkHost := '';
    WorkPort := 0;
    WorkAddr := '';

    if (Length(Trim(Proxy)) = 0) and (Port > 0) then
    begin
      InetGetDomain(Url, WorkHost, WorkAddr, WorkPort, False)
    end
    else
    begin
      WorkHost := Proxy;
      WorkPort := Port;
    end;

    if (Length(Trim(WorkHost)) > 0) and (WorkPort > 0) then
    begin
      SockAddr.sin_port := htons(WorkPort);
      SockAddr.sa_family := AF_INET;
      HostEnt := gethostbyname(PChar(WorkHost));
      SockAddr.sin_addr.S_addr := LongInt(PLongint(HostEnt.h_addr_list^)^);

      connect(WorkSocket, @SockAddr, SizeOf(SockAddr));

      WSAEvent := WSACreateEvent;
      try
        WSAEventSelect(WorkSocket, WSAEvent, FD_CONNECT);
        FEventArray[1] := WSAEvent;

        WaitRes := WaitForMultipleObjects(2, Pointer(FEventArray), False, FTimeout);
        Result := (WaitRes = (WAIT_OBJECT_0 + 1));
      finally
        WSACloseEvent(WSAEvent);
        FEventArray[1] := 0;
      end;
    end;
  except
    Result := False;
  end;
end;

function TWinSockSend.SocketRequest(WorkSocket: TSocket; WorkBuffer: TBufferRec): Boolean;
var
  WSAEvent  : THandle;
  WaitRes   : DWORD;
  BytesSent : Integer;

begin
  try
    Result := False;

    if Assigned(WorkBuffer.Buffer) and (WorkBuffer.Actual > 0) then
    begin
      WSAEvent := WSACreateEvent;
      try
        WSAEventSelect(WorkSocket, WSAEvent, FD_WRITE);
        FEventArray[1] := WSAEvent;

        WaitRes := WaitForMultipleObjects(2, Pointer(FEventArray), False, FTimeout);
        if (WaitRes = (WAIT_OBJECT_0 + 1)) then
        begin
          BytesSent := send(WorkSocket, WorkBuffer.Buffer, WorkBuffer.Actual, 0);
          Result := (BytesSent = SOCKET_ERROR);
        end;
      finally
        WSACloseEvent(WSAEvent);
        FEventArray[1] := 0;
      end;
    end;
  except
    Result := False;
  end;
end;

function TWinSockSend.SocketRead(WorkSocket: TSocket; WorkBuffer: TBufferRec): Boolean;
var
  WSAEvent : THandle;
  WaitRes  : DWORD;

begin
  try
    Result := False;

    if Assigned(WorkBuffer.Buffer) and Assigned(FChunkBuff.Buffer) then
    begin
      WSAEvent := WSACreateEvent;
      try
        WSAEventSelect(WorkSocket, WSAEvent, FD_READ);
        FEventArray[1] := WSAEvent;

        WaitRes := WaitForMultipleObjects(2, Pointer(FEventArray), False, FTimeout);
        if (WaitRes = (WAIT_OBJECT_0 + 1)) then
        begin
          repeat
            FChunkBuff.Actual := recv(WorkSocket, FChunkBuff.Buffer, FChunkBuff.Length, 0);
            if (FChunkBuff.Actual > 0) then
            begin
              // Resize Buffer If Needed
              ResizeBuffer(WorkBuffer, INET_BUFF_LEN, WorkBuffer.Length + FChunkBuff.Actual);
              if Assigned(WorkBuffer.Buffer) then
              begin
                // Move Chunks To Buffer
                Move((FChunkBuff.Buffer)^, Pointer(DWORD(WorkBuffer.Buffer) + WorkBuffer.Actual)^, FChunkBuff.Actual);
                // Get Actual Bytes Received
                Inc(WorkBuffer.Actual, FChunkBuff.Actual);
              end
            end;
          until (FChunkBuff.Actual = DWORD(SOCKET_ERROR)) or (FChunkBuff.Actual = 0);
        end;
      finally
        WSACloseEvent(WSAEvent);
        FEventArray[1] := 0;
      end;
    end;
  except
    Result := False;
  end;
end;

function TWinSockSend.SocketFree(WorkSocket: TSocket): Boolean;
begin
  shutdown(WorkSocket, SD_BOTH);
  closesocket(WorkSocket);
end;

function InitLib: Boolean;
begin
  try
    Result := (WSAStartup(MakeWord(2, 0), WSAData) = 0);
  except
    Result := False;
  end;
end;

procedure FreeLib;
begin
  WSACleanup;
end;

function TWinSockSend.InetGetDomain(const Url: string; var Server,
  Address: string; var Port: INTERNET_PORT; AddScheme: Boolean): Boolean;
var
  UrlComp : PURLComponents;
  Buffer  : PChar;
  BuffLen : DWORD;
  Scheme  : string;
  Params  : string;

begin
  Result := False;

  try
    Server := '';
    Address := '';
    Port := 0;
    BuffLen := INTERNET_MAX_URL_LENGTH;

    // URLComponents Allocate
    New(UrlComp);
    // Components Allocate
    UrlComp^.lpszScheme := AllocMem(INTERNET_MAX_SCHEME_LENGTH);
    UrlComp^.lpszHostName := AllocMem(INTERNET_MAX_HOST_NAME_LENGTH);
    UrlComp^.lpszUserName := AllocMem(INTERNET_MAX_USER_NAME_LENGTH);
    UrlComp^.lpszPassword := AllocMem(INTERNET_MAX_PASSWORD_LENGTH);
    UrlComp^.lpszUrlPath := AllocMem(INTERNET_MAX_PATH_LENGTH);
    UrlComp^.lpszExtraInfo := AllocMem(INTERNET_MAX_PATH_LENGTH);
    // Canonicalize Buffer Allocate
    Buffer := AllocMem(BuffLen);
    try
      UrlComp^.dwSchemeLength := INTERNET_MAX_SCHEME_LENGTH;
      UrlComp^.dwHostNameLength := INTERNET_MAX_HOST_NAME_LENGTH;
      UrlComp^.dwUserNameLength := INTERNET_MAX_USER_NAME_LENGTH;
      UrlComp^.dwPasswordLength := INTERNET_MAX_PASSWORD_LENGTH;
      UrlComp^.dwUrlPathLength := INTERNET_MAX_PATH_LENGTH;
      UrlComp^.dwExtraInfoLength := INTERNET_MAX_PATH_LENGTH;
      UrlComp^.dwStructSize := SizeOf(TURLComponents);

      // Put Url In Normal Form
      if InternetCanonicalizeUrl(PChar(Url), Buffer, BuffLen, 0) then
      begin
        // Get Url Patrs
        if InternetCrackUrl(Buffer, BuffLen, 0, UrlComp^) then
        begin
          SetLength(Server, UrlComp^.dwHostNameLength);
          Move((UrlComp^.lpszHostName)^, Pointer(Server)^, UrlComp^.dwHostNameLength);

          SetLength(Scheme, UrlComp^.dwSchemeLength);
          Move((UrlComp^.lpszScheme)^, Pointer(Scheme)^, UrlComp^.dwSchemeLength);

          // For InetCombineUrl
          if AddScheme then
            Server := Scheme + '://' + Server;

          SetLength(Address, UrlComp^.dwUrlPathLength);
          Move((UrlComp^.lpszUrlPath)^, Pointer(Address)^, UrlComp^.dwUrlPathLength);

          SetLength(Params, UrlComp^.dwExtraInfoLength);
          Move((UrlComp^.lpszExtraInfo)^, Pointer(Params)^, UrlComp^.dwExtraInfoLength);

          // Add Params
          if (Length(Trim(Params)) > 0) then
            Address := Address + Params;

          Port := UrlComp^.nPort;

          // User And Pass Skipped If Needed Add Them
          Result := True;
        end;
      end;
    finally
      // Free URLComponents
      FreeMem(UrlComp^.lpszScheme);
      FreeMem(UrlComp^.lpszHostName);
      FreeMem(UrlComp^.lpszUserName);
      FreeMem(UrlComp^.lpszPassword);
      FreeMem(UrlComp^.lpszUrlPath);
      FreeMem(UrlComp^.lpszExtraInfo);
      Dispose(UrlComp);
      // Free Canonicalize Buffer
      FreeMem(Buffer);
    end;
  except
    Server := '';
    Address := '';
    Port := 0;

    Result := False;
  end;
end;

procedure TWinSockSend.Abort;
begin
  SetEvent(FEventArray[0]);
end;

initialization
  WinSockOk := InitLib;

finalization
  FreeLib;

end.

unit ArgoxPrint;
{------------------------------------------------------------------------------}
{ ARGOX PRINTER LIBRARY                                                        }
{ www.argox.com, Command Library, WinPPLB                                      }
{------------------------------------------------------------------------------}

{------------------------------------------------------------------------------}
{ CONDITIONAL DEFINES USED                                                     }
{------------------------------------------------------------------------------}
{ V400DEBUG      - Enables Debug Information In File                           }
{ V400DEBUG_VIEW - Enables Debug Information In DebugView                      }
{------------------------------------------------------------------------------}

interface

uses Windows;

{------------------------------------------------------------------------------}
{ WinPPLB Routine Definitions                                                  }
{------------------------------------------------------------------------------}

type
  TB_CreatePrn = function(Selection: Integer; FileName: PChar): Integer; stdcall;
  TB_Set_Darkness = function(Darkness: Integer): Integer; stdcall;
  TB_Prn_Barcode = function(X, Y, Ori: Integer; TType: PChar;
    Narrow, Width, Height: Integer; Human: Char; Data: PChar): Integer; stdcall;
  TB_Print_Out = function(CopyPiece: Integer): Integer; stdcall;
  TB_ClosePrn = procedure(); stdcall;
  TB_Get_DLL_VersionA = function(ShowMessage: Integer): Integer; stdcall;
  TB_Set_DebugDialog = function(nEnable: Integer): Integer; stdcall;
  TB_GetUSBBufferLen = function(): Integer; stdcall;
  TB_EnumUSB = function(Buffer: PChar): Integer; stdcall;
  TB_GetNetPrinterBufferLen = function(): Integer; stdcall;
  TB_EnumNetPrinter = function(Buffer: PChar): Integer; stdcall;

{------------------------------------------------------------------------------}
{ Helper Structures                                                            }
{------------------------------------------------------------------------------}

type
  TEnumRecord = record
    EnumName : string;
    EnumType : Integer;
  end;
  PEnumRecord = ^TEnumRecord;

  TEnumArray = array of PEnumRecord;

{------------------------------------------------------------------------------}
{ Global Setings                                                               }
{------------------------------------------------------------------------------}

const
  ARG_DEF_PORT      = 1;               // LPT1 By Default
  ARG_DEF_TARGET    = '';              // Empty By Default
  ARG_DEF_USB       = 12;              // USB Printers
  ARG_DEF_NET       = 13;              // Network Printers
  ARG_FILE_NAME     = 'v400Print.log'; // Default Log File Name
  ARG_PPLB_VER      = 402;             // Required Minimum Library Version
  ARG_PPLB_DELIM    = #13#10;          // Enumerate Routines Delimiter
  ARG_PPLB_ERROR    = 1000;            // Error Start Offset

  ARG_X_DEF_COORD   = 240; // X Coord BarCode Coordinate
  ARG_Y_SNG_CAT_NUM = 60;  // Y Coord CatalogNum Only BarCode
  ARG_Y_MUL_CAT_NUM = 20;  // Y Coord CatalogNum Multi Case
  ARG_Y_MUL_SER_NUM = 110; // Y Coord SerialNum Multi Case

{------------------------------------------------------------------------------}
{ WinPPLB API Loader Class                                                     }
{------------------------------------------------------------------------------}

type
  TWinPPLB = class(TObject)
  private
    // WinPPLB Library Handle
    PPLBHandle: THandle;
  public
    // WinPPLB Library Routines
    B_CreatePrn: TB_CreatePrn;
    B_Set_Darkness: TB_Set_Darkness;
    B_Prn_Barcode: TB_Prn_Barcode;
    B_Print_Out: TB_Print_Out;
    B_ClosePrn: TB_ClosePrn;
    B_Get_DLL_VersionA: TB_Get_DLL_VersionA;
    B_Set_DebugDialog: TB_Set_DebugDialog;
    B_GetUSBBufferLen: TB_GetUSBBufferLen;
    B_EnumUSB: TB_EnumUSB;
    B_GetNetPrinterBufferLen: TB_GetNetPrinterBufferLen;
    B_EnumNetPrinter: TB_EnumNetPrinter;

    constructor Create(var Loaded: Boolean);
    destructor  Destroy; override;
  end;

{------------------------------------------------------------------------------}
{ ARGOX PRINTERS Class                                                         }
{------------------------------------------------------------------------------}

  TArgox = class(TObject)
  private
    // Check Library Loaded
    FPPLBLoaded: Boolean;

    // Routine Debug
    FPPLBDebug: Integer;

    // WINPPLB Library API
    FWinPPLB: TWinPPLB;

    // Enumerated Devices
    FPPLBEnum: TEnumArray;

    // Print Single Barcode
    function  PrintBarCode(X_Coord, Y_Coord: Integer; const Text: string; Multiple: Boolean = False): Boolean;
    // Enumerate Routines
    procedure EnumDevices(EnumType: Integer);

    // Helper Routines
    function  CopyString(DataPtr: Pointer; DataLen: Cardinal; var ResultStr: string): Boolean;

    // Enumerate Helper Routines
    procedure AddToEnum(const EnumName: string; EnumType: Integer);
    procedure ParseEnum(const EnumString: string; EnumType: Integer);
    procedure DeleteEnum;
  public
    constructor Create(Port: Integer = ARG_DEF_PORT; Target: string = ARG_DEF_TARGET);
    destructor  Destroy; override;

    // Draw Barcode
    function DrawLabel(const CatalogNum: string; const SerialNum : string = '') : Boolean;
    // Enumerate Printers
    function EnumPrinters: TEnumArray;

    // Check Loaded Properly
    property Loaded: Boolean read FPPLBLoaded;
  end;

{------------------------------------------------------------------------------}
{ Misc Routines                                                                }
{------------------------------------------------------------------------------}

function LoadLib(var LibHandle: THandle; const LibName: string): Boolean;
function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC; const FuncName: string): Boolean;
procedure ReleaseLib(var LibHandle: THandle);
procedure OutputDebug(const DebugMessage: string);

{------------------------------------------------------------------------------}

implementation

uses SysUtils, StrUtils;

{------------------------------------------------------------------------------}
{ WinPPLB API Loader Class                                                     }
{------------------------------------------------------------------------------}

constructor TWinPPLB.Create(var Loaded: Boolean);
begin
  try
    Loaded := False;

    {$IFDEF V400DEBUG}
      OutputDebug('[winpplb.dll] Library Loaded');
    {$ENDIF}

    // Load Library
    if (LoadLib(PPLBHandle, 'winpplb.dll') = False) then Exit;

    // Load Routines
    if (LoadFunc(PPLBHandle, @B_CreatePrn, 'B_CreatePrn') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_Set_Darkness, 'B_Set_Darkness') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_Prn_Barcode, 'B_Prn_Barcode') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_Print_Out, 'B_Print_Out') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_ClosePrn, 'B_ClosePrn') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_Get_DLL_VersionA, 'B_Get_DLL_VersionA') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_Set_DebugDialog, 'B_Set_DebugDialog') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_GetUSBBufferLen, 'B_GetUSBBufferLen') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_EnumUSB, 'B_EnumUSB') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_GetNetPrinterBufferLen, 'B_GetNetPrinterBufferLen') = False) then Exit;
    if (LoadFunc(PPLBHandle, @B_EnumNetPrinter, 'B_EnumNetPrinter') = False) then Exit;

    Loaded := True;
  except
    Loaded := False;
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TWinPPLB.Create] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
  end;
end; // Create

{------------------------------------------------------------------------------}

destructor TWinPPLB.Destroy;
begin
  try
    // Release Routines
    B_CreatePrn := nil;
    B_Set_Darkness := nil;
    B_Prn_Barcode := nil;
    B_Print_Out := nil;
    B_ClosePrn := nil;
    B_Get_DLL_VersionA := nil;
    B_Set_DebugDialog := nil;
    B_GetUSBBufferLen := nil;
    B_EnumUSB := nil;
    B_GetNetPrinterBufferLen := nil;
    B_EnumNetPrinter := nil;

    // Release Library
    ReleaseLib(PPLBHandle);

    {$IFDEF V400DEBUG}
      OutputDebug('[winpplb.dll] Library Released');
    {$ENDIF}

    inherited;
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TWinPPLB.Destroy] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
  end;
end; // Destroy

{------------------------------------------------------------------------------}
{ ARGOX PRINTERS Class                                                         }
{------------------------------------------------------------------------------}

constructor TArgox.Create(Port: Integer = ARG_DEF_PORT; Target: string = ARG_DEF_TARGET);
begin
  try
    FPPLBLoaded := False;

    // Load WinPPLB API
    FWinPPLB := TWinPPLB.Create(FPPLBLoaded);

    // Check Library Loaded 
    if (FPPLBLoaded = False) then Exit; 

    // Get Library Version
    // ShowMessage --> 0(Disable Message Dialog)
    // Result --> Version Number
    FPPLBDebug := FWinPPLB.B_Get_DLL_VersionA(0);

    // Older Libraries Have Problems. Better Check Versions
    {$IFDEF V400DEBUG}
      if (FPPLBDebug < ARG_PPLB_VER) then
        OutputDebug(Format('[winpplb.dll] Library Too Old --> %d, Required --> %d', [FPPLBDebug, ARG_PPLB_VER]))
      else
        OutputDebug(Format('[winpplb.dll] Library Attached --> %d', [FPPLBDebug]));
    {$ENDIF}

    // Remove Error Dialogs. Better Not Show Them To User
    // nEnable --> 0(Disable Error Dialogs)
    // Result --> 0(Success)
    FPPLBDebug := FWinPPLB.B_Set_DebugDialog(0);

    {$IFDEF V400DEBUG}
      OutputDebug(Format('[B_Set_DebugDialog] --> %d', [FPPLBDebug]));
    {$ENDIF}

    // Init Printer
    // Port --> 1(LPT1), 2(LPT2), 3(LPT3), 4(COM1), 5(COM2), 6(COM3)
    // File --> nil(Not Needed For LPT, COM)
    // Result --> 0(Success)
    FPPLBDebug := FWinPPLB.B_CreatePrn(Port, PChar(Target));

    {$IFDEF V400DEBUG}
      OutputDebug(Format('[B_CreatePrn](%d) --> %d', [Port, FPPLBDebug]));
    {$ENDIF}

    // Setup Heating Level
    // Darkness --> 12
    // Result --> 0(Success)
    FPPLBDebug := FWinPPLB.B_Set_Darkness(12);

    {$IFDEF V400DEBUG}
      OutputDebug(Format('[B_Set_Darkness] --> %d', [FPPLBDebug]));
    {$ENDIF}
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.Create] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
    FPPLBLoaded := False;
  end;
end; // Create

{------------------------------------------------------------------------------}

function TArgox.PrintBarCode(X_Coord, Y_Coord: Integer; const Text: string; Multiple: Boolean): Boolean;
var
  TempText : string;

begin
  try
    Result := False;
    TempText := Trim(Text);

    // Check Library Loaded
    if (FPPLBLoaded = False) then Exit;

    // Check Input Data
    if ((Length(TempText) = 0) or (X_Coord < 1) or (Y_Coord < 1)) then
    begin
      {$IFDEF V400DEBUG}
        OutputDebug(Format('[PrintBarCode](%d, %d, %s)', [X_Coord, Y_Coord, TempText]));
      {$ENDIF}

      Exit;
    end;

    // Create Barcode
    // X Coordinate --> 240(Was 230), Y Coordinate --> 60(Single), 20(Multiple), 110(Multiple)
    // Orientation --> 0, Type --> '1', Narrow --> 2
    // Width --> 2, Height --> 40, Human --> 'B'(66), Data --> Barcode Text
    // Result --> 0(Success)
    FPPLBDebug := FWinPPLB.B_Prn_Barcode(X_Coord, Y_Coord, 0, '1', 2, 2, 40, 'B', PChar(TempText));

    {$IFDEF V400DEBUG}
      OutputDebug(Format('[B_Prn_Barcode](%d, %d, %s) --> %d', [X_Coord, Y_Coord, TempText, FPPLBDebug]));
    {$ENDIF}

    // If Multiple Codes Are Printed Put [B_Print_Out] Only On Last
    // In Case CatalogNum + SerialNum Put PrintOut On Second Call
    if (Multiple = False) then
    begin
      // Print Barcodes
      // Label Set --> 1
      // Result --> 0(Success)
      FPPLBDebug := FWinPPLB.B_Print_Out(1);

      {$IFDEF V400DEBUG}
        OutputDebug(Format('[B_Print_Out] --> %d', [FPPLBDebug]));
      {$ENDIF}
    end;

    Result := True;
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.PrintBarCode] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
    Result := False;
  end;
end; // PrintBarCode

{------------------------------------------------------------------------------}

function TArgox.CopyString(DataPtr: Pointer; DataLen: Cardinal; var ResultStr: string): Boolean;
begin
  try
    // Reset Values
    Result := False;
    ResultStr := EmptyStr;

    // Check Input Data
    if (Assigned(DataPtr) = True) and (DataLen > 0) then
    begin
      // Resize String
      SetLength(ResultStr, DataLen);
      // Copy Data To String
      Move(DataPtr^, Pointer(ResultStr)^, DataLen);
      // Set Success
      Result := True;
    end;
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.CopyString] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
    // Reset Values
    Result := False;
    ResultStr := EmptyStr;
  end;
end; // CopyString

{------------------------------------------------------------------------------}

procedure TArgox.AddToEnum(const EnumName: string; EnumType: Integer);
var
  EnumItem: PEnumRecord;

begin
  try
    // Create New Item
    New(EnumItem);
    // Just To Be Sure
    if Assigned(EnumItem) then
    begin
      {$IFDEF V400DEBUG}
        OutputDebug(Format('[TArgox.AddToEnum] --> %s %d', [EnumName, EnumType]));
      {$ENDIF}

      // Populate Enum Item
      EnumItem^.EnumName := Trim(EnumName);
      EnumItem^.EnumType := EnumType;
      // Resize Array
      SetLength(FPPLBEnum, High(FPPLBEnum) + 2);
      // Attach Item
      FPPLBEnum[High(FPPLBEnum)] := EnumItem;
    end;
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.AddToEnum] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
  end;
end; // AddToEnum

{------------------------------------------------------------------------------}

procedure TArgox.ParseEnum(const EnumString: string; EnumType: Integer);
var
  DelimPos  : Integer;
  TempText  : string;
  TempCount : Integer;
  TempEnum  : string;

begin
  try
    TempEnum := Trim(EnumString);

    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.ParseEnum] --> %s', [TempEnum]));
    {$ENDIF}

    while (Length(Trim(TempEnum)) > 0) do
    begin
      DelimPos := LastDelimiter(ARG_PPLB_DELIM, TempEnum);
      TempCount := Length(TempEnum) - DelimPos;

      if (DelimPos > 0) then
        TempText := Trim(RightStr(TempEnum, TempCount))
      else
        TempText := Trim(TempEnum);

      AddToEnum(TempText, EnumType);

      Delete(TempEnum, DelimPos + 1, TempCount);
      TempEnum := Trim(TempEnum);
    end;
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.ParseEnum] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
  end;
end; // ParseEnum

{------------------------------------------------------------------------------}

procedure TArgox.DeleteEnum;
var
  i        : Integer;
  EnumItem : PEnumRecord;

begin
  try
    // Dispose Items
    for i := Low(FPPLBEnum) to High(FPPLBEnum) do
    begin
      EnumItem := FPPLBEnum[i];
      if Assigned(EnumItem) then
      begin
        Dispose(EnumItem);
      end;
    end;

    // Clear Arrays
    SetLength(FPPLBEnum, 0);
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.DeleteEnum] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
  end;
end; // DeleteEnum

{------------------------------------------------------------------------------}

procedure TArgox.EnumDevices(EnumType: Integer);
var
  BuffLen : Integer;
  Buffer  : Pointer;
  BuffStr : string;

begin
  try
    // Get Enumerate Buffer Length
    case EnumType of
      ARG_DEF_USB: BuffLen := FWinPPLB.B_GetUSBBufferLen;
      ARG_DEF_NET: BuffLen := FWinPPLB.B_GetNetPrinterBufferLen;
    else
      BuffLen := 0;
    end;

    {$IFDEF V400DEBUG}
      OutputDebug(Format('[B_GetBufferLen](%d) --> %d', [EnumType, BuffLen]));
    {$ENDIF}

    // Error Returned No Need To Continue
    if (BuffLen > ARG_PPLB_ERROR) or (BuffLen = 0) then Exit;

    // Allocate Buffer
    Buffer := AllocMem(BuffLen);
    try
      // Enumerate Devices
      case EnumType of
        ARG_DEF_USB: FPPLBDebug := FWinPPLB.B_EnumUSB(Buffer);
        ARG_DEF_NET: FPPLBDebug := FWinPPLB.B_EnumNetPrinter(Buffer);
      end;

      {$IFDEF V400DEBUG}
        OutputDebug(Format('[B_EnumPrinter](%d) --> %d', [EnumType, FPPLBDebug]));
      {$ENDIF}

      // Copy To String
      CopyString(Buffer, BuffLen, BuffStr);
    finally
      // Free Allocated Memory
      FreeMem(Buffer);
    end;

    BuffStr := Trim(BuffStr);

    // Add Enumerated Printers
    ParseEnum(BuffStr, EnumType);
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.EnumDevices] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
  end;
end; // EnumDevices

{------------------------------------------------------------------------------}

destructor TArgox.Destroy;
begin
  try
    // Close Printer
    if FPPLBLoaded then
    begin
      // Stop Printer
      FWinPPLB.B_ClosePrn();

      {$IFDEF V400DEBUG}
        OutputDebug('[B_ClosePrn]');
      {$ENDIF}
    end;

    // Clear Device Enumeration
    DeleteEnum;

    // Release PPLB API
    FWinPPLB.Free;

    // Reset Load Flag
    FPPLBLoaded := False;

    inherited;
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.Destroy] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
    FPPLBLoaded := False;
  end;
end; // Destroy

{------------------------------------------------------------------------------}

function TArgox.DrawLabel(const CatalogNum: string; const SerialNum: string = ''): Boolean;
begin
  Result := False;

  // Check Serial Number
  if (Length(Trim(SerialNum)) > 0) then
  begin
    // Print Both Catalog And Serial Number
    // Print Catalog Number
    if PrintBarCode(ARG_X_DEF_COORD, ARG_Y_MUL_CAT_NUM, CatalogNum, True) then
    begin
      // Print Serial number
      Result := PrintBarCode(ARG_X_DEF_COORD, ARG_Y_MUL_SER_NUM, SerialNum, False);
    end;
  end
  else
  begin
    // Serial Number Missing, Use Catalog Number Only Case
    Result := PrintBarCode(ARG_X_DEF_COORD, ARG_Y_SNG_CAT_NUM, CatalogNum, False);
  end;
end; // DrawLabel

{------------------------------------------------------------------------------}

function TArgox.EnumPrinters: TEnumArray;
begin
  try
    // Clear Enumerated Printers
    DeleteEnum;

    // Enumerate USB Printers
    EnumDevices(ARG_DEF_USB);

    // Enumerate Network Printers
    EnumDevices(ARG_DEF_NET);

    // Return Device Enumeration
    Result := FPPLBEnum;
  except
    {$IFDEF V400DEBUG}
      OutputDebug(Format('[TArgox.EnumPrinters] | %s', [Exception(ExceptObject).Message]));
    {$ENDIF}
    // Error Value
    Result := nil;
  end;
end; // EnumPrinters

{------------------------------------------------------------------------------}
{ Misc Routines                                                                }
{------------------------------------------------------------------------------}

function LoadLib(var LibHandle: THandle; const LibName: string): Boolean;
begin
  LibHandle := 0;

  LibHandle := LoadLibrary(PChar(LibName));
  Result := (LibHandle <> 0);
end; // LoadLib

{------------------------------------------------------------------------------}

function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC;
  const FuncName: string): Boolean;
begin
  FuncPtr := nil;
  Result := False;

  if (LibHandle <> 0) then
  begin
    FuncPtr := GetProcAddress(LibHandle, PChar(FuncName));
    Result := Assigned(FuncPtr);
  end;
end; // LoadFunc

{------------------------------------------------------------------------------}

procedure ReleaseLib(var LibHandle: THandle);
begin
  if (LibHandle <> 0) then
  begin
    FreeLibrary(LibHandle);
    LibHandle := 0;
  end;
end; // ReleaseLib

{------------------------------------------------------------------------------}

procedure OutputDebug(const DebugMessage: string);
var
  FileHandle : THandle;
  TempText   : string;
  TempDate   : string;

const
  DBG_FILE_BEGIN = 0;
  DBG_FILE_END   = 2;

begin
  try
    TempDate := FormatDateTime('dd/mm/yyyy hh:nn:ss:zzz', Now);
    TempText := Format('[%s]%s', [TempDate, Trim(DebugMessage)]) + #13#10;

    {$IFDEF V400DEBUG_VIEW}
      OutputDebugString(PChar(TempText));
    {$ENDIF}

    if FileExists(ARG_FILE_NAME) then
      FileHandle := FileOpen(ARG_FILE_NAME, fmOpenReadWrite)
    else
      FileHandle := FileCreate(ARG_FILE_NAME);

    // Check File Opened
    if (FileHandle = INVALID_HANDLE_VALUE) then Exit;

    try
      // If File BIGGER Than 200k Truncate
      if (GetFileSize(FileHandle, nil) > 204800) then
        FileSeek(FileHandle, 0, DBG_FILE_BEGIN)
      else
        FileSeek(FileHandle, 0, DBG_FILE_END);

      // Write Log Message
      FileWrite(FileHandle, Pointer(TempText)^, Length(TempText));
      // Truncate File
      SetEndOfFile(FileHandle);
    finally
      FileClose(FileHandle);
    end;
  except
    //
  end;
end; // OutputDebug

{------------------------------------------------------------------------------}

end.

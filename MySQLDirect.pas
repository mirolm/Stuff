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

unit MySQLDirect;

interface

uses Windows;

// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //

type
  PMYSQL            = Pointer;  // Structure Not Needed
  PMYSQL_RES        = Pointer;  // Structure Not Needed
  MYSQL_ROW         = ^PChar;   // Better Than Fixed Array

  PMYSQL_FIELD = ^MYSQL_FIELD;
  MYSQL_FIELD = record
    name:             PChar;    // Name Of Column
    org_name:         PChar;    // Original Column Name, If An Alias
    table:            PChar;    // Table Of Column If Column Was A Field
    org_table:        PChar;    // Original Table Name If Table Was An Alias
    db:               PChar;    // Database For Table
    catalog:          PChar;    // Catalog For Table
    def:              PChar;    // Default Value (Set By 'mysql_list_fields')
    length:           LongWord; // Width Of Column
    max_length:       LongWord; // Max Width Of Selected Set
    name_length:      Cardinal;
    org_name_length:  Cardinal;
    table_length:     Cardinal;
    org_table_length: Cardinal;
    db_length:        Cardinal;
    catalog_length:   Cardinal;
    def_length:       Cardinal;
    flags:            Cardinal; // Div Flags
    decimals:         Cardinal; // Number Of Decimals In Field
    charsetnr:        Cardinal; // Character Set
    _type:            Cardinal; // Type Of Field. See 'mysql_com.h' For Types
  end;

// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //

const
  LIB_MYSQL                    = 'libmysql.dll';

  FUN_MYSQL_ERR_NO             = 'mysql_errno';
  FUN_MYSQL_ERROR              = 'mysql_error';
  FUN_MYSQL_SQL_STATE          = 'mysql_sqlstate';
  FUN_MYSQL_INIT               = 'mysql_init';
  FUN_MYSQL_OPTIONS            = 'mysql_options';
  FUN_MYSQL_REAL_CONNECT       = 'mysql_real_connect';
  FUN_MYSQL_SELECT_DB          = 'mysql_select_db';
  FUN_MYSQL_CLOSE              = 'mysql_close';
  FUN_MYSQL_PING               = 'mysql_ping';
  FUN_MYSQL_REAL_QUERY         = 'mysql_real_query';
  FUN_MYSQL_AFFECTED_ROWS      = 'mysql_affected_rows';
  FUN_MYSQL_NUM_ROWS           = 'mysql_num_rows';
  FUN_MYSQL_INSERT_ID          = 'mysql_insert_id';
  FUN_MYSQL_ESCAPE_STRING      = 'mysql_escape_string';
  FUN_MYSQL_HEX_STRING         = 'mysql_hex_string';
  FUN_MYSQL_STORE_RESULT       = 'mysql_store_result';
  FUN_MYSQL_FREE_RESULT        = 'mysql_free_result';
  FUN_MYSQL_FETCH_ROW          = 'mysql_fetch_row';
  FUN_MYSQL_FETCH_LENGTHS      = 'mysql_fetch_lengths';
  FUN_MYSQL_NUM_FIELDS         = 'mysql_num_fields';
  FUN_MYSQL_FETCH_FIELD_DIRECT = 'mysql_fetch_field_direct';

const
  MYSQL_OPT_RECONNECT          = 20; // Attempt Auto Reconnect

type
  TMySqlErrNo = function(mysql: PMYSQL): Cardinal; stdcall;
  TMySqlError = function(mysql: PMYSQL): PChar; stdcall;
  TMySqlSqlState = function(mysql: PMYSQL): PChar; stdcall;
  TMySqlInit = function(mysql: PMYSQL): PMYSQL; stdcall;
  TMySqlOptions = function(mysql: PMYSQL; option: Cardinal; arg: PChar): Integer; stdcall;
  TMySqlRealConnect = function(mysql: PMYSQL; host, user, passwd, db: PChar;
    port: Cardinal; unix_socket: PChar; client_flag: LongWord): PMYSQL; stdcall;
  TMySqlSelectDb = function(mysql: PMYSQL; db: PChar): Integer; stdcall;
  TMySqlClose = procedure(mysql: PMYSQL); stdcall;
  TMySqlPing = function(mysql: PMYSQL): Integer; stdcall;
  TMySqlRealQuery = function(mysql: PMYSQL; stmt_str: PChar; length: LongWord): Integer; stdcall;
  TMySqlAffectedRows = function(mysql: PMYSQL): Int64; stdcall;
  TMySqlNumRows = function(result: PMYSQL_RES): Int64; stdcall;
  TMySqlInsertId = function(mysql: PMYSQL): Int64; stdcall;
  TMySqlEscapeString = function(_to, from: PChar; length: LongWord): LongWord; stdcall;
  TMySqlHexString = function(_to, from: PChar; length: LongWord): LongWord; stdcall;
  TMySqlStoreResult = function(mysql: PMYSQL): PMYSQL_RES; stdcall;
  TMySqlFreeResult = procedure(result: PMYSQL_RES); stdcall;
  TMySqlFetchRow = function(result: PMYSQL_RES): MYSQL_ROW; stdcall;
  TMySqlFetchLengths = function(result: PMYSQL_RES): PLongWord; stdcall;
  TMySqlNumFields = function(result: PMYSQL_RES): Cardinal; stdcall;
  TMySqlFetchFieldDirect = function(result: PMYSQL_RES; fieldnr: Cardinal): PMYSQL_FIELD; stdcall;

// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //

const
  DEF_HOST     = 'localhost';              // Default Host
  DEF_PORT     = 3306;                     // Default Port
  DEF_ERROR    = 'Unknown MySQL Error...'; // Default Error String
  DEF_NO_CONN  = -1;                       // Default Error Result
  DEF_STATE    = '00000';                  // Default SQL State
  DEF_NO_STR   = '';                       // Default Error String
  DEF_FAIL     = 'Failed';                 // For No Connection Errors
  DEF_NO_ERR   = 0;                        // No Error Everything Good

  ERR_FORMAT_S = '%s | %s';                // Exception Format
  ERR_FORMAT_D = '%d (#%s) - %s';          // MySQL Error Format
  ERR_INIT     = 'Could Not Init';
  ERR_CONN     = 'Connection Closed';
  HEX_FORMAT   = '0x%s';                   // 0xHEX_STRING Format

// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //
// -------------------------------------------------------------------------- //

type
  TMySQLConnection = class
  private
    // Connection
    FServerHost: string;
    FServerPort: Cardinal;
    FDBSchema: string;
    FUserName: string;
    FPassword: string;
    FConnection: PMYSQL;
    // Query
    FQueryResult: PMYSQL_RES;
    FResultRow: MYSQL_ROW;
    FResultLenghts: PLongWord;
    FFieldNames: array of string;
    // Other
    FTag: Integer;

    // Error Handling
    function GetError: string;
    // Query Helper
    procedure GetFieldNames;
    function GetFieldIndex(const FieldName: string): Integer;
    function GetFieldValue(const FieldName: string): string;
  public
    constructor Create(const ServerHost: string; ServerPort: Cardinal;
      const DBSchema, UserName, Password: string);
    destructor Destroy; override;

    // Keeps Pool ConnectionId
    property Tag: Integer read FTag write FTag;

    // Connection Manage
    procedure OpenConnection;
    procedure CloseConnection;
    function Connected: Boolean;
    function Spawn: TMySQLConnection;

    // Execute Query
    procedure ExecuteQuery(const SQLCommand: string);
    function RowsAffected: Int64;
    function LastInsertId: Int64;
    // Select Query
    procedure OpenQuery(const SQLCommand: string);
    procedure CloseQuery;
    function First: Boolean;
    function Next: Boolean;
    function Eof: Boolean;
    // Query Result
    function FieldByName(const FieldName: string): string;
    function FieldByNameInt(const FieldName: string): Integer;
  end;

// Other Routines
function MySqlEscapeString(const InputStr: string; ToHex: Boolean = False): string;

// Loader Routines
function InitLib: Boolean;
procedure FreeLib;

function LoadLib(var LibHandle: THandle; const LibName: string): Boolean;
function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC; const FuncName: string): Boolean;
function ReleaseLib(var LibHandle: THandle): Boolean;

var
  // Is MySQL Init Properly
  IsMySQLOk: Boolean = False;

  // MySQL Library Handle
  MySQLHandle: THandle = 0;

  // Loaded Procedures
  mysql_errno: TMySqlErrNo = nil;
  mysql_error: TMySqlError = nil;
  mysql_sqlstate: TMySqlSqlState = nil;
  mysql_init: TMySqlInit = nil;
  mysql_options: TMySqlOptions = nil;
  mysql_real_connect: TMySqlRealConnect = nil;
  mysql_select_db: TMySqlSelectDb = nil;
  mysql_close: TMySqlClose = nil;
  mysql_ping: TMySqlPing = nil;
  mysql_real_query: TMySqlRealQuery = nil;
  mysql_affected_rows: TMySqlAffectedRows = nil;
  mysql_num_rows: TMySqlNumRows = nil;
  mysql_insert_id: TMySqlInsertId = nil;
  mysql_escape_string: TMySqlEscapeString = nil;
  mysql_hex_string: TMySqlHexString = nil;
  mysql_store_result: TMySqlStoreResult = nil;
  mysql_free_result: TMySqlFreeResult = nil;
  mysql_fetch_row: TMySqlFetchRow = nil;
  mysql_fetch_lengths: TMySqlFetchLengths = nil;
  mysql_num_fields: TMySqlNumFields = nil;
  mysql_fetch_field_direct: TMySqlFetchFieldDirect = nil;

implementation

uses SysUtils;

{ MySQLConnection }

constructor TMySQLConnection.Create(const ServerHost: string; ServerPort: Cardinal;
  const DBSchema, UserName, Password: string);
begin
  inherited Create;

  // Connection
  if (Length(Trim(ServerHost)) > 0) then
    FServerHost := ServerHost
  else
    FServerHost := DEF_HOST;

  if (ServerPort > 0) then
    FServerPort := ServerPort
  else
    FServerPort := DEF_PORT;

  FDBSchema := DBSchema;
  FUserName := UserName;
  FPassword := Password;

  FConnection := nil;

  // Query
  FQueryResult := nil;
  FResultRow := nil;
  FResultLenghts := nil;
  SetLength(FFieldNames, 0);

  // Keeps Pool ConnectionId
  FTag := DEF_NO_CONN;
end;

destructor TMySQLConnection.Destroy;
begin
  // Close Connection If Open
  // Close Query Too
  CloseConnection();

  inherited Destroy;
end;

// Connection Manage
procedure TMySQLConnection.OpenConnection;
var
  MyErrorMsg : string;
  MyBool     : Byte;

begin
  // MySQLLib Not Init Properly...
  if (IsMySQLOk = False) then
  begin
    // Just To Be Sure
    CloseConnection();

    // Throw Exception
    raise Exception.CreateFmt(ERR_FORMAT_S, [ERR_INIT, LIB_MYSQL]);
  end;

  if Assigned(FConnection) then
  begin
    // Check Connection Still Open
    // ReUse If Already Open
    if (Connected() = False) then
    begin
      // Get Error Before Connection Close
      MyErrorMsg := GetError();

      // Connection Is Dead
      CloseConnection();

      // Throw Exception
      raise Exception.CreateFmt(ERR_FORMAT_S, [FUN_MYSQL_PING, MyErrorMsg]);
    end;
  end
  else
  begin
    // Just To Be Sure
    CloseConnection();

    // No Connection
    FConnection := mysql_init(nil);
    if Assigned(FConnection) then
    begin
      // Set To False
      MyBool := 0;

      // Do Not ReConnect. Connection Is Closed On Every Error
      // No Need To Check Result. Older Versions Off By Default
      mysql_options(FConnection, MYSQL_OPT_RECONNECT, @MyBool);

      // Connect To MySQL Server
      FConnection := mysql_real_connect(FConnection, PChar(FServerHost),
        PChar(FUserName), PChar(FPassword), nil, FServerPort, nil, 0);
      if Assigned(FConnection) then
      begin
        // Select Default Schema
        // If User Have No Access Error Returned
        if (mysql_select_db(FConnection, PChar(FDBSchema)) <> DEF_NO_ERR) then
        begin
          // Get Error Before Connection Close
          MyErrorMsg := GetError();

          // Free Resources
          CloseConnection();

          // Throw Exception
          raise Exception.CreateFmt(ERR_FORMAT_S, [FUN_MYSQL_SELECT_DB, MyErrorMsg]);
        end;
      end
      else
      begin
        // Just To Be Sure
        CloseConnection();

        // Throw Exception
        raise Exception.CreateFmt(ERR_FORMAT_S, [FUN_MYSQL_REAL_CONNECT, DEF_FAIL]);
      end;
    end
    else
    begin
      // Just To Be Sure
      CloseConnection();

      // Throw Exception
      raise Exception.CreateFmt(ERR_FORMAT_S, [FUN_MYSQL_INIT, DEF_FAIL]);
    end;
  end;
end;

procedure TMySQLConnection.CloseConnection;
begin
  try
    // Close Open Queries
    // Free Client Resources
    CloseQuery();

    if Assigned(FConnection) then
    begin
      try
        // Close Connection To Server
        mysql_close(FConnection);
      except
        // Bad Connection
      end;
    end;
  finally
    FConnection := nil;
  end;
end;

function TMySQLConnection.Connected: Boolean;
begin
  Result := False;

  if Assigned(FConnection) then
  begin
    // Check Connection Still Open
    if (mysql_ping(FConnection) = DEF_NO_ERR) then
    begin
      Result := True;
    end;
  end;
end;

function TMySQLConnection.Spawn: TMySQLConnection;
begin
  // Make Copy Of Connection
  Result := TMySQLConnection.Create(FServerHost, FServerPort, FDBSchema, FUserName, FPassword);
end;

// Execute Query
procedure TMySQLConnection.ExecuteQuery(const SQLCommand: string);
begin
  if Assigned(FConnection) then
  begin
    // Close Query If Open
    CloseQuery();

    // Execute Statement
    if (mysql_real_query(FConnection, PChar(SQLCommand), Length(SQLCommand)) <> DEF_NO_ERR) then
    begin
      // Just To Be Sure
      CloseQuery();

      // Throw Exception
      raise Exception.CreateFmt(ERR_FORMAT_S, [FUN_MYSQL_REAL_QUERY, GetError()]);
    end;
  end
  else
  begin
    // Just To Be Sure
    CloseQuery();

    // Throw Exception
    raise Exception.CreateFmt(ERR_FORMAT_S, [ERR_CONN, DEF_FAIL]);
  end;
end;

function TMySQLConnection.RowsAffected: Int64;
begin
  Result := DEF_NO_CONN;

  // Get Number Of Affected/Returned Rows By Query
  if Assigned(FConnection) then
  begin
    // Get Only If Executed Good
    if (mysql_errno(FConnection) = DEF_NO_ERR) then
    begin
      // Call Right Function Depending On SQL Type
      if Assigned(FQueryResult) then
        Result := mysql_num_rows(FQueryResult)
      else
        Result := mysql_affected_rows(FConnection);
    end;
  end;
end;

function TMySQLConnection.LastInsertId: Int64;
begin
  Result := DEF_NO_CONN;

  // Get Last Auto Increment Value
  // Generated By Current Connection
  if Assigned(FConnection) then
  begin
    // If Previous Query Executed Good Get The Insert Id
    // On Error Function Result Undefined No Neeed To Call
    if (mysql_errno(FConnection) = DEF_NO_ERR) then
    begin
      Result := mysql_insert_id(FConnection);
    end;
  end;
end;

// Select Query
procedure TMySQLConnection.OpenQuery(const SQLCommand: string);
begin
  if Assigned(FConnection) then
  begin
    // !!! CloseQuery Is Called !!!
    // !!! In ExecuteQuery      !!!
    ExecuteQuery(SQLCommand);

    // Get All Records Returned
    // Prevent COMMANDS_OUT_OF_SYNC Errors
    FQueryResult := mysql_store_result(FConnection);
    if Assigned(FQueryResult) then
    begin
      // Errors Are Reset After Success
      // Sometimes There Is Error And Result
      if (mysql_errno(FConnection) = DEF_NO_ERR) then
      begin
        // Cache Query Filed Names
        GetFieldNames();
      end
      else
      begin
        // Just To Be Sure
        CloseQuery();

        // Throw Exception
        raise Exception.CreateFmt(ERR_FORMAT_S, [FUN_MYSQL_STORE_RESULT, GetError()]);
      end;
    end
    else
    begin
      // Just To Be Sure
      CloseQuery();

      // Throw Exception
      raise Exception.CreateFmt(ERR_FORMAT_S, [FUN_MYSQL_STORE_RESULT, GetError()]);
    end;
  end
  else
  begin
    // Just To Be Sure
    CloseQuery();

    // Throw Exception
    raise Exception.CreateFmt(ERR_FORMAT_S, [ERR_CONN, DEF_FAIL]);
  end;
end;

procedure TMySQLConnection.CloseQuery;
begin
  try
    if Assigned(FQueryResult) then
    begin
      try
        // Free Fetched Rows
        mysql_free_result(FQueryResult);
      except
        // Bad Query
      end;
    end;
  finally
    FQueryResult := nil;
    FResultRow := nil;
    FResultLenghts := nil;
    SetLength(FFieldNames, 0);
  end;
end;

function TMySQLConnection.Next: Boolean;
begin
  Result := False;

  if Assigned(FQueryResult) then
  begin
    // Get Single Record
    FResultRow := mysql_fetch_row(FQueryResult);
    // Get Record Data Values Lenghts
    FResultLenghts := mysql_fetch_lengths(FQueryResult);
    // Check Valid
    if Assigned(FResultRow) and Assigned(FResultLenghts) then
    begin
      Result := True;
    end;
  end;
end;

function TMySQLConnection.First: Boolean;
begin
  Result := Next();
end;

function TMySQLConnection.Eof: Boolean;
begin
  if Assigned(FResultRow) and Assigned(FResultLenghts) then
    Result := False
  else
    Result := True;
end;

// Query Result
function TMySQLConnection.FieldByName(const FieldName: string): string;
begin
  Result := GetFieldValue(FieldName);
end;

function TMySQLConnection.FieldByNameInt(const FieldName: string): Integer;
begin
  // Return Default Value On Error
  Result := StrToIntDef(GetFieldValue(FieldName), DEF_NO_CONN);
end;

// Query Helper
procedure TMySQLConnection.GetFieldNames;
var
  FieldCount : Cardinal;
  i          : Cardinal;
  Field      : PMYSQL_FIELD;

begin
  if Assigned(FQueryResult) then
  begin
    // Get Query Field Count
    FieldCount := mysql_num_fields(FQueryResult);
    if (FieldCount > 0) then
    begin
      SetLength(FFieldNames, FieldCount);

      for i := Low(FFieldNames) to High(FFieldNames) do
      begin
        // Set By Default
        FFieldNames[i] := DEF_NO_STR;

        // Many Select Queries May Lead
        // To Memory Fragmentation
        Field := mysql_fetch_field_direct(FQueryResult, i);
        if Assigned(Field) then
        begin
          // Transfer Names To Array
          if Assigned(Field^.name) and (Field^.name_length > 0) then
          begin
            // May Occur Fragmentation
            SetLength(FFieldNames[i], Field^.name_length);
            Move(Pointer(Field^.name)^, Pointer(FFieldNames[i])^, Field^.name_length);
          end;
        end;
      end;
    end;
  end;
end;

function TMySQLConnection.GetFieldIndex(const FieldName: string): Integer;
var
  i         : Integer;
  FieldDest : string;

begin
  Result := DEF_NO_CONN;

  // Field Names Cached To Speed Up
  for i := Low(FFieldNames) to High(FFieldNames) do
  begin
    FieldDest := FFieldNames[i];

    // Hope Compare Is Fast Enought
    if AnsiSameText(FieldName, FieldDest) then
    begin
      Result := i;
      // Leave Loop Field Found
      Break;
    end;
  end;
end;

function TMySQLConnection.GetFieldValue(const FieldName: string): string;
var
  FieldIndex : Integer;
  PDataRow   : MYSQL_ROW;
  ResultPrt  : PChar;
  PDataLen   : PLongWord;
  ResultLen  : LongWord;

begin
  Result := DEF_NO_STR;

  if Assigned(FResultRow) and Assigned(FResultLenghts) then
  begin
    FieldIndex := GetFieldIndex(FieldName);
    if (FieldIndex <> DEF_NO_CONN) then
    begin
      // Keep Original Pointers UnModified
      PDataRow := FResultRow;
      PDataLen := FResultLenghts;

      // Goto Needed Field
      Inc(PDataRow, FieldIndex);
      Inc(PDataLen, FieldIndex);

      // Retrieve Value And Length
      ResultPrt := PDataRow^;
      ResultLen := PDataLen^;

      // Copy Field Value
      if Assigned(ResultPrt) and (ResultLen > 0) then
      begin
        // May Occur Fragmentation
        SetLength(Result, ResultLen);
        Move(Pointer(ResultPrt)^, Pointer(Result)^, ResultLen);
      end;
    end;
  end;
end;

// Error Handling
function TMySQLConnection.GetError: string;
var
  ErrorNumber  : Cardinal;
  PErrorState  : PChar;
  ErrorState   : string;
  PErrorString : PChar;
  ErrorString  : string;

begin
  // Return Formatted Error Message
  if Assigned(FConnection) then
  begin
    ErrorNumber := mysql_errno(FConnection);

    // Just To Be Sure
    PErrorString := mysql_error(FConnection);
    if Assigned(PErrorString) then
      ErrorString := PErrorString
    else
      ErrorString := DEF_ERROR;

    // Just To Be Sure
    PErrorState := mysql_sqlstate(FConnection);
    if Assigned(PErrorState) then
      ErrorState := PErrorState
    else
      ErrorState := DEF_STATE;
  end
  else
  begin
    ErrorString := DEF_ERROR;
    ErrorNumber := DEF_NO_ERR;
    ErrorState  := DEF_STATE;
  end;

  // !!! Error Code DbExpress Return IN ErrorState !!!
  // !!! ErrorNumber <> ErrorState                 !!!
  Result := Format(ERR_FORMAT_D, [ErrorNumber, ErrorState, ErrorString]);
end;

// Other Routines
function MySqlEscapeString(const InputStr: string; ToHex: Boolean = False): string;
var
  InputLen  : LongWord;
  OutputLen : LongWord;
  OutputBuf : PChar;
  OutputVal : string;

begin
  Result := DEF_NO_STR;

  // Check MySqlLib Loaded
  if IsMySQLOk then
  begin
    InputLen := Length(InputStr);
    if (InputLen > 0) then
    begin
      // May Occur Fragmentation
      OutputBuf := AllocMem((InputLen + 1) * 2);
      try
        // Convert Data According To Flag
        if ToHex then
          OutputLen := mysql_hex_string(OutputBuf, PChar(InputStr), InputLen)
        else
          OutputLen := mysql_escape_string(OutputBuf, PChar(InputStr), InputLen);

        if Assigned(OutputBuf) and (OutputLen > 0) then
        begin
          // May Occur Fragmentation
          SetLength(OutputVal, OutputLen);
          Move(Pointer(OutputBuf)^, Pointer(OutputVal)^, OutputLen);

          // Return Correct Value
          // To Be Decoded Format 0xHEX_STRING. No Quotes.
          if ToHex then
            Result := Format(HEX_FORMAT, [OutputVal])
          else
            Result := OutputVal;
        end;
      finally
        FreeMem(OutputBuf);
      end;
    end;
  end;
end;

// Library Initialization
function LoadLib(var LibHandle: THandle; const LibName: string): Boolean;
begin
  LibHandle := 0;

  LibHandle := LoadLibrary(PChar(LibName));
  if (LibHandle <> 0) then
    Result := True
  else
    Result := False;
end;

function LoadFunc(LibHandle: THandle; var FuncPtr: FARPROC;
  const FuncName: string): Boolean;
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
  Result := False;

  try
    if (LoadLib(MySQLHandle, LIB_MYSQL) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_errno, FUN_MYSQL_ERR_NO) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_error, FUN_MYSQL_ERROR) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_sqlstate, FUN_MYSQL_SQL_STATE) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_init, FUN_MYSQL_INIT) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_options, FUN_MYSQL_OPTIONS) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_real_connect, FUN_MYSQL_REAL_CONNECT) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_select_db, FUN_MYSQL_SELECT_DB) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_close, FUN_MYSQL_CLOSE) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_ping, FUN_MYSQL_PING) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_real_query, FUN_MYSQL_REAL_QUERY) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_affected_rows, FUN_MYSQL_AFFECTED_ROWS) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_num_rows, FUN_MYSQL_NUM_ROWS) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_insert_id, FUN_MYSQL_INSERT_ID) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_escape_string, FUN_MYSQL_ESCAPE_STRING) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_hex_string, FUN_MYSQL_HEX_STRING) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_store_result, FUN_MYSQL_STORE_RESULT) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_free_result, FUN_MYSQL_FREE_RESULT) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_fetch_row, FUN_MYSQL_FETCH_ROW) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_fetch_lengths, FUN_MYSQL_FETCH_LENGTHS) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_num_fields, FUN_MYSQL_NUM_FIELDS) = False) then Exit;
    if (LoadFunc(MySQLHandle, @mysql_fetch_field_direct, FUN_MYSQL_FETCH_FIELD_DIRECT) = False) then Exit;

    Result := True;
  except
    Result := False;
  end;
end;

procedure FreeLib;
begin
  IsMySQLOk := False;

  mysql_errno := nil;
  mysql_error := nil;
  mysql_sqlstate := nil;
  mysql_init := nil;
  mysql_options := nil;
  mysql_real_connect := nil;
  mysql_select_db := nil;
  mysql_close := nil;
  mysql_ping := nil;
  mysql_real_query := nil;
  mysql_affected_rows := nil;
  mysql_num_rows := nil;
  mysql_insert_id := nil;
  mysql_escape_string := nil;
  mysql_hex_string := nil;
  mysql_store_result := nil;
  mysql_free_result := nil;
  mysql_fetch_row := nil;
  mysql_fetch_lengths := nil;
  mysql_num_fields := nil;
  mysql_fetch_field_direct := nil;

  ReleaseLib(MySQLHandle);
end;

initialization
  // Get Library Init Status
  IsMySQLOk := InitLib();

finalization
  // Detach From Library
  FreeLib();

end.

/** @file
  This application is supposed to send all of memory to a TCP4 server.

**/

#include "Forensics.h"

#define TimeOut 1000 // in ms

EFI_HII_HANDLE mForensicsHiiHandle;

//
// All allowed shell parameters for command
//
STATIC CONST SHELL_PARAM_ITEM ParamList[] = {
  {L"-i", TypeValue},
  {L"-p", TypeValue},
  {NULL , TypeMax}
  };

/**
  Transmit the Packet to the other endpoint of the socket.
  Custom implementation to replace TcpIoTransmit and streamline the process 
  for the exact requirements. Which are, amongst others, that this function
  should be able to transmit all the data even if it comprises more than
  4GiB alltogether.

  @param[in]  TcpIo               The TcpIo instance wrapping the Tcp4 socket
                                  with an established connection.
  @param[in]  FragmentTable       The array containing the memory fragments
                                  to be sent.
  @param[in]  FragmentCount       The amount of memory fragments.

  @retval EFI_SUCCESS             The transmission was successful.
  @retval EFI_INVALID_PARAMETER   One or more parameters are invalid.
  @retval EFI_OUT_OF_RESOURCES    Failed to allocate memory.
  @retval EFI_ABORTED             The transmission has been aborted.
  @retval Others                  Errors produced by Tcp4->Transmit().
**/
EFI_STATUS
TcpCustomTransmit (
  TCP_IO                    *TcpIo,
  EFI_TCP4_FRAGMENT_DATA    *FragmentTable,
  UINT32                    FragmentCount
  );

/**
  The function for the 'forensics' command.

  @param[in] ImageHandle            The firmware allocated handle for the EFI image.
  @param[in] SystemTable            A pointer to the EFI System Table.

  @retval SHELL_SUCCESS             Command completed successfully.
  @retval SHELL_ABORTED             Command execution aborted by user.
  @retval SHELL_NOT_FOUND           Command could not be completed with any Nic.
  @retval SHELL_INVALID_PARAMETER   Command was called with wrong parameters.
  @retval SHELL_ACCESS_DENIED       Command could not access the memory map.
**/
SHELL_STATUS
RunForensics (
  IN  EFI_HANDLE                ImageHandle,
  IN  EFI_SYSTEM_TABLE          *SystemTable
  )
{
  EFI_STATUS                    Status;
  SHELL_STATUS                  ShellStatus;
  LIST_ENTRY                    *CheckPackage;
  CHAR16                        *ProblemParam;
  CONST CHAR16                  *ValueStr;
  UINTN                         Value;
  UINTN                         MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR         *MemoryDescriptors;
  UINTN                         MemoryMapItemSize;
  UINTN                         HandleCount;
  EFI_HANDLE                    *Handles;
  UINTN                         NicNumber;
  TCP_IO_CONFIG_DATA            TcpIoConfigData;
  TCP_IO                        TcpIo;
  EFI_TCP4_PROTOCOL             *Tcp4;
  EFI_TCP4_CONFIG_DATA          TcpConfigData;
  EFI_EVENT                     TimeoutEvent;
  EFI_MEMORY_DESCRIPTOR         *Walker;
  BOOLEAN                       IsHeaderEnabled;
  UINT32                        TcpFragmentsBeforeMemoryRegion;
  UINT32                        TcpFragmentsOfMemoryRegion;
  LIME_MEM_RANGE_HEADER         *MemRangeHeader;
  UINT8                         *NullByte;
  EFI_TCP4_FRAGMENT_DATA        *TcpFragmentData;
  UINTN                         Counter;

  DEBUG ((EFI_D_INFO, "[Forensics] Start\n"));

  //
  // Initialize all necessary variables
  //
  ProblemParam            = NULL;
  MemoryMapSize           = 0;
  MemoryDescriptors       = NULL;
  Handles                 = NULL;

  // Will need to reconfigure TCP4 instance after TcpIoCreateSocket() because 
  // there is no option to use configuration with default dhcp values
  ZeroMem (&TcpIoConfigData, sizeof(TCP_IO_CONFIG_DATA));

  // Set up the TCP4 configuration
  TcpConfigData.TypeOfService                 = 8;    // High throughput
  TcpConfigData.TimeToLive                    = 255;  // Max value
  TcpConfigData.ControlOption                 = NULL; // implementation specific
                                                      // defaults to be used
  TcpConfigData.AccessPoint.UseDefaultAddress = TRUE; // Use DHCP
  TcpConfigData.AccessPoint.StationPort       = 0;    // Use any port
  TcpConfigData.AccessPoint.ActiveFlag        = TRUE; // Take active part in
                                                      // building a connection

  Status = NetLibStrToIp4 (
            PcdGetPtr (PcdForensicsServerIp),
            &TcpConfigData.AccessPoint.RemoteAddress
            );
  ASSERT_EFI_ERROR (Status);

  TcpConfigData.AccessPoint.RemotePort = PcdGet16 (PcdForensicsServerPort);

  IsHeaderEnabled = PcdGetBool (PcdForensicsHeaderEnabled);

  //
  // Disable Watchdog Timer so code execution isn't stopped after 5 mins
  //
  gBS->SetWatchdogTimer(0, 0, 0, NULL);

  ShellStatus = SHELL_INVALID_PARAMETER;

  //
  // Parse the command line.
  //
  Status = ShellCommandLineParse (ParamList, &CheckPackage, &ProblemParam, TRUE);
  if (EFI_ERROR (Status)) {
    if ((Status == EFI_VOLUME_CORRUPTED) && (ProblemParam != NULL)) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_GEN_PROBLEM),
        mForensicsHiiHandle,
        L"forensics",
        ProblemParam
        );
      FreePool (ProblemParam);
    } else {
      ASSERT (FALSE);
    }
    goto Error;
  }

  //
  // Make sure there are no random positional parameters.
  //
  if (ShellCommandLineGetCount (CheckPackage) > 1) {
    ShellPrintHiiEx (
      -1, -1, NULL,
      STRING_TOKEN (STR_GEN_TOO_MANY),
      mForensicsHiiHandle,
      L"forensics"
      );
    goto Error;
  }

  //
  // Set server IP address if specified via shell
  //
  ValueStr = ShellCommandLineGetValue (CheckPackage, L"-i");
  if (ValueStr != NULL) {
    Status = NetLibStrToIp4 (ValueStr, &TcpConfigData.AccessPoint.RemoteAddress);
    if (EFI_ERROR (Status)) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_GEN_PARAM_INV),
        mForensicsHiiHandle,
        L"forensics",
        ValueStr
        );
      goto Error;
    }
  }

  //
  // Set the server port if specified via shell
  //
  ValueStr = ShellCommandLineGetValue (CheckPackage, L"-p");
  if (ValueStr != NULL) {
    Value = ShellStrToUintn (ValueStr);
    if (Value > MAX_UINT16) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_GEN_PARAM_INV),
        mForensicsHiiHandle,
        L"forensics",
        ValueStr
        );
      goto Error;
    }

    TcpConfigData.AccessPoint.RemotePort = (UINT16) Value;
  }

  //
  // Get the memory map to be able to traverse it
  //
  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  MemoryDescriptors,
                  NULL,
                  &MemoryMapItemSize,
                  NULL
                  );
  if (Status == EFI_BUFFER_TOO_SMALL) {

    // The size of the memory map can change between the calls
    MemoryMapSize += SIZE_1KB;

    // if NULL, GetMemoryMap will return Error
    MemoryDescriptors = AllocateZeroPool(MemoryMapSize);

    Status = gBS->GetMemoryMap (
                    &MemoryMapSize,
                    MemoryDescriptors,
                    NULL,
                    &MemoryMapItemSize,
                    NULL
                    );
  }
  if (EFI_ERROR (Status)) {
    ShellPrintHiiEx (
      -1, -1, NULL,
      STRING_TOKEN (STR_FORENSICS_ERR_MEMMAP),
      mForensicsHiiHandle
      );

    ShellStatus = SHELL_ACCESS_DENIED;
    goto Error;
  }

  //
  // Locate all Nic handles
  //
  ShellStatus = SHELL_NOT_FOUND;

  Status = gBS->LocateHandleBuffer (
                ByProtocol,
                &gEfiManagedNetworkServiceBindingProtocolGuid,
                NULL,
                &HandleCount,
                &Handles
                );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    ShellPrintHiiEx (
      -1, -1, NULL,
      STRING_TOKEN (STR_FORENSICS_ERR_NO_NIC),
      mForensicsHiiHandle
      );
    goto Error;
  }

  //
  // Go through all the Nics to transmit memory
  //
  for (
    NicNumber = 0;
    (NicNumber < HandleCount) && (ShellStatus != SHELL_SUCCESS);
    NicNumber++
    )
  {
    Tcp4    = NULL;

    //
    // Create the TcpIo structure wrapping the TCP4 socket
    //
    Status = TcpIoCreateSocket (
              ImageHandle,
              Handles[NicNumber],
              TCP_VERSION_4,
              &TcpIoConfigData,
              &TcpIo
              );
    if (EFI_ERROR (Status)) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_FORENSICS_ERR_CREATE_SOCKET),
        mForensicsHiiHandle,
        Status
        );
      goto NextHandle;
    }

    Tcp4 = TcpIo.Tcp.Tcp4;

    //
    // Reconfigure TCP4 instance wrapped by TcpIo
    //
    Tcp4->Configure (Tcp4, NULL);   // Tcp4 configuration has to be reset
                                    // before setting it again
    do {
      Status = Tcp4->Configure (Tcp4, &TcpConfigData);

      if (ShellGetExecutionBreakFlag()) {
        Status = EFI_ABORTED;
      }
    } while (Status == EFI_NO_MAPPING);  // Dhcp is not yet finished
    if (EFI_ERROR (Status)) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_FORENSICS_ERR_CONFIGURE),
        mForensicsHiiHandle,
        Status
        );
      goto NextHandle;
    }

    //
    // Connect to the server, try until timeout
    //
    Status = gBS->CreateEvent (
                    EVT_TIMER,
                    TPL_CALLBACK,
                    NULL,
                    NULL,
                    &TimeoutEvent
                    );
    if (EFI_ERROR (Status)) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_FORENSICS_ERR_EVENT_CREATE),
        mForensicsHiiHandle,
        Status
        );
      goto NextHandle;
    }

    Status = gBS->SetTimer (
                    TimeoutEvent,
                    TimerRelative,
                    TimeOut * TICKS_PER_MS
                    );
    if (EFI_ERROR (Status)) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_FORENSICS_ERR_TIMER_SET),
        mForensicsHiiHandle,
        Status
        );
      goto NextHandle;
    }

    Status = TcpIoConnect (&TcpIo, TimeoutEvent);
    gBS->SetTimer (TimeoutEvent, TimerCancel, 0);
    if (EFI_ERROR (Status)) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_FORENSICS_ERR_CONNECTION),
        mForensicsHiiHandle,
        Status
        );
      goto NextHandle;
    }

    //
    // Traverse the memorymap
    //
    ShellPrintHiiEx (
      -1, -1, NULL,
      STRING_TOKEN (STR_FORENSICS_START),
      mForensicsHiiHandle
      );

    for (
      Walker = MemoryDescriptors;
      Walker < (EFI_MEMORY_DESCRIPTOR *) ((UINT8 *)MemoryDescriptors + MemoryMapSize);
      Walker = (EFI_MEMORY_DESCRIPTOR *) ((UINT8 *)Walker + MemoryMapItemSize)
      )
    {
      MemRangeHeader          = NULL;
      NullByte                = NULL;
      TcpFragmentData         = NULL;

      //
      // Accounting for a memory descriptor spanning more than MAX_UINT32
      //
      TcpFragmentsOfMemoryRegion      = 1 + Walker->NumberOfPages * SIZE_4KB / MAX_UINT32;
      TcpFragmentsBeforeMemoryRegion  = 0;

      //
      // Generate LiME Memory Range Header
      // if IsHeaderEnabled
      //
      if (IsHeaderEnabled) {
        MemRangeHeader = AllocateZeroPool (sizeof (LIME_MEM_RANGE_HEADER));
        if (MemRangeHeader == NULL) {
          ShellPrintHiiEx (
            -1, -1, NULL,
            STRING_TOKEN (STR_FORENSICS_ERR_ALLOC),
            mForensicsHiiHandle
            );
          Status = EFI_OUT_OF_RESOURCES;
          goto Break;
        }

        MemRangeHeader->Magic           = LIME_MAGIC;
        MemRangeHeader->Version         = LIME_VERSION;
        MemRangeHeader->StartingAddress = Walker->PhysicalStart;
        MemRangeHeader->EndingAddress   = Walker->PhysicalStart - 1 +
                                          Walker->NumberOfPages * SIZE_4KB;

        TcpFragmentsBeforeMemoryRegion += 1;
      }

      //
      // Allocate a buffer containing one byte to account for 0x0 == NULL
      //
      if (Walker->PhysicalStart == 0) {
        NullByte = AllocateZeroPool (1);
        if (NullByte == NULL) {
          ShellPrintHiiEx (
            -1, -1, NULL,
            STRING_TOKEN (STR_FORENSICS_ERR_ALLOC),
            mForensicsHiiHandle
            );
          Status = EFI_OUT_OF_RESOURCES;
          goto Break;
        }

        TcpFragmentsBeforeMemoryRegion += 1;
      }

      //
      // Allocate the Tcp Fragment Array
      //
      TcpFragmentData = AllocateZeroPool (
                          sizeof (EFI_TCP4_FRAGMENT_DATA) * 
                          (TcpFragmentsBeforeMemoryRegion + TcpFragmentsOfMemoryRegion)
                          );
      if (TcpFragmentData == NULL) {
        ShellPrintHiiEx (
          -1, -1, NULL,
          STRING_TOKEN (STR_FORENSICS_ERR_ALLOC),
          mForensicsHiiHandle
          );
        Status = EFI_OUT_OF_RESOURCES;
        goto Break;
      }

      //
      // Fill in the header and / or the NullByte
      //
      if (IsHeaderEnabled) {
        TcpFragmentData[0].FragmentLength = sizeof (LIME_MEM_RANGE_HEADER);
        TcpFragmentData[0].FragmentBuffer = MemRangeHeader;
      }

      if (Walker->PhysicalStart == 0) {
        TcpFragmentData[TcpFragmentsBeforeMemoryRegion - 1].FragmentLength = 1;
        TcpFragmentData[TcpFragmentsBeforeMemoryRegion - 1].FragmentBuffer = NullByte;
      }

      //
      // Fill in the fragment(s) of the memory region
      //
      for (Counter = 0; Counter < TcpFragmentsOfMemoryRegion; Counter++) {
        if (Counter == TcpFragmentsOfMemoryRegion - 1) {
          TcpFragmentData[TcpFragmentsBeforeMemoryRegion + Counter].FragmentLength =
            (Walker->NumberOfPages * SIZE_4KB) % MAX_UINT32;
        } else {
          TcpFragmentData[TcpFragmentsBeforeMemoryRegion + Counter].FragmentLength =
            MAX_UINT32;
        }

        TcpFragmentData[TcpFragmentsBeforeMemoryRegion + Counter].FragmentBuffer =
          (VOID *) ((UINT8 *)Walker->PhysicalStart + MAX_UINT32 * Counter);
      }

      //
      // Correct the TcpFragmentData to account for 0x0 = NULL
      //
      if (Walker->PhysicalStart == 0) {
        TcpFragmentData[TcpFragmentsBeforeMemoryRegion].FragmentLength -= 1;
        TcpFragmentData[TcpFragmentsBeforeMemoryRegion].FragmentBuffer += 1;
      }

      //
      // Transmit the actual data
      //
      Status = TcpCustomTransmit (
                &TcpIo,
                TcpFragmentData,
                TcpFragmentsBeforeMemoryRegion + TcpFragmentsOfMemoryRegion
                );
      if (EFI_ERROR (Status)) {
        ShellPrintHiiEx (
          -1, -1, NULL,
          STRING_TOKEN (STR_FORENSICS_ERR_TRANSMISSION),
          mForensicsHiiHandle,
          Status
          );
        goto Break;
      }

      Break:

      if (MemRangeHeader != NULL) {
        FreePool (MemRangeHeader);
      }
      if (NullByte != NULL) {
        FreePool (NullByte);
      }
      if (TcpFragmentData != NULL) {
        FreePool (TcpFragmentData);
      }
      if (EFI_ERROR (Status)) {
        goto NextHandle;
      }
    }

    ShellStatus = SHELL_SUCCESS;

    NextHandle:

    if (ShellStatus != SHELL_SUCCESS) {
      ShellPrintHiiEx (
        -1, -1, NULL,
        STRING_TOKEN (STR_FORENSICS_ERR_NIC_FAILED),
        mForensicsHiiHandle,
        NicNumber,
        Status
        );
    }

    if (Status == EFI_ABORTED || ShellGetExecutionBreakFlag ()) {
      ShellStatus = SHELL_ABORTED;
    }

    // Close connection gracefully
    if (Tcp4 != NULL) {
      TcpIo.IsCloseDone = FALSE;
      Status = Tcp4->Close (Tcp4, &TcpIo.CloseToken.Tcp4Token);
      while (!EFI_ERROR (Status) && !TcpIo.IsCloseDone) {
        Tcp4->Poll (Tcp4);
      }
    }

    gBS->CloseEvent (TimeoutEvent);

    TcpIoDestroySocket (&TcpIo);

    if (ShellStatus == SHELL_ABORTED) {
      break;
    }
  }

  if (ShellStatus != SHELL_SUCCESS) {
    ShellPrintHiiEx (
      -1, -1, NULL,
      STRING_TOKEN (STR_FORENSICS_UNSUCCESSFUL),
      mForensicsHiiHandle
      );
  } else {
    ShellPrintHiiEx (
      -1, -1, NULL,
      STRING_TOKEN (STR_FORENSICS_SUCCESSFUL),
      mForensicsHiiHandle
      );
  }

  Error:

  ShellCommandLineFreeVarList (CheckPackage);

  if (MemoryDescriptors != NULL) {
    FreePool (MemoryDescriptors);
  }

  if (Handles != NULL) {
    FreePool (Handles);
  }

  DEBUG ((EFI_D_INFO, "[Forensics] End\n"));

  return ShellStatus;
}

/**
  Transmit the Packet to the other endpoint of the socket.
  Custom implementation to replace TcpIoTransmit and streamline the process 
  for the exact requirements. Which are, amongst others, that this function
  should be able to transmit all the data even if it comprises more than
  4GiB alltogether.

  @param[in]  TcpIo               The TcpIo instance wrapping the Tcp4 socket
                                  with an established connection.
  @param[in]  FragmentTable       The array containing the memory fragments
                                  to be sent.
  @param[in]  FragmentCount       The amount of memory fragments.

  @retval EFI_SUCCESS             The transmission was successful.
  @retval EFI_INVALID_PARAMETER   One or more parameters are invalid.
  @retval EFI_OUT_OF_RESOURCES    Failed to allocate memory.
  @retval EFI_ABORTED             The transmission has been aborted.
  @retval Others                  Errors produced by Tcp4->Transmit().
**/
EFI_STATUS
TcpCustomTransmit (
  TCP_IO                    *TcpIo,
  EFI_TCP4_FRAGMENT_DATA    *FragmentTable,
  UINT32                    FragmentCount
  )
{
  EFI_STATUS                Status;
  EFI_TCP4_PROTOCOL         *Tcp4;
  EFI_TCP4_TRANSMIT_DATA    *Data;
  UINTN                     Counter;

  if (
    (TcpIo == NULL) || (TcpIo->Tcp.Tcp4 == NULL) ||
    (FragmentTable == NULL) || (FragmentCount == 0)
    )
  {
    return EFI_INVALID_PARAMETER;
  }

  Tcp4 = TcpIo->Tcp.Tcp4;

  //
  // Set up the transmission data
  //
  Data = AllocatePool (
            sizeof (EFI_TCP4_TRANSMIT_DATA) +
            (FragmentCount - 1) * sizeof (EFI_TCP4_FRAGMENT_DATA)
            );
  if (Data == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Data->Push    = TRUE; // FragmentTable should span a lot of memory
  Data->Urgent  = FALSE;
  Counter       = 0;
  Status        = EFI_SUCCESS;

  //
  // Double loop to account for an overall size of > MAX_UINT32
  //
  while (Counter < FragmentCount && !EFI_ERROR (Status)) {
    Data->FragmentCount  = 0;
    Data->DataLength     = 0;

    while (Counter < FragmentCount) {
      if (FragmentTable[Counter].FragmentLength == 0) {
        Counter += 1;
        continue;
      }
      if (FragmentTable[Counter].FragmentBuffer == NULL) {
        Status = EFI_INVALID_PARAMETER;
        goto Error;
      }

      //
      // Would otherwise create overflow in Data->DataLength
      //
      if (
        (UINT64)Data->DataLength + (UINT64)FragmentTable[Counter].FragmentLength >
        MAX_UINT32
        ) 
      {
        break;
      }

      Data->FragmentTable[Data->FragmentCount].FragmentLength =
            FragmentTable[Counter].FragmentLength;
      Data->FragmentTable[Data->FragmentCount].FragmentBuffer =
            FragmentTable[Counter].FragmentBuffer;
      Data->DataLength += FragmentTable[Counter].FragmentLength;
      Data->FragmentCount += 1;
      Counter += 1;
    }

    if (Data->FragmentCount == 0) {
      Status = EFI_INVALID_PARAMETER;
      break;
    }

    TcpIo->TxToken.Tcp4Token.Packet.TxData = Data;
    TcpIo->IsTxDone = FALSE; 

    //
    // Start the transmission
    //
    Status  = Tcp4->Transmit (Tcp4, &TcpIo->TxToken.Tcp4Token);
    if (EFI_ERROR (Status)) {
      break;
    }

    //
    // Wait for the transmission to finish
    //
    while (!TcpIo->IsTxDone) {
      Tcp4->Poll (Tcp4);
    }
    Status = TcpIo->TxToken.Tcp4Token.CompletionToken.Status;

    if (ShellGetExecutionBreakFlag()) {
      Status = EFI_ABORTED;
    }
  }

  Error:

  FreePool (Data);

  return Status;
}

/**
  Retrive HII package list from ImageHandle and publish to HII database.

  @param ImageHandle            The image handle of the process.

  @return HII handle.
**/
EFI_STATUS
InitializeHiiPackage (
  EFI_HANDLE                    ImageHandle
  )
{
  EFI_STATUS                    Status;
  EFI_HII_PACKAGE_LIST_HEADER   *PackageList;

  //
  // Retrieve HII package list from ImageHandle
  //
  Status = gBS->OpenProtocol (
                  ImageHandle,
                  &gEfiHiiPackageListProtocolGuid,
                  (VOID **)&PackageList,
                  ImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Publish HII package list to HII Database.
  //
  Status = gHiiDatabase->NewPackageList (
                          gHiiDatabase,
                          PackageList,
                          NULL,
                          &mForensicsHiiHandle
                          );
  ASSERT_EFI_ERROR (Status);

  return Status;
}

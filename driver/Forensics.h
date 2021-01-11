/** @file
  Header file for 'forensics' command functions
**/

#ifndef _FORENSICS_H_
#define _FORENSICS_H_

#include <Uefi.h>

#include <Protocol/HiiPackageList.h>
#include <Protocol/ManagedNetwork.h>
#include <Protocol/ShellDynamicCommand.h>
#include <Protocol/Tcp4.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HiiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/NetLib.h>
#include <Library/PcdLib.h>
#include <Library/ShellLib.h>
#include <Library/TcpIoLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiHiiServicesLib.h>
#include <Library/UefiLib.h>

extern EFI_HII_HANDLE mForensicsHiiHandle;

/**
  LiME Memory Range Header Version 1 to structure memory
**/
#define LIME_MAGIC    0x4C694D45 // LiME
#define LIME_VERSION  1

typedef struct {
  UINT32  Magic;
  UINT32  Version;
  UINT64  StartingAddress;
  UINT64  EndingAddress;
  UINT8   Reserved[8];
} LIME_MEM_RANGE_HEADER;

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
  IN  EFI_HANDLE          ImageHandle,
  IN  EFI_SYSTEM_TABLE    *SystemTable
  );

/**
  Retrive HII package list from ImageHandle and publish to HII database.

  @param ImageHandle            The image handle of the process.

  @return HII handle.
**/
EFI_STATUS
InitializeHiiPackage (
  EFI_HANDLE                  ImageHandle
  );
#endif  // _FORENSICS_H_

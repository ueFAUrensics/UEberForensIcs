/** @file
  Entry point to the 'forensics' shell application
**/
#include "Forensics.h"

//
// String token ID of help message text.
// Shell supports to find help message in the resource section of an application image if
// .MAN file is not found. This global variable is added to make build tool recognizes
// that the help string is consumed by user and then build tool will add the string into
// the resource section. Thus the application can use '-?' option to show help message in
// Shell.
//
GLOBAL_REMOVE_IF_UNREFERENCED EFI_STRING_ID mStringHelpTokenId = STRING_TOKEN (STR_GET_HELP_FORENSICS);

/**
  Entry point of Forensics application.

  @param ImageHandle            The image handle of the process.
  @param SystemTable            The EFI System Table pointer.

  @retval EFI_SUCCESS           Application was executed successfully.
  @retval EFI_ABORTED           HII package was failed to initialize.
  @retval others                Other errors during execution.
**/
EFI_STATUS
EFIAPI
RunForensicsApp (
  IN EFI_HANDLE               ImageHandle,
  IN EFI_SYSTEM_TABLE         *SystemTable
  )
{
  EFI_STATUS                  Status;

  Status = InitializeHiiPackage (ImageHandle);
  if (EFI_ERROR (Status)) {
    return EFI_ABORTED;
  }

  Status = (EFI_STATUS)RunForensics (ImageHandle, SystemTable);

  HiiRemovePackages (mForensicsHiiHandle);

  return Status;
}

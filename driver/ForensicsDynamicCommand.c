/** @file
  Produce the 'forensics' shell dynamic command

**/
#include "Forensics.h"
#include <Protocol/ShellDynamicCommand.h>

/**
  This is the shell command handler function pointer callback type.  This
  function handles the command when it is invoked in the shell.

  @param[in] This                   The instance of the EFI_SHELL_DYNAMIC_COMMAND_PROTOCOL.
  @param[in] SystemTable            The pointer to the system table.
  @param[in] ShellParameters        The parameters associated with the command.
  @param[in] Shell                  The instance of the shell protocol used in the context
                                    of processing this command.

  @return EFI_SUCCESS               The operation was sucessful.
  @return other                     The operation failed.
**/
SHELL_STATUS
EFIAPI
ForensicsCommandHandler (
  IN EFI_SHELL_DYNAMIC_COMMAND_PROTOCOL    *This,
  IN EFI_SYSTEM_TABLE                      *SystemTable,
  IN EFI_SHELL_PARAMETERS_PROTOCOL         *ShellParameters,
  IN EFI_SHELL_PROTOCOL                    *Shell
  )
{
  //
  // ShellLib not initialized
  //
  gEfiShellParametersProtocol = ShellParameters;
  gEfiShellProtocol           = Shell;


  // After setting the gEfiShellParametersProtocol and the gEfiShellProtocol
  // we don't need to initialize anything else as we don't need it
  /*  //
  // Initialize the Shell library (we must be in non-auto-init...)
  // (<PcdsFixedAtBuild> gEfiShellPkgTokenSpaceGuid.PcdShellLibAutoInitialize must
  // be set to FALSE because shell is not yet initialized in DxE phase)
  //
  Status = ShellInitialize ();
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return SHELL_ABORTED;
  }*/

  return RunForensics (gImageHandle, SystemTable);
}

/**
  This is the command help handler function pointer callback type. This
  function is responsible for displaying help information for the associated
  command.

  @param[in] This       The instance of the EFI_SHELL_DYNAMIC_COMMAND_PROTOCOL.
  @param[in] Language   The pointer to the language string to use.

  @return string        Pool allocated help string, must be freed by caller
**/
CHAR16 *
EFIAPI
ForensicsCommandGetHelp (
  IN EFI_SHELL_DYNAMIC_COMMAND_PROTOCOL   *This,
  IN CONST CHAR8                          *Language
  )
{
  return HiiGetString (
          mForensicsHiiHandle,
          STRING_TOKEN (STR_GET_HELP_FORENSICS),
          Language
          );
}

EFI_SHELL_DYNAMIC_COMMAND_PROTOCOL mForensicsDynamicCommand = {
  L"forensics",
  ForensicsCommandHandler,
  ForensicsCommandGetHelp
};

/**
  Entry point of Forensics Dynamic Command.

  Produce the DynamicCommand protocol to handle 'forensics' command.

  @param ImageHandle            The image handle of the process.
  @param SystemTable            The EFI System Table pointer.

  @retval EFI_SUCCESS           Dynamic command is installed successfully.
  @retval others                Errors when trying to install command.
**/
EFI_STATUS
EFIAPI
ForensicsCommandInitialize (
  IN EFI_HANDLE                 ImageHandle,
  IN EFI_SYSTEM_TABLE           *SystemTable
  )
{
  EFI_STATUS                    Status;

  DEBUG ((EFI_D_INFO, "[Forensics] Initializing\n"));

  Status = InitializeHiiPackage (ImageHandle);
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ImageHandle,
                  &gEfiShellDynamicCommandProtocolGuid,
                  &mForensicsDynamicCommand,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  DEBUG ((EFI_D_INFO, "[Forensics] Initialized\n"));

  return Status;
}

/**
  Forensics driver unload handler.

  @param ImageHandle            The image handle of the process.

  @retval EFI_SUCCESS           The image is unloaded.
  @retval Others                Failed to unload the image.
**/
EFI_STATUS
EFIAPI
ForensicsUnload (
  IN EFI_HANDLE               ImageHandle
  )
{
  EFI_STATUS                  Status;

  DEBUG ((EFI_D_INFO, "[Forensics] Unloading\n"));

  Status = gBS->UninstallMultipleProtocolInterfaces (
                  ImageHandle,
                  &gEfiShellDynamicCommandProtocolGuid,
                  &mForensicsDynamicCommand,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  HiiRemovePackages (mForensicsHiiHandle);

  DEBUG ((EFI_D_INFO, "[Forensics] Unloaded\n"));

  return EFI_SUCCESS;
}

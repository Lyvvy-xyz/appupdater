@{
  Severity     = @('Error', 'Warning')
  ExcludeRules = @(
    # Crashes the analyzer on these files ("Reference Position should begin before start Position of Range").
    'PSUseSupportsShouldProcess'
    # WPF event handlers run in their own scope; shared state goes through $global:.
    'PSAvoidGlobalVars'
    # Write-Host is the UI log channel, and background runspaces replace it with queue stubs.
    'PSAvoidUsingWriteHost'
    'PSAvoidOverwritingBuiltInCmdlets'
    # Function source is reflected into runspaces with Invoke-Expression.
    'PSAvoidUsingInvokeExpression'
    # WPF delegates and test stubs have fixed signatures.
    'PSReviewUnusedParameter'
    'PSAvoidAssignmentToAutomaticVariable'
    # Engine globals are consumed by dot-sourced functions; [xml] casts validate.
    'PSUseDeclaredVarsMoreThanAssignments'
    # Best-effort cleanup and telemetry deliberately ignore failures.
    'PSAvoidUsingEmptyCatchBlock'
    # No -WhatIf surface; the app is GUI-driven.
    'PSUseShouldProcessForStateChangingFunctions'
    # Renaming existing functions would break callers.
    'PSUseSingularNouns'
    'PSUseApprovedVerbs'
    # The engine is linted from a BOM-less extraction; host.ps1 itself carries the BOM.
    'PSUseBOMForUnicodeEncodedFile'
  )
}

# Testing with Atomic Red Team

*By Adekunle Akeju.*

Atomic Red Team runs small, real attack techniques so you can see whether a detection fires. Use a disposable virtual machine you own, with a snapshot to roll back to, and never a production or shared system.

```powershell
# Inside the isolated test VM only
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

Choose the test numbers from `-ShowDetailsBrief`, because numbering changes between releases.

## Results

Record the date, atomic test number and result here after each run. No run has been recorded yet.

| Technique | Rule | Atomic test | Date | Detected |
|---|---|---|---|---|
| T1059.001 | win_powershell_encoded_command | Not run | | |
| T1105 | win_certutil_download | Not run | | |
| T1053.005 | win_schtasks_user_writable_path | Not run | | |
| T1490 | win_shadow_copy_delete | Not run | | |
| T1098 | win_local_admin_added | Not run | | |
| T1685.005 | win_event_log_cleared | Not run | | |
| T1003.001 | win_lsass_memory_access | Not run | | |
| T1059.004 | lnx_download_piped_to_shell | Not run | | |
| T1003.008 | lnx_shadow_file_read | Not run | | |
| T1136.001 | lnx_second_root_user | Not run | | |

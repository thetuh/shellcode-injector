# shellcode-injector
While researching ways to preserve stealth in remote code execution, I stumbled across information that identified the massive security hole within one of Microsoft's Windows API functions, 'SetWindowsHookEx'. As documented, this function installs an application-defined hook procedure into a hook chain. At first glance, this is of no significance. However, as per analysis by [Waryas](https://github.com/waryas/), a series of tests will confirm that the hook procedure does not need to belong to the module passed to the function. This has serious implications and enables remote code execution from any process, as showcased by this project.
# Planned
* Restructure/reorganize project
* Clean/Optimize code

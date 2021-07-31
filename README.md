# driver
a simple pasted windows kernel driver that does stuff: 
      
   . locates MiFillPteHierarchy by sigcanning it    
   . VA To PA (by manually walking pagetables, another way I used is to directly call MiFillPteHierarchy) 
   . GetModuleBase (doesn't use KeStackAttachProcess by just replaces the current cr3 value with the process cr3) 
   . QueryPagingInfo (gets what paging mode the system is on)
   . gets module information from kldr 

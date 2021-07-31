# driver
a simple pasted windows kernel driver that does stuff: 
      
   . locates MiFillPteHierarchy by sigcanning it    
  
   . VA To PA (by manually walking pagetables, another way I used is to directly call MiFillPteHierarchy) 
   
   . GetModuleBase (doesn't use KeStackAttachProcess by just replaces the current cr3 value with the process cr3) 
   
   . QueryPagingInfo (gets what paging mode the system is on)
   
   . gets module information from kldr 
   
Credits: 
         
         . https://githacks.org/_xeroxz/bluepill/-/blob/master/mm.cpp#L12 (translate function) 
         
         . https://githacks.org/_xeroxz/bluepill/-/blob/master/mm.hpp (virtual address structure) 
         
         . https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html (helper functions however I edited them a little
         
         . https://www.triplefault.io/2017/07/introduction-to-ia-32e-hardware-paging.html (page tables structures, also very good article on paging at general) 

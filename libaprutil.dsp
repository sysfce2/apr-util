# Microsoft Developer Studio Project File - Name="libaprutil" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libaprutil - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libaprutil.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libaprutil.mak" CFG="libaprutil - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libaprutil - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libaprutil - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libaprutil - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /I "./include" /I "../apr/include" /I "./include/private" /I "./dbm/sdbm" /I "./xml/expat/lib" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "APU_DECLARE_EXPORT" /D "APU_USE_SDBM" /Fd"Release\aprutil" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib advapi32.lib ws2_32.lib mswsock.lib ole32.lib /nologo /base:"0x6ED0000" /subsystem:windows /dll /map /machine:I386
# ADD LINK32 kernel32.lib advapi32.lib ws2_32.lib mswsock.lib ole32.lib /nologo /base:"0x6ED0000" /subsystem:windows /dll /map /machine:I386

!ELSEIF  "$(CFG)" == "libaprutil - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "./include" /I "../apr/include" /I "./include/private" /I "./dbm/sdbm" /I "./xml/expat/lib" /I "./expat/lib" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "APU_DECLARE_EXPORT" /D "APU_USE_SDBM" /Fd"Debug\aprutil" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib advapi32.lib ws2_32.lib mswsock.lib ole32.lib /nologo /base:"0x6ED0000" /subsystem:windows /dll /incremental:no /map /debug /machine:I386
# ADD LINK32 kernel32.lib advapi32.lib ws2_32.lib mswsock.lib ole32.lib /nologo /base:"0x6ED00000" /subsystem:windows /dll /incremental:no /map /debug /machine:I386

!ENDIF 

# Begin Target

# Name "libaprutil - Win32 Release"
# Name "libaprutil - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Group "buckets"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\buckets\apr_brigade.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_alloc.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_eos.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_file.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_flush.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_heap.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_mmap.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_pipe.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_pool.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_refcount.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_simple.c
# End Source File
# Begin Source File

SOURCE=.\buckets\apr_buckets_socket.c
# End Source File
# End Group
# Begin Group "crypto"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\crypto\apr_md4.c
# End Source File
# Begin Source File

SOURCE=.\crypto\apr_sha1.c
# End Source File
# End Group
# Begin Group "dbm"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\dbm\apr_dbm.c
# End Source File
# Begin Source File

SOURCE=.\dbm\apr_dbm_berkeleydb.c
# End Source File
# Begin Source File

SOURCE=.\dbm\apr_dbm_gdbm.c
# End Source File
# Begin Source File

SOURCE=.\dbm\apr_dbm_sdbm.c
# End Source File
# End Group
# Begin Group "encoding"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\encoding\apr_base64.c
# End Source File
# End Group
# Begin Group "hooks"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\hooks\apr_hooks.c
# End Source File
# End Group
# Begin Group "ldap"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\ldap\apr_ldap_compat.c
# PROP Exclude_From_Build 1
# End Source File
# End Group
# Begin Group "misc"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\misc\apr_date.c
# End Source File
# Begin Source File

SOURCE=.\misc\apr_rmm.c
# End Source File
# End Group
# Begin Group "sdbm"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\dbm\sdbm\sdbm.c
# End Source File
# Begin Source File

SOURCE=.\dbm\sdbm\sdbm_hash.c
# End Source File
# Begin Source File

SOURCE=.\dbm\sdbm\sdbm_lock.c
# End Source File
# Begin Source File

SOURCE=.\dbm\sdbm\sdbm_pair.c
# End Source File
# Begin Source File

SOURCE=.\dbm\sdbm\sdbm_pair.h
# End Source File
# Begin Source File

SOURCE=.\dbm\sdbm\sdbm_private.h
# End Source File
# Begin Source File

SOURCE=.\dbm\sdbm\sdbm_tune.h
# End Source File
# End Group
# Begin Group "strmatch"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\strmatch\apr_strmatch.c
# End Source File
# End Group
# Begin Group "uri"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\uri\apr_uri.c
# End Source File
# End Group
# Begin Group "xml"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\xml\apr_xml.c
# End Source File
# End Group
# End Group
# Begin Group "Generated Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\include\apr_ldap.h.in
# End Source File
# Begin Source File

SOURCE=.\include\apr_ldap.hnw
# End Source File
# Begin Source File

SOURCE=.\include\apr_ldap.hw

!IF  "$(CFG)" == "libaprutil - Win32 Release"

# Begin Custom Build - Creating apr_ldap.h from apr_ldap.hw 
InputPath=.\include\apr_ldap.hw

".\include\apr_ldap.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\apr_ldap.hw > .\include\apr_ldap.h
	
# End Custom Build

!ELSEIF  "$(CFG)" == "libaprutil - Win32 Debug"

# Begin Custom Build - Creating apr_ldap.h from apr_ldap.hw 
InputPath=.\include\apr_ldap.hw

".\include\apr_ldap.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\apr_ldap.hw > .\include\apr_ldap.h
	
# End Custom Build

!ENDIF 

# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\include\apu.h.in
# End Source File
# Begin Source File

SOURCE=.\include\apu.hnw
# End Source File
# Begin Source File

SOURCE=.\include\apu.hw

!IF  "$(CFG)" == "aprutil - Win32 Release"

# Begin Custom Build - Creating apu.h from apu.hw 
InputPath=.\include\apu.hw

".\include\apu.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\apu.hw > .\include\apu.h
	
# End Custom Build

!ELSEIF  "$(CFG)" == "aprutil - Win32 Debug"

# Begin Custom Build - Creating apu.h from apu.hw 
InputPath=.\include\apu.hw

".\include\apu.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\apu.hw > .\include\apu.h
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\include\private\apu_config.h.in
# End Source File
# Begin Source File

SOURCE=.\include\private\apu_config.hw

!IF  "$(CFG)" == "aprutil - Win32 Release"

# Begin Custom Build - Creating apu_config.h from apu_config.hw 
InputPath=.\include\private\apu_config.hw

".\include\private\apu_config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\private\apu_config.hw > .\include\private\apu_config.h
	
# End Custom Build

!ELSEIF  "$(CFG)" == "aprutil - Win32 Debug"

# Begin Custom Build - Creating apu_config.h from apu_config.hw 
InputPath=.\include\private\apu_config.hw

".\include\private\apu_config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\private\apu_config.hw > .\include\private\apu_config.h
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\include\private\apu_select_dbm.h.in
# End Source File
# Begin Source File

SOURCE=.\include\private\apu_select_dbm.hw

!IF  "$(CFG)" == "aprutil - Win32 Release"

# Begin Custom Build - Creating apu_select_dbm.h from apu_select_dbm.hw 
InputPath=.\include\private\apu_select_dbm.hw

".\include\private\apu_select_dbm.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\private\apu_select_dbm.hw > .\include\private\apu_select_dbm.h
	
# End Custom Build

!ELSEIF  "$(CFG)" == "aprutil - Win32 Debug"

# Begin Custom Build - Creating apu_select_dbm.h from apu_select_dbm.hw 
InputPath=.\include\private\apu_select_dbm.hw

".\include\private\apu_select_dbm.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\include\private\apu_select_dbm.hw > .\include\private\apu_select_dbm.h
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\uri\gen_uri_delims.exe

!IF  "$(CFG)" == "aprutil - Win32 Release"

# Begin Custom Build - Generating uri_delims.h
InputPath=.\uri\gen_uri_delims.exe

".\uri\uri_delims.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\uri\gen_uri_delims.exe >.\uri\uri_delims.h 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "aprutil - Win32 Debug"

# Begin Custom Build - Generating uri_delims.h
InputPath=.\uri\gen_uri_delims.exe

".\uri\uri_delims.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\uri\gen_uri_delims.exe >.\uri\uri_delims.h 
	
# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Public Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\include\apr_anylock.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_base64.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_buckets.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_date.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_dbm.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_hooks.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_md4.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_optional.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_optional_hooks.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_rmm.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_sdbm.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_sha1.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_strmatch.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_uri.h
# End Source File
# Begin Source File

SOURCE=.\include\apr_xml.h
# End Source File
# Begin Source File

SOURCE=.\include\apu_compat.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\libaprutil.rc
# End Source File
# Begin Source File

SOURCE=..\apr\build\win32ver.awk

!IF  "$(CFG)" == "libaprutil - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\apr\build\win32ver.awk

".\libaprutil.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../apr/build/win32ver.awk libaprutil "Apache APR Utility Library"  ../../include/ap_release.h > .\libaprutil.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "libaprutil - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\apr\build\win32ver.awk

".\libaprutil.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../apr/build/win32ver.awk libaprutil "Apache APR Utility Library"  ../../include/ap_release.h > .\libaprutil.rc

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project

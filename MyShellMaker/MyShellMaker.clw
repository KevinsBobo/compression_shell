; CLW file contains information for the MFC ClassWizard

[General Info]
Version=1
LastClass=CMyShellMakerDlg
LastTemplate=CDialog
NewFileInclude1=#include "stdafx.h"
NewFileInclude2=#include "MyShellMaker.h"

ClassCount=4
Class1=CMyShellMakerApp
Class2=CMyShellMakerDlg
Class3=CAboutDlg

ResourceCount=3
Resource1=IDD_ABOUTBOX
Resource2=IDR_MAINFRAME
Resource3=IDD_MYSHELLMAKER_DIALOG

[CLS:CMyShellMakerApp]
Type=0
HeaderFile=MyShellMaker.h
ImplementationFile=MyShellMaker.cpp
Filter=N

[CLS:CMyShellMakerDlg]
Type=0
HeaderFile=MyShellMakerDlg.h
ImplementationFile=MyShellMakerDlg.cpp
Filter=D
BaseClass=CDialog
VirtualFilter=dWC

[CLS:CAboutDlg]
Type=0
HeaderFile=MyShellMakerDlg.h
ImplementationFile=MyShellMakerDlg.cpp
Filter=D

[DLG:IDD_ABOUTBOX]
Type=1
Class=CAboutDlg
ControlCount=4
Control1=IDC_STATIC,static,1342177283
Control2=IDC_STATIC,static,1342308480
Control3=IDC_STATIC,static,1342308352
Control4=IDOK,button,1342373889

[DLG:IDD_MYSHELLMAKER_DIALOG]
Type=1
Class=CMyShellMakerDlg
ControlCount=1
Control1=BTN_MAKER,button,1342242816


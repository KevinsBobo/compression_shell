// MyShellMakerDlg.h : header file
//

#if !defined(AFX_MYSHELLMAKERDLG_H__11D5D530_936B_448F_8AF6_C8F0BA07EA5C__INCLUDED_)
#define AFX_MYSHELLMAKERDLG_H__11D5D530_936B_448F_8AF6_C8F0BA07EA5C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CMyShellMakerDlg dialog

class CMyShellMakerDlg : public CDialog
{
// Construction
public:
	CMyShellMakerDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CMyShellMakerDlg)
	enum { IDD = IDD_MYSHELLMAKER_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMyShellMakerDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CMyShellMakerDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnMaker();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MYSHELLMAKERDLG_H__11D5D530_936B_448F_8AF6_C8F0BA07EA5C__INCLUDED_)

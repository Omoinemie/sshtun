//go:build windows

package tun2socks

import (
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	jobOnce sync.Once
	jobObj  windows.Handle
)

// procJob 返回一个带「关闭即终止成员」策略的任务对象句柄（只创建一次）。
// 句柄随本进程持有：sshtun 一旦退出（含崩溃/被强杀），系统会关闭该句柄并
// 连带结束对象内的全部子进程，从而避免 tun2socks 残留。
func procJob() windows.Handle {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(h,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			_ = windows.CloseHandle(h)
			return
		}
		jobObj = h
	})
	return jobObj
}

// guardChild 在子进程启动后把它纳入任务对象。失败不影响正常运行，仅失去兜底清理。
func guardChild(cmd *exec.Cmd) {
	job := procJob()
	if job == 0 || cmd == nil || cmd.Process == nil {
		return
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_ = windows.AssignProcessToJobObject(job, h)
}

// prepareChild Windows 下隐藏 tun2socks 的控制台窗口。
//
// 后台模式（`sshtun start -d`）的守护进程以 DETACHED_PROCESS 启动，本身不持有控制台；
// 此时再启动 tun2socks.exe，Windows 会为它新建一个控制台（桌面上的黑色小窗）。
// CREATE_NO_WINDOW 让子进程以「无窗口控制台程序」方式运行：不再弹出窗口，
// 而 stdout/stderr 仍走管道被 sshtun 收集（日志不受影响）。
func prepareChild(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}

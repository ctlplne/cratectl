//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WinBase.h: input attribute number13, available on Windows10/Server2016+.
// The pinned x/sys exposes the attribute-list API but not this named constant.
const procThreadAttributeJobList = 0x0002000d

func writePrivateDiagnostic(path string, raw []byte) error {
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || len(raw) > 8<<20 {
		return errors.New("private diagnostic owner/byte bound")
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		windows.CloseHandle(handle)
		return errors.New("private diagnostic handle unavailable")
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	return f.Sync()
}

type jobAccounting struct {
	UserTime, KernelTime, PeriodUserTime, PeriodKernelTime  int64
	PageFaults, TotalProcesses, ActiveProcesses, Terminated uint32
}

func accounting(job windows.Handle) (jobAccounting, error) {
	var value jobAccounting
	var length uint32
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&value)), uint32(unsafe.Sizeof(value)), &length)
	if err != nil || length != uint32(unsafe.Sizeof(value)) {
		return value, errors.New("cannot observe owned Windows job accounting")
	}
	return value, nil
}

// No PID enumeration/signalling: the OS assigns the new suspended process to
// this handle-owned job at creation. Only explicit stdio handles are inherited.
func runPlatformCommand(ctx context.Context, argv []string, directory string, environment []string, maximum int) (result commandResult, err error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return result, errors.New("cannot create owned Windows job")
	}
	defer windows.CloseHandle(job)
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return result, errors.New("cannot constrain owned Windows job")
	}
	read, write, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer read.Close()
	defer write.Close()
	input, err := os.Open(os.DevNull)
	if err != nil {
		return result, err
	}
	defer input.Close()
	var childInput, childOutput windows.Handle
	self := windows.CurrentProcess()
	if err := windows.DuplicateHandle(self, windows.Handle(input.Fd()), self, &childInput, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return result, err
	}
	defer windows.CloseHandle(childInput)
	if err := windows.DuplicateHandle(self, windows.Handle(write.Fd()), self, &childOutput, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return result, err
	}
	defer func() {
		if childOutput != 0 {
			windows.CloseHandle(childOutput)
		}
	}()
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return result, err
	}
	defer attributes.Delete()
	inherited := []windows.Handle{childInput, childOutput}
	jobs := []windows.Handle{job}
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		return result, err
	}
	if err := attributes.Update(procThreadAttributeJobList, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
		return result, errors.New("native Windows job-at-creation attribute unavailable")
	}
	info := windows.StartupInfoEx{ProcThreadAttributeList: attributes.List()}
	info.Cb = uint32(unsafe.Sizeof(info))
	info.Flags = windows.STARTF_USESTDHANDLES
	info.StdInput, info.StdOutput, info.StdErr = childInput, childOutput, childOutput
	arguments := make([]string, len(argv))
	for n, value := range argv {
		arguments[n] = windows.EscapeArg(value)
	}
	command, err := windows.UTF16FromString(strings.Join(arguments, " "))
	if err != nil || len(command) > 32767 {
		return result, errors.New("Windows command line exceeds its native bound")
	}
	app, err := windows.UTF16PtrFromString(argv[0])
	if err != nil {
		return result, err
	}
	cwd, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return result, err
	}
	// Environment entries are explicit and sorted; duplicate names refuse.
	env := make([]string, 0, len(environment))
	for _, entry := range environment {
		// Hidden per-drive working-directory entries are unnecessary: this
		// launcher requires an absolute executable and working directory.
		if !strings.HasPrefix(entry, "=") {
			env = append(env, entry)
		}
	}
	sort.Slice(env, func(a, b int) bool { return strings.ToUpper(env[a]) < strings.ToUpper(env[b]) })
	seen := map[string]bool{}
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if !ok || key == "" || seen[key] {
			return result, errors.New("invalid or duplicate Windows environment name")
		}
		seen[key] = true
	}
	var block []uint16
	for _, entry := range env {
		part, e := windows.UTF16FromString(entry)
		if e != nil {
			return result, e
		}
		block = append(block, part...)
	}
	block = append(block, 0)
	if len(block) < 2 {
		block = []uint16{0, 0}
	}
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(app, &command[0], nil, nil, true, flags, &block[0], cwd, &info.StartupInfo, &process); err != nil {
		return result, errors.New("cannot create suspended process in owned Windows job")
	}
	defer windows.CloseHandle(process.Thread)
	defer windows.CloseHandle(process.Process)
	var output chan struct {
		body []byte
		err  error
	}
	defer func() {
		// Every path after creation retires this job's descendants, then observes
		// zero active processes. A failed cleanup can never return success.
		if e := windows.TerminateJobObject(job, 125); e != nil {
			err = errors.New("owned Windows job termination failed")
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			value, e := accounting(job)
			if e != nil {
				err = e
				break
			}
			result.TotalProcesses = value.TotalProcesses
			if value.ActiveProcesses == 0 {
				result.Cleaned = true
				break
			}
			if time.Now().After(deadline) {
				err = errors.New("owned Windows job still has active processes")
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if output != nil {
			select {
			case partial := <-output:
				result.Output = partial.body
			case <-time.After(time.Second):
				read.Close()
				err = errors.New("owned Windows output reader did not retire")
				select {
				case partial := <-output:
					result.Output = partial.body
				case <-time.After(time.Second):
				}
			}
		}
		read.Close()
		runtime.KeepAlive(block)
		runtime.KeepAlive(command)
		runtime.KeepAlive(inherited)
		runtime.KeepAlive(jobs)
	}()
	if value, e := accounting(job); e != nil || value.ActiveProcesses != 1 {
		return result, errors.New("suspended child was not observed in its owned job")
	}
	if previous, e := windows.ResumeThread(process.Thread); e != nil || previous != 1 {
		return result, errors.New("owned child did not resume from its initial suspension")
	}
	// Close every parent's writer after the child has inherited its allowlist.
	windows.CloseHandle(childOutput)
	childOutput = 0
	write.Close()
	output = make(chan struct {
		body []byte
		err  error
	}, 1)
	go func() {
		body, e := io.ReadAll(io.LimitReader(read, int64(maximum)+1))
		if len(body) > maximum {
			body, e = body[:maximum], errCommandOutput
		}
		output <- struct {
			body []byte
			err  error
		}{body, e}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case readResult := <-output:
			result.Output = readResult.body
			if readResult.err != nil {
				return result, readResult.err
			}
			output = nil
		case <-ticker.C:
			state, e := windows.WaitForSingleObject(process.Process, 0)
			if e != nil {
				return result, e
			}
			if state != windows.WAIT_OBJECT_0 {
				continue
			}
			if e := windows.GetExitCodeProcess(process.Process, &result.Exit); e != nil {
				return result, e
			}
			if e := windows.TerminateJobObject(job, 125); e != nil {
				return result, e
			}
			if output == nil {
				return result, nil
			}
		}
	}
}

/*
	rusage
	By aadz, 2019

	v. 1.0 - 2019-06-07
		Initial version

	v. 1.1 - 2019-06-10
		rusage returns exit code it have got from a testing executalbe

	v. 1.2 - 2019-06-10
		display information about abnormal termination of a testing executalbe

*/
package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

const (
	VERSION = "1.1"
)

func printRusage(procState *os.ProcessState, rtime time.Duration) {
	// &syscall.Rusage{
	//	Utime:syscall.Timeval{Sec:1, Usec:288000},
	//	Stime:syscall.Timeval{Sec:1, Usec:508000},
	//	Maxrss:5008,
	//	Ixrss:0,
	//	Idrss:0,
	//	Isrss:0,
	//	Minflt:686,
	//	Majflt:0,
	//	Nswap:0,
	//	Inblock:0,
	//	Oublock:0,
	//	Msgsnd:0,
	//	Msgrcv:0,
	//	Nsignals:0,
	//	Nvcsw:1,
	//	Nivcsw:344
	// } see man 2 getrusage for explanation

	sysRu := procState.SysUsage()
	sysRusage := sysRu.(*syscall.Rusage)

	fmt.Printf("\nUtime: %22.3f\n", procState.UserTime().Seconds())
	fmt.Printf("Stime: %22.3f\n", procState.SystemTime().Seconds())
	fmt.Printf("Rtime: %22.3f\n", rtime.Seconds())
	fmt.Printf("Maxrss: %21d\n", sysRusage.Maxrss)
	fmt.Printf("Ixrss: %22d\n", sysRusage.Ixrss)
	fmt.Printf("Idrss: %22d\n", sysRusage.Idrss)
	fmt.Printf("Isrss: %22d\n", sysRusage.Isrss)
	fmt.Printf("Minflt: %21d\n", sysRusage.Minflt)
	fmt.Printf("Majflt: %21d\n", sysRusage.Majflt)
	fmt.Printf("Nswap: %22d\n", sysRusage.Nswap)
	fmt.Printf("Inblock: %20d\n", sysRusage.Inblock)
	fmt.Printf("Oublock: %20d\n", sysRusage.Oublock)
	fmt.Printf("Msgsnd: %21d\n", sysRusage.Msgsnd)
	fmt.Printf("Msgrcv: %21d\n", sysRusage.Msgrcv)
	fmt.Printf("Nsignals: %19d\n", sysRusage.Nsignals)
	fmt.Printf("Nvcsw: %22d\n", sysRusage.Nvcsw)
	fmt.Printf("Nivcsw: %21d\n", sysRusage.Nivcsw)
}

func main() {
	//fmt.Printf("CMD: %v\n", os.Args[1:])

	// set inherited files
	pAttr := new(os.ProcAttr)
	pAttr.Files = []*os.File{os.Stdin, os.Stdout, os.Stderr}

	// start the process and count run time
	startTime := time.Now()
	process, err := os.StartProcess(os.Args[1], os.Args[1:], pAttr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	procState, err := process.Wait()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	endTime := time.Now()
	printRusage(procState, endTime.Sub(startTime))

	exitCode := procState.ExitCode()
	if exitCode != 0 { // abnormal termination
		waitStatus := procState.Sys().(syscall.WaitStatus)
		termSignal := waitStatus.Signal()
		fmt.Printf("\n")
		if waitStatus.Signaled() {
			infoLine := "Terminated by signal %d - %s"
			if waitStatus.CoreDump() {
				infoLine += " (core dumped)"
			}
			fmt.Printf(infoLine, termSignal, termSignal)
			fmt.Printf("\nExitCode: %d\n", procState.Sys())
		} else {
			fmt.Printf("ExitCode: %d\n", exitCode)
		}
	}
	os.Exit(exitCode)
}

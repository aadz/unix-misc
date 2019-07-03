/*
	rusage
	By aadz, 2019

	v. 1.0 - 2019-06-07
		Initial version

	v. 1.1 - 2019-06-10
		rusage returns exit code it have got from a testing executalbe

	v. 1.2 - 2019-06-10
		display information about abnormal termination of a testing executalbe

	v. 1.3 - 2019-06-11
		some refactoring

	v. 1.4 - 2019-07-03
		statistics explanation added (from man 2 getrusage)
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"
)

const STAT_EXPLANATION = `The fields are interpreted as follows:

Utime
    This is the total amount of time spent executing in user mode, expressed
    in a timeval structure (seconds plus microseconds).

Stime
    This is the total amount of time spent executing in kernel mode,
    expressed in a timeval structure (seconds plus microseconds).

Rtime
    Real time of execution.

Maxrss (since Linux 2.6.32)
    This is the maximum resident set size used (in kilobytes).
    For RUSAGE_CHILDREN, this is the resident set size of the largest child,
    not the maximum resident set size of the process tree.

Ixrss (unmaintained)
    This field is currently unused on Linux.

Idrss (unmaintained)
    This field is currently unused on Linux.

Isrss (unmaintained)
    This field is currently unused on Linux.

Minflt
    The number of page faults serviced without any I/O activity; here
    I/O activity is avoided by “reclaiming” a page frame from the list of pages
    awaiting reallocation.

Majflt
    The number of page faults serviced that required I/O activity.

Nswap (unmaintained)
    This field is currently unused on Linux.

Inblock (since Linux 2.6.22)
    The number of times the filesystem had to perform input.

Oublock (since Linux 2.6.22)
    The number of times the filesystem had to perform output.

Msgsnd (unmaintained)
    This field is currently unused on Linux.

Msgrcv (unmaintained)
    This field is currently unused on Linux.

Nsignals (unmaintained)
    This field is currently unused on Linux.

Nvcsw (since Linux 2.6)
    The number of times a context switch resulted due to a process voluntarily
    giving up the processor before its time slice was completed (usually
    to await availability of a resource).

Nivcsw (since Linux 2.6)
    The number of times a context switch resulted due to a higher priority
    process becoming runnable or because the current process exceeded its time
    slice.`

func init() {
	Hflag := flag.Bool("H", false, "Show explanation of ececution stat psrameters")
	flag.Parse()
	if *Hflag {
		fmt.Println(STAT_EXPLANATION)
		os.Exit(0)
	}
}

// printRusage formats and prints a testing executable run stats.
func printRusage(procState *os.ProcessState, rtime time.Duration) {
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

	// show the execution results and usage of system resources
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

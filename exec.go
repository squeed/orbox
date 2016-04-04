package main

import "os/exec"
import "os"
import "syscall"
import "log"

// TODO: Not just amd64
const SYSCALL_SETRESUID = 117
const SYSCALL_SETRESGID = 119

func doExec(command []string) {

	cmd := exec.Command(command[0], command[1:]...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	uid := os.Getuid()
	euid := os.Geteuid()

	gid := os.Getgid()
	egid := os.Getegid()

	setUser(uid, gid)
	// TODO: do we care about the return code?
	_ = cmd.Run()

	setUser(euid, egid)

}

func setUser(uid int, gid int) {
	log.Printf("Setting uid %d gid %d\n", uid, gid)
	val := (0xffffffff)
	pp := uintptr(val)

	_, _, el := syscall.Syscall(SYSCALL_SETRESUID, pp, uintptr(uid), pp)
	if el != 0 {
		log.Fatalf("Failed to setuid(), errno %d", el)
	}

	_, _, el = syscall.Syscall(SYSCALL_SETRESGID, pp, uintptr(gid), pp)
	if el != 0 {
		log.Fatalf("Failed to setgid(), errno %d", el)
	}
}

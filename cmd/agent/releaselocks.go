package main

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/appcontrol"
)

// releaseAppControlLocks puts back every application this agent prevented from
// launching.
//
// It runs before anything else is removed, and it is the one uninstall step
// that is about the user's own software rather than ours. An agent that is
// deleted while holding launch locks leaves applications that do not start,
// with the only thing that knew how to undo it gone — and the person left
// behind has no way to find out which ones, or why.
//
// Best-effort and never fatal: an uninstall has to finish on a machine that is
// already half broken, which is exactly the state somebody reaches for it in.
func releaseAppControlLocks() {
	enforcer := appcontrol.New(appcontrol.Options{
		Logger:   zap.NewNop(),
		StateDir: appControlStateDir,
	})

	held := enforcer.HeldCount()
	if held == 0 {
		return
	}

	fmt.Printf("Restoring %d application(s) this agent had blocked…\n", held)
	enforcer.Release()

	if left := enforcer.HeldCount(); left > 0 {
		fmt.Printf("  ✗ %d could not be restored. Run this again with administrator rights.\n", left)
	}
}

package core

// Recover turns a panic in a CLI command into a logged error so the
// process can exit cleanly instead of dumping a stack trace at the user.
// Call from a deferred function inside SafeRun.
func Recover(name string) {
	if r := recover(); r != nil {
		Errorf("panic in %s: %v", name, r)
	}
}

// SafeRun wraps fn with panic recovery. Every command handler in main
// calls this so a bug in one module doesn't crash the whole binary.
func SafeRun(name string, fn func()) {
	defer Recover(name)
	fn()
}

package datapath

// DpGetLock - routine to take underlying DP lock
func DpGetLock() {
	flb_xh_lock()
}

// DpRelLock - routine to release underlying DP lock
func DpRelLock() {
	flb_xh_unlock()
}

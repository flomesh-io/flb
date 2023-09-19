package api

// DpWorkT - type of requested work
type DpWorkT uint8

// dp work codes
const (
	DpCreate DpWorkT = iota + 1
	DpRemove
	DpChange
	DpStatsGet
	DpStatsClr
	DpMapGet
	DpMapShow
)

// DpStatusT - status of a dp work
type DpStatusT uint8

// dp work status codes
const (
	DpCreateErr DpStatusT = iota + 1
	DpRemoveErr
	DpChangeErr
	DpUknownErr
	DpInProgressErr
)

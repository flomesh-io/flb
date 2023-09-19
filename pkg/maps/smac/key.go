package smac

type Key struct {
	Smac [6]uint8 `json:"smac"`
	Bd   uint16   `json:"bd"`
}

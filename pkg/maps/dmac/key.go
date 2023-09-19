package dmac

type Key struct {
	Dmac [6]uint8 `json:"dmac"`
	Bd   uint16   `json:"bd"`
}

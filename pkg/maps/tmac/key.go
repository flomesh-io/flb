package tmac

type Key struct {
	Mac      [6]uint8 `json:"mac"`
	TunType  uint8    `json:"tun_type"`
	Pad      uint8    `json:"pad"`
	TunnelId uint32   `json:"tunnel_id"`
}

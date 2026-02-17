package modules

import (
	"bytemomo/kraken/internal/modules/mqtt"
	"bytemomo/kraken/internal/modules/rtsp"
)

func Init() {
	mqtt.Init()
	rtsp.Init()
}

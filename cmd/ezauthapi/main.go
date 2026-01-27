package main

import (
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/handler"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

func main() {
	cfg := config.V
	xlog.Info("config", "cfg", cfg)
	auth := service.New(&cfg)
	handler := handler.New(auth, "auth")
	xlog.Info("starting server")
	handler.Run()
}

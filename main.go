package main

import (
	"flag"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

func main() {
	// Simulate dropping command line arguments
	flag.Parse()

	mygo.App.WhenReady(func() {
		mygo.NewWindow(mygo.WindowOptions{
			Title:         AppName + " " + AppVersion,
			Width:         WindowWidth,
			Height:        WindowHeight,
			MinWidth:      WindowMinWidth,
			MinHeight:     WindowMinHeight,
			DisableResize: false,
			Content:       ui.View(view),
		})
		if flag.NArg() > 0 {
			onDrop(flag.Args())
		}
	})
	if err := mygo.App.Run(); err != nil {
		panic(err)
	}
}

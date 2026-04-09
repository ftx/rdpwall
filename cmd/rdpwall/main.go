//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/aliforever/rdpwall/lib/rdpwall"
	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ── Win32 helpers ────────────────────────────────────────────────────────────

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	user32               = windows.NewLazySystemDLL("user32.dll")
	getConsoleWin        = kernel32.NewProc("GetConsoleWindow")
	showWindowProc       = user32.NewProc("ShowWindow")
	isIconicProc         = user32.NewProc("IsIconic")
	setForegroundWinProc = user32.NewProc("SetForegroundWindow")
	bringWindowToTopProc = user32.NewProc("BringWindowToTop")
)

const (
	swHide     = 0
	swShow     = 5
	swMinimize = 6
	swRestore  = 9
)

func consoleHwnd() uintptr {
	hwnd, _, _ := getConsoleWin.Call()
	return hwnd
}

func showConsole() {
	hwnd := consoleHwnd()
	showWindowProc.Call(hwnd, swShow)
	showWindowProc.Call(hwnd, swRestore)
	setForegroundWinProc.Call(hwnd)
	bringWindowToTopProc.Call(hwnd)
}

func hideConsole() {
	showWindowProc.Call(consoleHwnd(), swHide)
}

func isIconic() bool {
	ret, _, _ := isIconicProc.Call(consoleHwnd())
	return ret != 0
}

// watchMinimize hides the console window whenever the user minimises it.
func watchMinimize() {
	for {
		if isIconic() {
			hideConsole()
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// ── Launch on startup (HKCU registry) ────────────────────────────────────────

func logTime() string {
	return time.Now().Format("15:04:05")
}

const (
	startupRegPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	startupRegName = "RdpWall"
)

// isStartupEnabled reports whether the HKCU Run entry for RdpWall exists.
func isStartupEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, startupRegPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(startupRegName)
	return err == nil
}

// enableStartup writes the current executable path to the HKCU Run key.
func enableStartup() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, startupRegPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(startupRegName, exe)
}

// disableStartup removes the HKCU Run entry for RdpWall.
func disableStartup() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, startupRegPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue(startupRegName)
}

// ── ICO generator ────────────────────────────────────────────────────────────

// generateTrayIcon returns a 16×16 32-bpp ICO file as a byte slice.
// The icon is a solid dark-red square (no CGo, no external files).
func generateTrayIcon() []byte {
	const (
		w, h       = 16, 16
		bpp        = 32
		r8, g8, b8 = 0x99, 0x00, 0x00 // dark red
	)

	pixelBytes := w * h * 4 // BGRA
	andMaskBytes := h * ((w + 31) / 32 * 4)

	biSizeImage := pixelBytes
	biSize := 40
	icoHeaderSize := 6
	icoDirEntrySize := 16
	imageDataOffset := icoHeaderSize + icoDirEntrySize

	totalSize := imageDataOffset + biSize + pixelBytes + andMaskBytes
	buf := make([]byte, totalSize)

	// ICONDIR
	binary.LittleEndian.PutUint16(buf[0:], 0) // reserved
	binary.LittleEndian.PutUint16(buf[2:], 1) // type = ICO
	binary.LittleEndian.PutUint16(buf[4:], 1) // count = 1

	// ICONDIRENTRY
	buf[6] = byte(w)
	buf[7] = byte(h)
	buf[8] = 0                                   // color count (0 = >256 colors)
	buf[9] = 0                                   // reserved
	binary.LittleEndian.PutUint16(buf[10:], 1)   // planes
	binary.LittleEndian.PutUint16(buf[12:], bpp) // bit count
	binary.LittleEndian.PutUint32(buf[14:], uint32(biSize+pixelBytes+andMaskBytes))
	binary.LittleEndian.PutUint32(buf[18:], uint32(imageDataOffset))

	// BITMAPINFOHEADER
	o := imageDataOffset
	binary.LittleEndian.PutUint32(buf[o:], uint32(biSize))
	binary.LittleEndian.PutUint32(buf[o+4:], uint32(w))
	binary.LittleEndian.PutUint32(buf[o+8:], uint32(h*2)) // XOR + AND masks
	binary.LittleEndian.PutUint16(buf[o+12:], 1)          // planes
	binary.LittleEndian.PutUint16(buf[o+14:], bpp)        // bit count
	binary.LittleEndian.PutUint32(buf[o+16:], 0)          // compression = BI_RGB
	binary.LittleEndian.PutUint32(buf[o+20:], uint32(biSizeImage))
	// remaining BITMAPINFOHEADER fields stay 0

	// XOR (pixel) data — bottom-up row order, BGRA
	o += biSize
	for row := h - 1; row >= 0; row-- {
		for col := 0; col < w; col++ {
			idx := o + ((h-1-row)*w+col)*4
			buf[idx+0] = b8   // B
			buf[idx+1] = g8   // G
			buf[idx+2] = r8   // R
			buf[idx+3] = 0xFF // A (fully opaque)
		}
	}
	// AND mask: all zeros = fully opaque (already zero from make)
	return buf
}

// ── Entry point ──────────────────────────────────────────────────────────────

func main() {
	fs, err := rdpwall.NewFileStorage("failed_audits.json")
	if err != nil {
		panic(err)
	}

	go fs.Sync(5 * time.Second)

	q := rdpwall.New(fs)

	systray.Run(func() { onReady(q) }, onExit)
}

func onReady(q *rdpwall.Quantom) {
	systray.SetIcon(generateTrayIcon())
	systray.SetTitle("RdpWall")
	systray.SetTooltip("RdpWall – RDP brute-force protection")

	mShow := systray.AddMenuItem("Show Console", "Bring the console window to front")
	mHide := systray.AddMenuItem("Hide Console", "Hide the console window to tray")
	systray.AddSeparator()
	mStartup := systray.AddMenuItemCheckbox(
		"Launch on Startup",
		"Start RdpWall automatically when Windows starts",
		isStartupEnabled(),
	)
	systray.AddSeparator()
	mExit := systray.AddMenuItem("Exit", "Stop RdpWall and quit")

	// Start the protection engine.
	q.Start()

	// Poll for minimize-to-tray.
	go watchMinimize()

	// Handle tray menu clicks.
	for {
		select {
		case <-mShow.ClickedCh:
			showConsole()
		case <-mHide.ClickedCh:
			hideConsole()
		case <-mStartup.ClickedCh:
			if mStartup.Checked() {
				if err := disableStartup(); err != nil {
					fmt.Printf("[%s] STARTUP ERROR: could not disable: %v\n", logTime(), err)
				} else {
					mStartup.Uncheck()
				}
			} else {
				if err := enableStartup(); err != nil {
					fmt.Printf("[%s] STARTUP ERROR: could not enable: %v\n", logTime(), err)
				} else {
					mStartup.Check()
				}
			}
		case <-mExit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func onExit() {}

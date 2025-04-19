package main

/*

Picocrypt v1.48
Copyright (c) Evan Su
Released under a GNU GPL v3 License
https://github.com/Picocrypt/Picocrypt

~ In cryptography we trust ~

*/

import (
	"archive/zip"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"hash"
	"image"
	"image/color"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Picocrypt/dialog"
	"github.com/Picocrypt/giu"
	"github.com/Picocrypt/imgui-go"
	"github.com/Picocrypt/infectious"
	"github.com/Picocrypt/serpent"
	"github.com/Picocrypt/zxcvbn-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Constants
const KiB = 1 << 10
const MiB = 1 << 20
const GiB = 1 << 30
const TiB = 1 << 40

var WHITE = color.RGBA{0xff, 0xff, 0xff, 0xff}
var RED = color.RGBA{0xff, 0x00, 0x00, 0xff}
var GREEN = color.RGBA{0x00, 0xff, 0x00, 0xff}
var YELLOW = color.RGBA{0xff, 0xff, 0x00, 0xff}
var TRANSPARENT = color.RGBA{0x00, 0x00, 0x00, 0x00}

// Generic variables
var window *giu.MasterWindow
var version = "v1.48"
var dpi float32
var mode string
var working bool
var scanning bool

// Popup modals
var modalId int
var showPassgen bool
var showKeyfile bool
var showOverwrite bool
var showProgress bool

// Input and output files
var inputFile string
var inputFileOld string
var outputFile string
var onlyFiles []string
var onlyFolders []string
var allFiles []string
var inputLabel = "Drop files and folders into this window"

// Password and confirm password
var password string
var cpassword string
var passwordStrength int
var passwordState = giu.InputTextFlagsPassword
var passwordStateLabel = "Show"

// Password generator
var passgenLength int32 = 32
var passgenUpper bool
var passgenLower bool
var passgenNums bool
var passgenSymbols bool
var passgenCopy bool

// Keyfile variables
var keyfile bool
var keyfiles []string
var keyfileOrdered bool
var keyfileLabel = "None selected"

// Comments variables
var comments string
var commentsLabel = "Comments:"
var commentsDisabled bool

// Advanced options
var paranoid bool
var reedsolo bool
var deniability bool
var recursively bool
var split bool
var splitSize string
var splitUnits = []string{"KiB", "MiB", "GiB", "TiB", "Total"}
var splitSelected int32 = 1
var recombine bool
var compress bool
var delete bool
var autoUnzip bool
var sameLevel bool
var keep bool
var kept bool

// Status variables
var startLabel = "Start"
var mainStatus = "Ready"
var mainStatusColor = WHITE
var popupStatus string
var requiredFreeSpace int64

// Progress variables
var progress float32
var progressInfo string
var speed float64
var eta string
var canCancel bool

// Reed-Solomon encoders
var rs1, rsErr1 = infectious.NewFEC(1, 3)
var rs5, rsErr2 = infectious.NewFEC(5, 15)
var rs16, rsErr3 = infectious.NewFEC(16, 48)
var rs24, rsErr4 = infectious.NewFEC(24, 72)
var rs32, rsErr5 = infectious.NewFEC(32, 96)
var rs64, rsErr6 = infectious.NewFEC(64, 192)
var rs128, rsErr7 = infectious.NewFEC(128, 136)
var fastDecode bool

// Compression variables and passthrough
var compressDone int64
var compressTotal int64
var compressStart time.Time

type compressorProgress struct {
	io.Reader
}

func (p *compressorProgress) Read(data []byte) (int, error) {
	if !working {
		return 0, io.EOF
	}
	read, err := p.Reader.Read(data)
	compressDone += int64(read)
	progress, speed, eta = statify(compressDone, compressTotal, compressStart)
	if compress {
		popupStatus = fmt.Sprintf("Compressing at %.2f MiB/s (ETA: %s)", speed, eta)
	} else {
		popupStatus = fmt.Sprintf("Combining at %.2f MiB/s (ETA: %s)", speed, eta)
	}
	giu.Update()
	return read, err
}

type encryptedZipWriter struct {
	_w      io.Writer
	_cipher *chacha20.Cipher
}

func (ezw *encryptedZipWriter) Write(data []byte) (n int, err error) {
	dst := make([]byte, len(data))
	ezw._cipher.XORKeyStream(dst, data)
	return ezw._w.Write(dst)
}

type encryptedZipReader struct {
	_r      io.Reader
	_cipher *chacha20.Cipher
}

func (ezr *encryptedZipReader) Read(data []byte) (n int, err error) {
	src := make([]byte, len(data))
	n, err = ezr._r.Read(src)
	if err == nil && n > 0 {
		dst := make([]byte, n)
		ezr._cipher.XORKeyStream(dst, src[:n])
		if copy(data, dst) != n {
			panic(errors.New("built-in copy() function failed"))
		}
	}
	return n, err
}

func onClickStartButton() {
	// Start button should be disabled if these conditions are true; don't do anything if so
	if (len(keyfiles) == 0 && password == "") || (mode == "encrypt" && password != cpassword) {
		return
	}

	if keyfile && keyfiles == nil {
		mainStatus = "Please select your keyfiles"
		mainStatusColor = RED
		giu.Update()
		return
	}
	tmp, err := strconv.Atoi(splitSize)
	if split && (splitSize == "" || err != nil || tmp <= 0) {
		mainStatus = "Invalid chunk size"
		mainStatusColor = RED
		giu.Update()
		return
	}

	// Check if output file already exists
	_, err = os.Stat(outputFile)

	// Check if any split chunks already exist
	if split {
		names, err2 := filepath.Glob(outputFile + ".*")
		if err2 != nil {
			panic(err2)
		}
		if len(names) > 0 {
			err = nil
		} else {
			err = os.ErrNotExist
		}
	}

	// If files already exist, show the overwrite modal
	if err == nil && !recursively {
		showOverwrite = true
		modalId++
		giu.Update()
	} else { // Nothing to worry about, start working
		showProgress = true
		fastDecode = true
		canCancel = true
		modalId++
		giu.Update()
		if !recursively {
			go func() {
				work()
				working = false
				showProgress = false
				giu.Update()
			}()
		} else {
			// Store variables as they will be cleared
			oldPassword := password
			oldKeyfile := keyfile
			oldKeyfiles := keyfiles
			oldKeyfileOrdered := keyfileOrdered
			oldKeyfileLabel := keyfileLabel
			oldComments := comments
			oldParanoid := paranoid
			oldReedsolo := reedsolo
			oldDeniability := deniability
			oldSplit := split
			oldSplitSize := splitSize
			oldSplitSelected := splitSelected
			oldDelete := delete
			files := allFiles
			go func() {
				for _, file := range files {
					// Simulate dropping the file
					onDrop([]string{file})

					// Restore variables and options
					password = oldPassword
					cpassword = oldPassword
					keyfile = oldKeyfile
					keyfiles = oldKeyfiles
					keyfileOrdered = oldKeyfileOrdered
					keyfileLabel = oldKeyfileLabel
					comments = oldComments
					paranoid = oldParanoid
					reedsolo = oldReedsolo
					if mode != "decrypt" {
						deniability = oldDeniability
					}
					split = oldSplit
					splitSize = oldSplitSize
					splitSelected = oldSplitSelected
					delete = oldDelete

					work()
					if !working {
						resetUI()
						cancel(nil, nil)
						showProgress = false
						giu.Update()
						return
					}
				}
				working = false
				showProgress = false
				giu.Update()
			}()
		}
	}
}

// The main user interface
func draw() {
	giu.SingleWindow().Flags(524351).Layout(
		giu.Custom(func() {
			if giu.IsKeyReleased(giu.KeyEnter) {
				onClickStartButton()
				return
			}
			if showPassgen {
				giu.PopupModal("Generate password:##"+strconv.Itoa(modalId)).Flags(6).Layout(
					giu.Row(
						giu.Label("Length:"),
						giu.SliderInt(&passgenLength, 12, 64).Size(giu.Auto),
					),
					giu.Checkbox("Uppercase", &passgenUpper),
					giu.Checkbox("Lowercase", &passgenLower),
					giu.Checkbox("Numbers", &passgenNums),
					giu.Checkbox("Symbols", &passgenSymbols),
					giu.Checkbox("Copy to clipboard", &passgenCopy),
					giu.Row(
						giu.Button("Cancel").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showPassgen = false
						}),
						giu.Style().SetDisabled(!(passgenUpper || passgenLower || passgenNums || passgenSymbols)).To(
							giu.Button("Generate").Size(100, 0).OnClick(func() {
								password = genPassword()
								cpassword = password
								passwordStrength = zxcvbn.PasswordStrength(password, nil).Score

								giu.CloseCurrentPopup()
								showPassgen = false
							}),
						),
					),
				).Build()
				giu.OpenPopup("Generate password:##" + strconv.Itoa(modalId))
				giu.Update()
			}

			if showKeyfile {
				giu.PopupModal("Manage keyfiles:##"+strconv.Itoa(modalId)).Flags(70).Layout(
					giu.Label("Drag and drop your keyfiles here"),
					giu.Custom(func() {
						if mode != "decrypt" {
							giu.Checkbox("Require correct order", &keyfileOrdered).Build()
							giu.Tooltip("Ordering of keyfiles will matter").Build()
						} else if keyfileOrdered {
							giu.Label("Correct ordering is required").Build()
						}
					}),
					giu.Custom(func() {
						if len(keyfiles) > 0 {
							giu.Separator().Build()
						}
						for _, i := range keyfiles {
							giu.Label(filepath.Base(i)).Build()
						}
					}),
					giu.Row(
						giu.Button("Clear").Size(100, 0).OnClick(func() {
							keyfiles = nil
							if keyfile {
								keyfileLabel = "Keyfiles required"
							} else {
								keyfileLabel = "None selected"
							}
							modalId++
							giu.Update()
						}),
						giu.Tooltip("Remove all keyfiles"),

						giu.Button("Done").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showKeyfile = false
						}),
					),
				).Build()
				giu.OpenPopup("Manage keyfiles:##" + strconv.Itoa(modalId))
				giu.Update()
			}

			if showOverwrite {
				giu.PopupModal("Warning:##"+strconv.Itoa(modalId)).Flags(6).Layout(
					giu.Label("Output already exists. Overwrite?"),
					giu.Row(
						giu.Button("No").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showOverwrite = false
						}),
						giu.Button("Yes").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showOverwrite = false

							showProgress = true
							fastDecode = true
							canCancel = true
							modalId++
							giu.Update()
							go func() {
								work()
								working = false
								showProgress = false
								giu.Update()
							}()
						}),
					),
				).Build()
				giu.OpenPopup("Warning:##" + strconv.Itoa(modalId))
				giu.Update()
			}

			if showProgress {
				giu.PopupModal("Progress:##"+strconv.Itoa(modalId)).Flags(6|1<<0).Layout(
					giu.Dummy(0, 0),
					giu.Row(
						giu.ProgressBar(progress).Size(210, 0).Overlay(progressInfo),
						giu.Style().SetDisabled(!canCancel).To(
							giu.Button(func() string {
								if working {
									return "Cancel"
								}
								return "..."
							}()).Size(58, 0).OnClick(func() {
								working = false
								canCancel = false
							}),
						),
					),
					giu.Label(popupStatus),
				).Build()
				giu.OpenPopup("Progress:##" + strconv.Itoa(modalId))
				giu.Update()
			}
		}),

		giu.Row(
			giu.Label(inputLabel),
			giu.Custom(func() {
				bw, _ := giu.CalcTextSize("Clear")
				p, _ := giu.GetWindowPadding()
				bw += p * 2
				giu.Dummy((bw+p)/-dpi, 0).Build()
				giu.SameLine()
				giu.Style().SetDisabled((len(allFiles) == 0 && len(onlyFiles) == 0) || scanning).To(
					giu.Button("Clear").Size(bw/dpi, 0).OnClick(resetUI),
					giu.Tooltip("Clear all input files and reset UI state"),
				).Build()
			}),
		),

		giu.Separator(),
		giu.Style().SetDisabled((len(allFiles) == 0 && len(onlyFiles) == 0) || scanning).To(
			giu.Label("Password:"),
			giu.Row(
				giu.Button(passwordStateLabel).Size(54, 0).OnClick(func() {
					if passwordState == giu.InputTextFlagsPassword {
						passwordState = giu.InputTextFlagsNone
						passwordStateLabel = "Hide"
					} else {
						passwordState = giu.InputTextFlagsPassword
						passwordStateLabel = "Show"
					}
					giu.Update()
				}),
				giu.Tooltip("Toggle the visibility of password entries"),

				giu.Button("Clear").Size(54, 0).OnClick(func() {
					password = ""
					cpassword = ""
					giu.Update()
				}),
				giu.Tooltip("Clear the password entries"),

				giu.Button("Copy").Size(54, 0).OnClick(func() {
					giu.Context.GetPlatform().SetClipboard(password)
					giu.Update()
				}),
				giu.Tooltip("Copy the password into your clipboard"),

				giu.Button("Paste").Size(54, 0).OnClick(func() {
					tmp := giu.Context.GetPlatform().GetClipboard()
					password = tmp
					if mode != "decrypt" {
						cpassword = tmp
					}
					passwordStrength = zxcvbn.PasswordStrength(password, nil).Score
					giu.Update()
				}),
				giu.Tooltip("Paste a password from your clipboard"),

				giu.Style().SetDisabled(mode == "decrypt").To(
					giu.Button("Create").Size(54, 0).OnClick(func() {
						showPassgen = true
						modalId++
						giu.Update()
					}),
				),
				giu.Tooltip("Generate a cryptographically secure password"),
			),
			giu.Row(
				giu.InputText(&password).Flags(passwordState).Size(302/dpi).OnChange(func() {
					passwordStrength = zxcvbn.PasswordStrength(password, nil).Score
					giu.Update()
				}),
				giu.Custom(func() {
					c := giu.GetCanvas()
					p := giu.GetCursorScreenPos()
					col := color.RGBA{
						uint8(0xc8 - 31*passwordStrength),
						uint8(0x4c + 31*passwordStrength), 0x4b, 0xff,
					}
					if password == "" || mode == "decrypt" {
						col = TRANSPARENT
					}
					path := p.Add(image.Pt(
						int(math.Round(-20*float64(dpi))),
						int(math.Round(12*float64(dpi))),
					))
					c.PathArcTo(path, 6*dpi, -math.Pi/2, math.Pi*(.4*float32(passwordStrength)-.1), -1)
					c.PathStroke(col, false, 2)
				}),
			),

			giu.Dummy(0, 0),
			giu.Style().SetDisabled(password == "" || mode == "decrypt").To(
				giu.Label("Confirm password:"),
				giu.Row(
					giu.InputText(&cpassword).Flags(passwordState).Size(302/dpi),
					giu.Custom(func() {
						c := giu.GetCanvas()
						p := giu.GetCursorScreenPos()
						col := color.RGBA{0x4c, 0xc8, 0x4b, 0xff}
						if cpassword != password {
							col = color.RGBA{0xc8, 0x4c, 0x4b, 0xff}
						}
						if password == "" || cpassword == "" || mode == "decrypt" {
							col = TRANSPARENT
						}
						path := p.Add(image.Pt(
							int(math.Round(-20*float64(dpi))),
							int(math.Round(12*float64(dpi))),
						))
						c.PathArcTo(path, 6*dpi, 0, 2*math.Pi, -1)
						c.PathStroke(col, false, 2)
					}),
				),
			),

			giu.Dummy(0, 0),
			giu.Style().SetDisabled(mode == "decrypt" && !keyfile && !deniability).To(
				giu.Row(
					giu.Label("Keyfiles:"),
					giu.Button("Edit").Size(54, 0).OnClick(func() {
						showKeyfile = true
						modalId++
						giu.Update()
					}),
					giu.Tooltip("Manage keyfiles to use for "+(func() string {
						if mode != "decrypt" {
							return "encryption"
						}
						return "decryption"
					}())),

					giu.Style().SetDisabled(mode == "decrypt").To(
						giu.Button("Create").Size(54, 0).OnClick(func() {
							f := dialog.File().Title("Choose where to save the keyfile")
							f.SetStartDir(func() string {
								if len(onlyFiles) > 0 {
									return filepath.Dir(onlyFiles[0])
								}
								return filepath.Dir(onlyFolders[0])
							}())
							f.SetInitFilename("keyfile-" + strconv.Itoa(int(time.Now().Unix())) + ".bin")
							file, err := f.Save()
							if file == "" || err != nil {
								return
							}

							fout, err := os.Create(file)
							if err != nil {
								mainStatus = "Failed to create keyfile"
								mainStatusColor = RED
								giu.Update()
								return
							}
							data := make([]byte, 32)
							if n, err := rand.Read(data); err != nil || n != 32 {
								panic(errors.New("fatal crypto/rand error"))
							}
							n, err := fout.Write(data)
							if err != nil || n != 32 {
								fout.Close()
								panic(errors.New("failed to write full keyfile"))
							}
							if err := fout.Close(); err != nil {
								panic(err)
							} else {
								mainStatus = "Ready"
								mainStatusColor = WHITE
								giu.Update()
								return
							}
						}),
						giu.Tooltip("Generate a cryptographically secure keyfile"),
					),
					giu.Style().SetDisabled(true).To(
						giu.InputText(&keyfileLabel).Size(giu.Auto),
					),
				),
			),
		),

		giu.Separator(),
		giu.Style().SetDisabled(mode != "decrypt" && ((len(keyfiles) == 0 && password == "") || (password != cpassword)) || deniability).To(
			giu.Style().SetDisabled(mode == "decrypt" && (comments == "" || comments == "Comments are corrupted")).To(
				giu.Label(commentsLabel),
				giu.InputText(&comments).Size(giu.Auto).Flags(func() giu.InputTextFlags {
					if commentsDisabled {
						return giu.InputTextFlagsReadOnly
					} else if deniability {
						comments = ""
					}
					return giu.InputTextFlagsNone
				}()),
				giu.Custom(func() {
					if !commentsDisabled {
						giu.Tooltip("Note: comments are not encrypted!").Build()
					}
				}),
			),
		),
		giu.Style().SetDisabled((len(keyfiles) == 0 && password == "") || (mode == "encrypt" && password != cpassword)).To(
			giu.Label("Advanced:"),
			giu.Custom(func() {
				if mode != "decrypt" {
					giu.Row(
						giu.Checkbox("Paranoid mode", &paranoid),
						giu.Tooltip("Provides the highest level of security attainable"),
						giu.Dummy(-170, 0),
						giu.Style().SetDisabled(recursively || !(len(allFiles) > 1 || len(onlyFolders) > 0)).To(
							giu.Checkbox("Compress files", &compress),
							giu.Tooltip("Compress files with Deflate before encrypting"),
						),
					).Build()

					giu.Row(
						giu.Checkbox("Reed-Solomon", &reedsolo),
						giu.Tooltip("Prevent file corruption with erasure coding"),
						giu.Dummy(-170, 0),
						giu.Checkbox("Delete files", &delete),
						giu.Tooltip("Delete the input files after encryption"),
					).Build()

					giu.Row(
						giu.Checkbox("Deniability", &deniability),
						giu.Tooltip("Warning: only use this if you know what it does!"),
						giu.Dummy(-170, 0),
						giu.Style().SetDisabled(!(len(allFiles) > 1 || len(onlyFolders) > 0)).To(
							giu.Checkbox("Recursively", &recursively).OnChange(func() {
								compress = false
							}),
							giu.Tooltip("Warning: only use this if you know what it does!"),
						),
					).Build()

					giu.Row(
						giu.Checkbox("Split into chunks:", &split),
						giu.Tooltip("Split the output file into smaller chunks"),
						giu.Dummy(-170, 0),
						giu.InputText(&splitSize).Size(86/dpi).Flags(2).OnChange(func() {
							split = splitSize != ""
						}),
						giu.Tooltip("Choose the chunk size"),
						giu.Combo("##splitter", splitUnits[splitSelected], splitUnits, &splitSelected).Size(68),
						giu.Tooltip("Choose the chunk units"),
					).Build()
				} else {
					giu.Row(
						giu.Style().SetDisabled(deniability).To(
							giu.Checkbox("Force decrypt", &keep),
							giu.Tooltip("Override security measures when decrypting"),
						),
						giu.Dummy(-170, 0),
						giu.Checkbox("Delete volume", &delete),
						giu.Tooltip("Delete the volume after a successful decryption"),
					).Build()

					giu.Row(
						giu.Style().SetDisabled(!strings.HasSuffix(inputFile, ".zip.pcv")).To(
							giu.Checkbox("Auto unzip", &autoUnzip).OnChange(func() {
								if !autoUnzip {
									sameLevel = false
								}
							}),
							giu.Tooltip("Extract .zip upon decryption (may overwrite files)"),
						),
						giu.Dummy(-170, 0),
						giu.Style().SetDisabled(!autoUnzip).To(
							giu.Checkbox("Same level", &sameLevel),
							giu.Tooltip("Extract .zip contents to same folder as volume"),
						),
					).Build()
				}
			}),

			giu.Style().SetDisabled(recursively).To(
				giu.Label("Save output as:"),
				giu.Custom(func() {
					w, _ := giu.GetAvailableRegion()
					bw, _ := giu.CalcTextSize("Change")
					p, _ := giu.GetWindowPadding()
					bw += p * 2
					dw := w - bw - p
					giu.Style().SetDisabled(true).To(
						giu.InputText(func() *string {
							tmp := ""
							if outputFile == "" {
								return &tmp
							}
							tmp = filepath.Base(outputFile)
							if split {
								tmp += ".*"
							}
							if recursively {
								tmp = "(multiple values)"
							}
							return &tmp
						}()).Size(dw / dpi / dpi).Flags(16384),
					).Build()

					giu.SameLine()
					giu.Button("Change").Size(bw/dpi, 0).OnClick(func() {
						f := dialog.File().Title("Choose where to save the output. Don't include extensions")
						f.SetStartDir(func() string {
							if len(onlyFiles) > 0 {
								return filepath.Dir(onlyFiles[0])
							}
							return filepath.Dir(onlyFolders[0])
						}())

						// Prefill the filename
						tmp := strings.TrimSuffix(filepath.Base(outputFile), ".pcv")
						f.SetInitFilename(strings.TrimSuffix(tmp, filepath.Ext(tmp)))
						if mode == "encrypt" && (len(allFiles) > 1 || len(onlyFolders) > 0 || compress) {
							f.SetInitFilename("encrypted-" + strconv.Itoa(int(time.Now().Unix())))
						}

						// Get the chosen file path
						file, err := f.Save()
						if file == "" || err != nil {
							return
						}
						file = filepath.Join(filepath.Dir(file), strings.Split(filepath.Base(file), ".")[0])

						// Add the correct extensions
						if mode == "encrypt" {
							if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
								file += ".zip.pcv"
							} else {
								file += filepath.Ext(inputFile) + ".pcv"
							}
						} else {
							if strings.HasSuffix(inputFile, ".zip.pcv") {
								file += ".zip"
							} else {
								tmp := strings.TrimSuffix(filepath.Base(inputFile), ".pcv")
								file += filepath.Ext(tmp)
							}
						}
						outputFile = file
						mainStatus = "Ready"
						mainStatusColor = WHITE
						giu.Update()
					}).Build()
					giu.Tooltip("Save the output with a custom name and path").Build()
				}),
			),

			giu.Dummy(0, 0),
			giu.Separator(),
			giu.Dummy(0, 0),
			giu.Button(func() string {
				if !recursively {
					return startLabel
				}
				return "Process"
			}()).Size(giu.Auto, 34).OnClick(onClickStartButton),
			giu.Custom(func() {
				if mainStatus != "Ready" {
					giu.Style().SetColor(giu.StyleColorText, mainStatusColor).To(
						giu.Label(mainStatus),
					).Build()
					return
				}
				if requiredFreeSpace > 0 {
					multiplier := 1
					if len(allFiles) > 1 || len(onlyFolders) > 0 { // need a temporary zip file
						multiplier++
					}
					if deniability {
						multiplier++
					}
					if split {
						multiplier++
					}
					if recombine {
						multiplier++
					}
					if autoUnzip {
						multiplier++
					}
					giu.Style().SetColor(giu.StyleColorText, WHITE).To(
						giu.Label("Ready (ensure >" + sizeify(requiredFreeSpace*int64(multiplier)) + " of disk space is free)"),
					).Build()
				} else {
					giu.Style().SetColor(giu.StyleColorText, WHITE).To(
						giu.Label("Ready"),
					).Build()
				}
			}),
		),

		giu.Custom(func() {
			window.SetSize(int(318*dpi), giu.GetCursorPos().Y+1)
		}),
	)
}

func onDrop(names []string) {
	if showKeyfile {
		keyfiles = append(keyfiles, names...)

		// Make sure keyfiles are accessible, remove duplicates
		var tmp []string
		for _, i := range keyfiles {
			duplicate := false
			for _, j := range tmp {
				if i == j {
					duplicate = true
				}
			}
			stat, statErr := os.Stat(i)
			fin, err := os.Open(i)
			if err == nil {
				fin.Close()
			} else {
				showKeyfile = false
				resetUI()
				accessDenied("Keyfile read")
				giu.Update()
				return
			}
			if !duplicate && statErr == nil && !stat.IsDir() {
				tmp = append(tmp, i)
			}
		}
		keyfiles = tmp

		// Update the keyfile status
		if len(keyfiles) == 0 {
			keyfileLabel = "None selected"
		} else if len(keyfiles) == 1 {
			keyfileLabel = "Using 1 keyfile"
		} else {
			keyfileLabel = fmt.Sprintf("Using %d keyfiles", len(keyfiles))
		}

		modalId++
		giu.Update()
		return
	}

	scanning = true
	files, folders := 0, 0
	compressDone, compressTotal = 0, 0
	resetUI()

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			mainStatus = "Failed to stat dropped item"
			mainStatusColor = RED
			giu.Update()
			return
		}

		// A folder was dropped
		if stat.IsDir() {
			folders++
			mode = "encrypt"
			inputLabel = "1 folder"
			startLabel = "Zip and Encrypt"
			onlyFolders = append(onlyFolders, names[0])
			inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			outputFile = inputFile + ".pcv"
		} else { // A file was dropped
			files++
			requiredFreeSpace = stat.Size()

			// Is the file a part of a split volume?
			nums := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
			endsNum := false
			for _, i := range nums {
				if strings.HasSuffix(names[0], i) {
					endsNum = true
				}
			}
			isSplit := strings.Contains(names[0], ".pcv.") && endsNum

			// Decide if encrypting or decrypting
			if strings.HasSuffix(names[0], ".pcv") || isSplit {
				mode = "decrypt"
				inputLabel = "Volume for decryption"
				startLabel = "Decrypt"
				commentsLabel = "Comments (read-only):"
				commentsDisabled = true

				// Get the correct input and output filenames
				if isSplit {
					ind := strings.Index(names[0], ".pcv")
					names[0] = names[0][:ind+4]
					inputFile = names[0]
					outputFile = names[0][:ind]
					recombine = true

					// Find out the number of splitted chunks
					totalFiles := 0
					for {
						stat, err := os.Stat(fmt.Sprintf("%s.%d", inputFile, totalFiles))
						if err != nil {
							break
						}
						totalFiles++
						compressTotal += stat.Size()
					}
					requiredFreeSpace = compressTotal
				} else {
					outputFile = names[0][:len(names[0])-4]
				}

				// Open the input file in read-only mode
				var fin *os.File
				var err error
				if isSplit {
					fin, err = os.Open(names[0] + ".0")
				} else {
					fin, err = os.Open(names[0])
				}
				if err != nil {
					resetUI()
					accessDenied("Read")
					giu.Update()
					return
				}

				// Check if version can be read from header
				tmp := make([]byte, 15)
				if n, err := fin.Read(tmp); err != nil || n != 15 {
					fin.Close()
					mainStatus = "Failed to read 15 bytes from file"
					mainStatusColor = RED
					giu.Update()
					return
				}
				tmp, err = rsDecode(rs5, tmp)
				if valid, _ := regexp.Match(`^v\d\.\d{2}`, tmp); err != nil || !valid {
					// Volume has plausible deniability
					deniability = true
					mainStatus = "Can't read header, assuming volume is deniable"
					fin.Close()
					giu.Update()
				} else {
					// Read comments from file and check for corruption
					tmp = make([]byte, 15)
					if n, err := fin.Read(tmp); err != nil || n != 15 {
						fin.Close()
						mainStatus = "Failed to read 15 bytes from file"
						mainStatusColor = RED
						giu.Update()
						return
					}
					tmp, err = rsDecode(rs5, tmp)
					if err == nil {
						commentsLength, err := strconv.Atoi(string(tmp))
						if err != nil {
							comments = "Comment length is corrupted"
							giu.Update()
						} else {
							tmp = make([]byte, commentsLength*3)
							if n, err := fin.Read(tmp); err != nil || n != commentsLength*3 {
								fin.Close()
								mainStatus = "Failed to read comments from file"
								mainStatusColor = RED
								giu.Update()
								return
							}
							comments = ""
							for i := 0; i < commentsLength*3; i += 3 {
								t, err := rsDecode(rs1, tmp[i:i+3])
								if err != nil {
									comments = "Comments are corrupted"
									break
								}
								comments += string(t)
							}
							giu.Update()
						}
					} else {
						comments = "Comments are corrupted"
						giu.Update()
					}

					// Read flags from file and check for corruption
					flags := make([]byte, 15)
					if n, err := fin.Read(flags); err != nil || n != 15 {
						fin.Close()
						mainStatus = "Failed to read 15 bytes from file"
						mainStatusColor = RED
						giu.Update()
						return
					}
					if err := fin.Close(); err != nil {
						panic(err)
					}
					flags, err = rsDecode(rs5, flags)
					if err != nil {
						mainStatus = "The volume header is damaged"
						mainStatusColor = RED
						giu.Update()
						return
					}

					// Update UI and variables according to flags
					if flags[1] == 1 {
						keyfile = true
						keyfileLabel = "Keyfiles required"
					} else {
						keyfileLabel = "Not applicable"
					}
					if flags[2] == 1 {
						keyfileOrdered = true
					}
					giu.Update()
				}
			} else { // One file was dropped for encryption
				mode = "encrypt"
				inputLabel = "1 file"
				startLabel = "Encrypt"
				inputFile = names[0]
				outputFile = names[0] + ".pcv"
				giu.Update()
			}

			// Add the file
			onlyFiles = append(onlyFiles, names[0])
			inputFile = names[0]
			if !isSplit {
				compressTotal += stat.Size()
			}
			giu.Update()
		}
	} else { // There are multiple dropped items
		mode = "encrypt"
		startLabel = "Zip and Encrypt"

		// Go through each dropped item and add to corresponding slices
		for _, name := range names {
			stat, err := os.Stat(name)
			if err != nil {
				resetUI()
				mainStatus = "Failed to stat dropped items"
				mainStatusColor = RED
				giu.Update()
				return
			}
			if stat.IsDir() {
				folders++
				onlyFolders = append(onlyFolders, name)
			} else {
				files++
				onlyFiles = append(onlyFiles, name)
				allFiles = append(allFiles, name)

				compressTotal += stat.Size()
				requiredFreeSpace += stat.Size()
				inputLabel = fmt.Sprintf("Scanning files... (%s)", sizeify(compressTotal))
				giu.Update()
			}
		}

		// Update UI with the number of files and folders selected
		if folders == 0 {
			inputLabel = fmt.Sprintf("%d files", files)
		} else if files == 0 {
			inputLabel = fmt.Sprintf("%d folders", folders)
		} else {
			if files == 1 && folders > 1 {
				inputLabel = fmt.Sprintf("1 file and %d folders", folders)
			} else if folders == 1 && files > 1 {
				inputLabel = fmt.Sprintf("%d files and 1 folder", files)
			} else if folders == 1 && files == 1 {
				inputLabel = "1 file and 1 folder"
			} else {
				inputLabel = fmt.Sprintf("%d files and %d folders", files, folders)
			}
		}

		// Set the input and output paths
		inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
		outputFile = inputFile + ".pcv"
		giu.Update()
	}

	// Recursively add all files in 'onlyFolders' to 'allFiles'
	go func() {
		oldInputLabel := inputLabel
		for _, name := range onlyFolders {
			if filepath.Walk(name, func(path string, _ os.FileInfo, err error) error {
				if err != nil {
					resetUI()
					mainStatus = "Failed to walk through dropped items"
					mainStatusColor = RED
					giu.Update()
					return err
				}
				stat, err := os.Stat(path)
				if err != nil {
					resetUI()
					mainStatus = "Failed to walk through dropped items"
					mainStatusColor = RED
					giu.Update()
					return err
				}
				// If 'path' is a valid file path, add to 'allFiles'
				if !stat.IsDir() {
					allFiles = append(allFiles, path)
					compressTotal += stat.Size()
					requiredFreeSpace += stat.Size()
					inputLabel = fmt.Sprintf("Scanning files... (%s)", sizeify(compressTotal))
					giu.Update()
				}
				return nil
			}) != nil {
				resetUI()
				mainStatus = "Failed to walk through dropped items"
				mainStatusColor = RED
				giu.Update()
				return
			}
		}
		inputLabel = fmt.Sprintf("%s (%s)", oldInputLabel, sizeify(compressTotal))
		scanning = false
		giu.Update()
	}()
}

func work() {
	popupStatus = "Starting..."
	mainStatus = "Working..."
	mainStatusColor = WHITE
	working = true
	padded := false
	giu.Update()

	// Cryptography values
	var salt []byte                    // Argon2 salt, 16 bytes
	var hkdfSalt []byte                // HKDF-SHA3 salt, 32 bytes
	var serpentIV []byte               // Serpent IV, 16 bytes
	var nonce []byte                   // 24-byte XChaCha20 nonce
	var keyHash []byte                 // SHA3-512 hash of encryption key
	var keyHashRef []byte              // Same as 'keyHash', but used for comparison
	var keyfileKey []byte              // The SHA3-256 hashes of keyfiles
	var keyfileHash = make([]byte, 32) // The SHA3-256 of 'keyfileKey'
	var keyfileHashRef []byte          // Same as 'keyfileHash', but used for comparison
	var authTag []byte                 // 64-byte authentication tag (BLAKE2b or HMAC-SHA3)

	var tempZipCipherW *chacha20.Cipher
	var tempZipCipherR *chacha20.Cipher
	var tempZipInUse bool = false
	func() { // enclose to keep out of parent scope
		key, nonce := make([]byte, 32), make([]byte, 12)
		if n, err := rand.Read(key); err != nil || n != 32 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 12 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(key, make([]byte, 32)) || bytes.Equal(nonce, make([]byte, 12)) {
			panic(errors.New("fatal crypto/rand error")) // this should never happen but be safe
		}
		var errW error
		var errR error
		tempZipCipherW, errW = chacha20.NewUnauthenticatedCipher(key, nonce)
		tempZipCipherR, errR = chacha20.NewUnauthenticatedCipher(key, nonce)
		if errW != nil || errR != nil {
			panic(errors.New("fatal chacha20 init error"))
		}
	}()

	// Combine/compress all files into a .zip file if needed
	if len(allFiles) > 1 || len(onlyFolders) > 0 {
		// Consider case where compressing only one file
		files := allFiles
		if len(allFiles) == 0 {
			files = onlyFiles
		}

		// Get the root directory of the selected files
		var rootDir string
		if len(onlyFolders) > 0 {
			rootDir = filepath.Dir(onlyFolders[0])
		} else {
			rootDir = filepath.Dir(onlyFiles[0])
		}

		// Open a temporary .zip for writing
		inputFile = strings.TrimSuffix(outputFile, ".pcv") + ".tmp"
		file, err := os.Create(inputFile)
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}

		// Add each file to the .zip
		tempZip := encryptedZipWriter{
			_w:      file,
			_cipher: tempZipCipherW,
		}
		tempZipInUse = true
		writer := zip.NewWriter(&tempZip)
		compressStart = time.Now()
		for i, path := range files {
			progressInfo = fmt.Sprintf("%d/%d", i+1, len(files))
			giu.Update()

			// Create file info header (size, last modified, etc.)
			stat, err := os.Stat(path)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(inputFile)
				resetUI()
				mainStatus = "Failed to stat input files"
				mainStatusColor = RED
				return
			}
			header, err := zip.FileInfoHeader(stat)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(inputFile)
				resetUI()
				mainStatus = "Failed to create zip.FileInfoHeader"
				mainStatusColor = RED
				return
			}
			header.Name = strings.TrimPrefix(path, rootDir)
			header.Name = filepath.ToSlash(header.Name)
			header.Name = strings.TrimPrefix(header.Name, "/")

			if compress {
				header.Method = zip.Deflate
			} else {
				header.Method = zip.Store
			}

			// Open the file for reading
			entry, err := writer.CreateHeader(header)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(inputFile)
				resetUI()
				mainStatus = "Failed to writer.CreateHeader"
				mainStatusColor = RED
				return
			}
			fin, err := os.Open(path)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(inputFile)
				resetUI()
				accessDenied("Read")
				return
			}

			// Use a passthrough to catch compression progress
			passthrough := &compressorProgress{Reader: fin}
			buf := make([]byte, MiB)
			_, err = io.CopyBuffer(entry, passthrough, buf)
			fin.Close()

			if err != nil {
				writer.Close()
				insufficientSpace(nil, file)
				os.Remove(inputFile)
				return
			}

			if !working {
				writer.Close()
				cancel(nil, file)
				os.Remove(inputFile)
				return
			}
		}
		if err := writer.Close(); err != nil {
			panic(err)
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
	}

	// Recombine a split file if necessary
	if recombine {
		totalFiles := 0
		totalBytes := int64(0)
		done := 0

		// Find out the number of splitted chunks
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", inputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			totalBytes += stat.Size()
		}

		// Make sure not to overwrite anything
		_, err := os.Stat(outputFile + ".pcv")
		if err == nil { // File already exists
			mainStatus = "Please remove " + filepath.Base(outputFile+".pcv")
			mainStatusColor = RED
			return
		}

		// Create a .pcv to combine chunks into
		fout, err := os.Create(outputFile + ".pcv")
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}

		// Merge all chunks into one file
		startTime := time.Now()
		for i := range totalFiles {
			fin, err := os.Open(fmt.Sprintf("%s.%d", inputFile, i))
			if err != nil {
				fout.Close()
				os.Remove(outputFile + ".pcv")
				resetUI()
				accessDenied("Read")
				return
			}

			for {
				if !working {
					cancel(fin, fout)
					os.Remove(outputFile + ".pcv")
					return
				}

				// Copy from the chunk into the .pcv
				data := make([]byte, MiB)
				read, err := fin.Read(data)
				if err != nil {
					break
				}
				data = data[:read]
				var n int
				n, err = fout.Write(data)
				done += read

				if err != nil || n != len(data) {
					insufficientSpace(fin, fout)
					os.Remove(outputFile + ".pcv")
					return
				}

				// Update the stats
				progress, speed, eta = statify(int64(done), totalBytes, startTime)
				progressInfo = fmt.Sprintf("%d/%d", i+1, totalFiles)
				popupStatus = fmt.Sprintf("Recombining at %.2f MiB/s (ETA: %s)", speed, eta)
				giu.Update()
			}
			if err := fin.Close(); err != nil {
				panic(err)
			}
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}
		inputFileOld = inputFile
		inputFile = outputFile + ".pcv"
	}

	// Input volume has plausible deniability
	if mode == "decrypt" && deniability {
		popupStatus = "Removing deniability protection..."
		progressInfo = ""
		progress = 0
		canCancel = false
		giu.Update()

		// Get size of volume for showing progress
		stat, err := os.Stat(inputFile)
		if err != nil {
			// we already read from inputFile successfully in onDrop
			// so it is very unlikely this err != nil, we can just panic
			panic(err)
		}
		total := stat.Size()

		// Rename input volume to free up the filename
		fin, err := os.Open(inputFile)
		if err != nil {
			panic(err)
		}
		for strings.HasSuffix(inputFile, ".tmp") {
			inputFile = strings.TrimSuffix(inputFile, ".tmp")
		}
		inputFile += ".tmp"
		fout, err := os.Create(inputFile)
		if err != nil {
			panic(err)
		}

		// Get the Argon2 salt and XChaCha20 nonce from input volume
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := fin.Read(salt); err != nil || n != 16 {
			panic(errors.New("failed to read 16 bytes from file"))
		}
		if n, err := fin.Read(nonce); err != nil || n != 24 {
			panic(errors.New("failed to read 24 bytes from file"))
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Decrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if n, err := fout.Write(dst); err != nil || n != len(dst) {
				fout.Close()
				os.Remove(fout.Name())
				panic(errors.New("failed to write dst"))
			}

			// Update stats
			done += size
			counter += MiB
			progress = float32(float64(done) / float64(total))
			giu.Update()

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if n, err := tmp.Write(nonce); err != nil || n != len(nonce) {
					panic(errors.New("failed to write nonce to tmp during rekeying"))
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}

		// Check if the version can be read from the volume
		fin, err = os.Open(inputFile)
		if err != nil {
			panic(err)
		}
		tmp := make([]byte, 15)
		if n, err := fin.Read(tmp); err != nil || n != 15 {
			panic(errors.New("failed to read 15 bytes from file"))
		}
		if err := fin.Close(); err != nil {
			panic(err)
		}
		tmp, err = rsDecode(rs5, tmp)
		if valid, _ := regexp.Match(`^v1\.\d{2}`, tmp); err != nil || !valid {
			os.Remove(inputFile)
			inputFile = strings.TrimSuffix(inputFile, ".tmp")
			broken(nil, nil, "Password is incorrect or the file is not a volume", true)
			if recombine {
				inputFile = inputFileOld
			}
			return
		}
	}

	canCancel = false
	progress = 0
	progressInfo = ""
	giu.Update()

	// Subtract the header size from the total size if decrypting
	stat, err := os.Stat(inputFile)
	if err != nil {
		resetUI()
		accessDenied("Read")
		return
	}
	total := stat.Size()
	if mode == "decrypt" {
		total -= 789
	}

	// Open input file in read-only mode
	fin, err := os.Open(inputFile)
	if err != nil {
		resetUI()
		accessDenied("Read")
		return
	}

	// Setup output file
	var fout *os.File

	// If encrypting, generate values and write to file
	if mode == "encrypt" {
		popupStatus = "Generating values..."
		giu.Update()

		// Stores any errors when writing to file
		errs := make([]error, 11)

		// Make sure not to overwrite anything
		_, err = os.Stat(outputFile)
		if split && err == nil { // File already exists
			fin.Close()
			if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			mainStatus = "Please remove " + filepath.Base(outputFile)
			mainStatusColor = RED
			return
		}

		// Create the output file
		fout, err = os.Create(outputFile + ".incomplete")
		if err != nil {
			fin.Close()
			if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			accessDenied("Write")
			return
		}

		// Set up cryptographic values
		salt = make([]byte, 16)
		hkdfSalt = make([]byte, 32)
		serpentIV = make([]byte, 16)
		nonce = make([]byte, 24)

		// Write the program version to file
		_, errs[0] = fout.Write(rsEncode(rs5, []byte(version)))

		if len(comments) > 99999 {
			panic(errors.New("comments exceed maximum length"))
		}

		// Encode and write the comment length to file
		commentsLength := []byte(fmt.Sprintf("%05d", len(comments)))
		_, errs[1] = fout.Write(rsEncode(rs5, commentsLength))

		// Encode the comment and write to file
		for _, i := range []byte(comments) {
			_, err := fout.Write(rsEncode(rs1, []byte{i}))
			if err != nil {
				errs[2] = err
			}
		}

		// Configure flags and write to file
		flags := make([]byte, 5)
		if paranoid { // Paranoid mode selected
			flags[0] = 1
		}
		if len(keyfiles) > 0 { // Keyfiles are being used
			flags[1] = 1
		}
		if keyfileOrdered { // Order of keyfiles matter
			flags[2] = 1
		}
		if reedsolo { // Full Reed-Solomon encoding is selected
			flags[3] = 1
		}
		if total%int64(MiB) >= int64(MiB)-128 { // Reed-Solomon internals
			flags[4] = 1
		}
		_, errs[3] = fout.Write(rsEncode(rs5, flags))

		// Fill values with Go's CSPRNG
		if _, err := rand.Read(salt); err != nil {
			panic(err)
		}
		if _, err := rand.Read(hkdfSalt); err != nil {
			panic(err)
		}
		if _, err := rand.Read(serpentIV); err != nil {
			panic(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			panic(err)
		}
		if bytes.Equal(salt, make([]byte, 16)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(hkdfSalt, make([]byte, 32)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(serpentIV, make([]byte, 16)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("fatal crypto/rand error"))
		}

		// Encode values with Reed-Solomon and write to file
		_, errs[4] = fout.Write(rsEncode(rs16, salt))
		_, errs[5] = fout.Write(rsEncode(rs32, hkdfSalt))
		_, errs[6] = fout.Write(rsEncode(rs16, serpentIV))
		_, errs[7] = fout.Write(rsEncode(rs24, nonce))

		// Write placeholders for future use
		_, errs[8] = fout.Write(make([]byte, 192))  // Hash of encryption key
		_, errs[9] = fout.Write(make([]byte, 96))   // Hash of keyfile key
		_, errs[10] = fout.Write(make([]byte, 192)) // BLAKE2b/HMAC-SHA3 tag

		for _, err := range errs {
			if err != nil {
				insufficientSpace(fin, fout)
				if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
					os.Remove(inputFile)
				}
				os.Remove(fout.Name())
				return
			}
		}
	} else { // Decrypting, read values from file and decode
		popupStatus = "Reading values..."
		giu.Update()

		// Stores any Reed-Solomon decoding errors
		errs := make([]error, 10)

		version := make([]byte, 15)
		fin.Read(version)
		_, errs[0] = rsDecode(rs5, version)

		tmp := make([]byte, 15)
		fin.Read(tmp)
		tmp, errs[1] = rsDecode(rs5, tmp)

		if valid, err := regexp.Match(`^\d{5}$`, tmp); !valid || err != nil {
			broken(fin, nil, "Unable to read comments length", true)
			return
		}

		commentsLength, _ := strconv.Atoi(string(tmp))
		fin.Read(make([]byte, commentsLength*3))
		total -= int64(commentsLength) * 3

		flags := make([]byte, 15)
		fin.Read(flags)
		flags, errs[2] = rsDecode(rs5, flags)
		paranoid = flags[0] == 1
		reedsolo = flags[3] == 1
		padded = flags[4] == 1
		if deniability {
			keyfile = flags[1] == 1
			keyfileOrdered = flags[2] == 1
		}

		salt = make([]byte, 48)
		fin.Read(salt)
		salt, errs[3] = rsDecode(rs16, salt)

		hkdfSalt = make([]byte, 96)
		fin.Read(hkdfSalt)
		hkdfSalt, errs[4] = rsDecode(rs32, hkdfSalt)

		serpentIV = make([]byte, 48)
		fin.Read(serpentIV)
		serpentIV, errs[5] = rsDecode(rs16, serpentIV)

		nonce = make([]byte, 72)
		fin.Read(nonce)
		nonce, errs[6] = rsDecode(rs24, nonce)

		keyHashRef = make([]byte, 192)
		fin.Read(keyHashRef)
		keyHashRef, errs[7] = rsDecode(rs64, keyHashRef)

		keyfileHashRef = make([]byte, 96)
		fin.Read(keyfileHashRef)
		keyfileHashRef, errs[8] = rsDecode(rs32, keyfileHashRef)

		authTag = make([]byte, 192)
		fin.Read(authTag)
		authTag, errs[9] = rsDecode(rs64, authTag)

		// If there was an issue during decoding, the header is corrupted
		for _, err := range errs {
			if err != nil {
				if keep { // If the user chooses to force decrypt
					kept = true
				} else {
					broken(fin, nil, "The volume header is damaged", true)
					return
				}
			}
		}
	}

	popupStatus = "Deriving key..."
	giu.Update()

	// Derive encryption keys and subkeys
	var key []byte
	if paranoid {
		key = argon2.IDKey(
			[]byte(password),
			salt,
			8,     // 8 passes
			1<<20, // 1 GiB memory
			8,     // 8 threads
			32,    // 32-byte output key
		)
	} else {
		key = argon2.IDKey(
			[]byte(password),
			salt,
			4,
			1<<20,
			4,
			32,
		)
	}
	if bytes.Equal(key, make([]byte, 32)) {
		panic(errors.New("fatal crypto/argon2 error"))
	}

	// If keyfiles are being used
	if len(keyfiles) > 0 || keyfile {
		popupStatus = "Reading keyfiles..."
		giu.Update()

		var keyfileTotal int64
		for _, path := range keyfiles {
			stat, err := os.Stat(path)
			if err != nil {
				panic(err) // we already checked os.Stat in onDrop
			}
			keyfileTotal += stat.Size()
		}

		if keyfileOrdered { // If order matters, hash progressively
			var tmp = sha3.New256()
			var keyfileDone int

			// For each keyfile...
			for _, path := range keyfiles {
				fin, err := os.Open(path)
				if err != nil {
					panic(err)
				}
				for { // Read in chunks of 1 MiB
					data := make([]byte, MiB)
					size, err := fin.Read(data)
					if err != nil {
						break
					}
					data = data[:size]
					if _, err := tmp.Write(data); err != nil { // Hash the data
						panic(err)
					}

					// Update progress
					keyfileDone += size
					progress = float32(keyfileDone) / float32(keyfileTotal)
					giu.Update()
				}
				if err := fin.Close(); err != nil {
					panic(err)
				}
			}
			keyfileKey = tmp.Sum(nil) // Get the SHA3-256

			// Store a hash of 'keyfileKey' for comparison
			tmp = sha3.New256()
			if _, err := tmp.Write(keyfileKey); err != nil {
				panic(err)
			}
			keyfileHash = tmp.Sum(nil)
		} else { // If order doesn't matter, hash individually and combine
			var keyfileDone int

			// For each keyfile...
			for _, path := range keyfiles {
				fin, err := os.Open(path)
				if err != nil {
					panic(err)
				}
				tmp := sha3.New256()
				for { // Read in chunks of 1 MiB
					data := make([]byte, MiB)
					size, err := fin.Read(data)
					if err != nil {
						break
					}
					data = data[:size]
					if _, err := tmp.Write(data); err != nil { // Hash the data
						panic(err)
					}

					// Update progress
					keyfileDone += size
					progress = float32(keyfileDone) / float32(keyfileTotal)
					giu.Update()
				}
				if err := fin.Close(); err != nil {
					panic(err)
				}

				sum := tmp.Sum(nil) // Get the SHA3-256

				// XOR keyfile hash with 'keyfileKey'
				if keyfileKey == nil {
					keyfileKey = sum
				} else {
					for i, j := range sum {
						keyfileKey[i] ^= j
					}
				}
			}

			// Store a hash of 'keyfileKey' for comparison
			tmp := sha3.New256()
			if _, err := tmp.Write(keyfileKey); err != nil {
				panic(err)
			}
			keyfileHash = tmp.Sum(nil)
		}
	}

	popupStatus = "Calculating values..."
	giu.Update()

	// Hash the encryption key for comparison when decrypting
	tmp := sha3.New512()
	if _, err := tmp.Write(key); err != nil {
		panic(err)
	}
	keyHash = tmp.Sum(nil)

	// Validate the password and/or keyfiles
	if mode == "decrypt" {
		keyCorrect := subtle.ConstantTimeCompare(keyHash, keyHashRef) == 1
		keyfileCorrect := subtle.ConstantTimeCompare(keyfileHash, keyfileHashRef) == 1
		incorrect := !keyCorrect
		if keyfile || len(keyfiles) > 0 {
			incorrect = !keyCorrect || !keyfileCorrect
		}

		// If something is incorrect
		if incorrect {
			if keep {
				kept = true
			} else {
				if !keyCorrect {
					mainStatus = "The provided password is incorrect"
				} else {
					if keyfileOrdered {
						mainStatus = "Incorrect keyfiles or ordering"
					} else {
						mainStatus = "Incorrect keyfiles"
					}
					if deniability {
						fin.Close()
						os.Remove(inputFile)
						inputFile = strings.TrimSuffix(inputFile, ".tmp")
					}
				}
				broken(fin, nil, mainStatus, true)
				if recombine {
					inputFile = inputFileOld
				}
				return
			}
		}

		// Create the output file for decryption
		fout, err = os.Create(outputFile + ".incomplete")
		if err != nil {
			fin.Close()
			if recombine {
				os.Remove(inputFile)
			}
			accessDenied("Write")
			return
		}
	}

	if len(keyfiles) > 0 || keyfile {
		// Prevent an even number of duplicate keyfiles
		if bytes.Equal(keyfileKey, make([]byte, 32)) {
			mainStatus = "Duplicate keyfiles detected"
			mainStatusColor = RED
			fin.Close()
			if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			fout.Close()
			os.Remove(fout.Name())
			return
		}

		// XOR the encryption key with the keyfile key
		tmp := key
		key = make([]byte, 32)
		for i := range key {
			key[i] = tmp[i] ^ keyfileKey[i]
		}
	}

	done, counter := 0, 0
	chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	// Use HKDF-SHA3 to generate a subkey for the MAC
	var mac hash.Hash
	subkey := make([]byte, 32)
	hkdf := hkdf.New(sha3.New256, key, hkdfSalt, nil)
	if n, err := hkdf.Read(subkey); err != nil || n != 32 {
		panic(errors.New("fatal hkdf.Read error"))
	}
	if paranoid {
		mac = hmac.New(sha3.New512, subkey) // HMAC-SHA3
	} else {
		mac, err = blake2b.New512(subkey) // Keyed BLAKE2b
		if err != nil {
			panic(err)
		}
	}

	// Generate another subkey for use as Serpent's key
	serpentKey := make([]byte, 32)
	if n, err := hkdf.Read(serpentKey); err != nil || n != 32 {
		panic(errors.New("fatal hkdf.Read error"))
	}
	s, err := serpent.NewCipher(serpentKey)
	if err != nil {
		panic(err)
	}
	serpent := cipher.NewCTR(s, serpentIV)

	// Start the main encryption process
	canCancel = true
	startTime := time.Now()
	tempZip := encryptedZipReader{
		_r:      fin,
		_cipher: tempZipCipherR,
	}
	for {
		if !working {
			cancel(fin, fout)
			if recombine || len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			os.Remove(fout.Name())
			return
		}

		// Read in data from the file
		var src []byte
		if mode == "decrypt" && reedsolo {
			src = make([]byte, MiB/128*136)
		} else {
			src = make([]byte, MiB)
		}

		var size int
		if tempZipInUse {
			size, err = tempZip.Read(src)
		} else {
			size, err = fin.Read(src)
		}
		if err != nil {
			break
		}
		src = src[:size]
		dst := make([]byte, len(src))

		// Do the actual encryption
		if mode == "encrypt" {
			if paranoid {
				serpent.XORKeyStream(dst, src)
				copy(src, dst)
			}

			chacha.XORKeyStream(dst, src)
			if _, err := mac.Write(dst); err != nil {
				panic(err)
			}

			if reedsolo {
				copy(src, dst)
				dst = nil
				// If a full MiB is available
				if len(src) == MiB {
					// Encode every chunk
					for i := 0; i < MiB; i += 128 {
						dst = append(dst, rsEncode(rs128, src[i:i+128])...)
					}
				} else {
					// Encode the full chunks
					chunks := math.Floor(float64(len(src)) / 128)
					for i := 0; float64(i) < chunks; i++ {
						dst = append(dst, rsEncode(rs128, src[i*128:(i+1)*128])...)
					}

					// Pad and encode the final partial chunk
					dst = append(dst, rsEncode(rs128, pad(src[int(chunks*128):]))...)
				}
			}
		} else { // Decryption
			if reedsolo {
				copy(dst, src)
				src = nil
				// If a complete 1 MiB block is available
				if len(dst) == MiB/128*136 {
					// Decode every chunk
					for i := 0; i < MiB/128*136; i += 136 {
						tmp, err := rsDecode(rs128, dst[i:i+136])
						if err != nil {
							if keep {
								kept = true
							} else {
								broken(fin, fout, "The input file is irrecoverably damaged", false)
								return
							}
						}
						if i == MiB/128*136-136 && done+MiB/128*136 >= int(total) && padded {
							tmp = unpad(tmp)
						}
						src = append(src, tmp...)

						if !fastDecode && i%17408 == 0 {
							progress, speed, eta = statify(int64(done+i), total, startTime)
							progressInfo = fmt.Sprintf("%.2f%%", progress*100)
							popupStatus = fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", speed, eta)
							giu.Update()
						}
					}
				} else {
					// Decode the full chunks
					chunks := len(dst)/136 - 1
					for i := range chunks {
						tmp, err := rsDecode(rs128, dst[i*136:(i+1)*136])
						if err != nil {
							if keep {
								kept = true
							} else {
								broken(fin, fout, "The input file is irrecoverably damaged", false)
								return
							}
						}
						src = append(src, tmp...)

						if !fastDecode && i%128 == 0 {
							progress, speed, eta = statify(int64(done+i*136), total, startTime)
							progressInfo = fmt.Sprintf("%.2f%%", progress*100)
							popupStatus = fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", speed, eta)
							giu.Update()
						}
					}

					// Unpad and decode the final partial chunk
					tmp, err := rsDecode(rs128, dst[int(chunks)*136:])
					if err != nil {
						if keep {
							kept = true
						} else {
							broken(fin, fout, "The input file is irrecoverably damaged", false)
							return
						}
					}
					src = append(src, unpad(tmp)...)
				}
				dst = make([]byte, len(src))
			}

			if _, err := mac.Write(src); err != nil {
				panic(err)
			}
			chacha.XORKeyStream(dst, src)

			if paranoid {
				copy(src, dst)
				serpent.XORKeyStream(dst, src)
			}
		}

		// Write the data to output file
		_, err = fout.Write(dst)
		if err != nil {
			insufficientSpace(fin, fout)
			if recombine || len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
				os.Remove(inputFile)
			}
			os.Remove(fout.Name())
			return
		}

		// Update stats
		if mode == "decrypt" && reedsolo {
			done += MiB / 128 * 136
		} else {
			done += MiB
		}
		counter += MiB
		progress, speed, eta = statify(int64(done), total, startTime)
		progressInfo = fmt.Sprintf("%.2f%%", progress*100)
		if mode == "encrypt" {
			popupStatus = fmt.Sprintf("Encrypting at %.2f MiB/s (ETA: %s)", speed, eta)
		} else {
			if fastDecode {
				popupStatus = fmt.Sprintf("Decrypting at %.2f MiB/s (ETA: %s)", speed, eta)
			}
		}
		giu.Update()

		// Change nonce/IV after 60 GiB to prevent overflow
		if counter >= 60*GiB {
			// ChaCha20
			nonce = make([]byte, 24)
			if n, err := hkdf.Read(nonce); err != nil || n != 24 {
				panic(errors.New("fatal hkdf.Read error"))
			}
			chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
			if err != nil {
				panic(err)
			}

			// Serpent
			serpentIV = make([]byte, 16)
			if n, err := hkdf.Read(serpentIV); err != nil || n != 16 {
				panic(errors.New("fatal hkdf.Read error"))
			}
			serpent = cipher.NewCTR(s, serpentIV)

			// Reset counter to 0
			counter = 0
		}
	}

	progress = 0
	progressInfo = ""
	giu.Update()

	if mode == "encrypt" {
		popupStatus = "Writing values..."
		giu.Update()

		// Seek back to header and write important values
		if _, err := fout.Seek(int64(309+len(comments)*3), 0); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs64, keyHash)); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs32, keyfileHash)); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs64, mac.Sum(nil))); err != nil {
			panic(err)
		}
	} else {
		popupStatus = "Comparing values..."
		giu.Update()

		// Validate the authenticity of decrypted data
		if subtle.ConstantTimeCompare(mac.Sum(nil), authTag) == 0 {
			// Decrypt again but this time rebuilding the input data
			if reedsolo && fastDecode {
				fastDecode = false
				fin.Close()
				fout.Close()
				work()
				return
			}

			if keep {
				kept = true
			} else {
				broken(fin, fout, "The input file is damaged or modified", false)
				return
			}
		}
	}

	if err := fin.Close(); err != nil {
		panic(err)
	}
	if err := fout.Close(); err != nil {
		panic(err)
	}

	if err := os.Rename(outputFile+".incomplete", outputFile); err != nil {
		panic(err)
	}

	// Add plausible deniability
	if mode == "encrypt" && deniability {
		popupStatus = "Adding plausible deniability..."
		canCancel = false
		giu.Update()

		// Get size of volume for showing progress
		stat, err := os.Stat(outputFile)
		if err != nil {
			panic(err)
		}
		total := stat.Size()

		// Rename the output volume to free up the filename
		os.Rename(outputFile, outputFile+".tmp")
		fin, err := os.Open(outputFile + ".tmp")
		if err != nil {
			panic(err)
		}
		fout, err := os.Create(outputFile + ".incomplete")
		if err != nil {
			panic(err)
		}

		// Use a random Argon2 salt and XChaCha20 nonce
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := rand.Read(salt); err != nil || n != 16 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 24 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(salt, make([]byte, 16)) || bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if _, err := fout.Write(salt); err != nil {
			panic(err)
		}
		if _, err := fout.Write(nonce); err != nil {
			panic(err)
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)
		if bytes.Equal(key, make([]byte, 32)) {
			panic(errors.New("fatal crypto/argon2 error"))
		}
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Encrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if _, err := fout.Write(dst); err != nil {
				panic(err)
			}

			// Update stats
			done += size
			counter += MiB
			progress = float32(float64(done) / float64(total))
			giu.Update()

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if _, err := tmp.Write(nonce); err != nil {
					panic(err)
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}
		if err := os.Remove(fin.Name()); err != nil {
			panic(err)
		}
		if err := os.Rename(outputFile+".incomplete", outputFile); err != nil {
			panic(err)
		}
		canCancel = true
		giu.Update()
	}

	// Split the file into chunks
	if split {
		var splitted []string
		stat, err := os.Stat(outputFile)
		if err != nil {
			panic(err)
		}
		size := stat.Size()
		finishedFiles := 0
		finishedBytes := 0
		chunkSize, err := strconv.Atoi(splitSize)
		if err != nil {
			panic(err)
		}

		// Calculate chunk size
		if splitSelected == 0 {
			chunkSize *= KiB
		} else if splitSelected == 1 {
			chunkSize *= MiB
		} else if splitSelected == 2 {
			chunkSize *= GiB
		} else if splitSelected == 3 {
			chunkSize *= TiB
		} else {
			chunkSize = int(math.Ceil(float64(size) / float64(chunkSize)))
		}

		// Get the number of required chunks
		chunks := int(math.Ceil(float64(size) / float64(chunkSize)))
		progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
		giu.Update()

		// Open the volume for reading
		fin, err := os.Open(outputFile)
		if err != nil {
			panic(err)
		}

		// Delete existing chunks to prevent mixed chunks
		names, err := filepath.Glob(outputFile + ".*")
		if err != nil {
			panic(err)
		}
		for _, i := range names {
			if err := os.Remove(i); err != nil {
				panic(err)
			}
		}

		// Start the splitting process
		startTime := time.Now()
		for i := range chunks {
			// Make the chunk
			fout, _ := os.Create(fmt.Sprintf("%s.%d.incomplete", outputFile, i))
			done := 0

			// Copy data into the chunk
			for {
				data := make([]byte, MiB)
				for done+len(data) > chunkSize {
					data = make([]byte, int(math.Ceil(float64(len(data))/2)))
				}

				read, err := fin.Read(data)
				if err != nil {
					break
				}
				if !working {
					cancel(fin, fout)
					if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
						os.Remove(inputFile)
					}
					os.Remove(outputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", outputFile, i))
					return
				}

				data = data[:read]
				_, err = fout.Write(data)
				if err != nil {
					insufficientSpace(fin, fout)
					if len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
						os.Remove(inputFile)
					}
					os.Remove(outputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", outputFile, i))
					return
				}
				done += read
				if done >= chunkSize {
					break
				}

				// Update stats
				finishedBytes += read
				progress, speed, eta = statify(int64(finishedBytes), int64(size), startTime)
				popupStatus = fmt.Sprintf("Splitting at %.2f MiB/s (ETA: %s)", speed, eta)
				giu.Update()
			}
			if err := fout.Close(); err != nil {
				panic(err)
			}

			// Update stats
			finishedFiles++
			if finishedFiles == chunks {
				finishedFiles--
			}
			splitted = append(splitted, fmt.Sprintf("%s.%d", outputFile, i))
			progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
			giu.Update()
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := os.Remove(outputFile); err != nil {
			panic(err)
		}
		names, err = filepath.Glob(outputFile + ".*.incomplete")
		if err != nil {
			panic(err)
		}
		for _, i := range names {
			if err := os.Rename(i, strings.TrimSuffix(i, ".incomplete")); err != nil {
				panic(err)
			}
		}
	}

	canCancel = false
	progress = 0
	progressInfo = ""
	giu.Update()

	// Delete temporary files used during encryption and decryption
	if recombine || len(allFiles) > 1 || len(onlyFolders) > 0 || compress {
		if err := os.Remove(inputFile); err != nil {
			panic(err)
		}
		if deniability {
			os.Remove(strings.TrimSuffix(inputFile, ".tmp"))
		}
	}

	// Delete the input files if the user chooses
	if delete {
		popupStatus = "Deleting files..."
		giu.Update()

		if mode == "decrypt" {
			if recombine { // Remove each chunk of volume
				i := 0
				for {
					_, err := os.Stat(fmt.Sprintf("%s.%d", inputFileOld, i))
					if err != nil {
						break
					}
					if err := os.Remove(fmt.Sprintf("%s.%d", inputFileOld, i)); err != nil {
						panic(err)
					}
					i++
				}
			} else {
				if err := os.Remove(inputFile); err != nil {
					panic(err)
				}
				if deniability {
					if err := os.Remove(strings.TrimSuffix(inputFile, ".tmp")); err != nil {
						panic(err)
					}
				}
			}
		} else {
			for _, i := range onlyFiles {
				if err := os.Remove(i); err != nil {
					panic(err)
				}
			}
			for _, i := range onlyFolders {
				if err := os.RemoveAll(i); err != nil {
					panic(err)
				}
			}
		}
	}
	if mode == "decrypt" && deniability {
		os.Remove(inputFile)
	}

	if mode == "decrypt" && !kept && autoUnzip {
		showProgress = true
		popupStatus = "Unzipping..."
		giu.Update()

		if err := unpackArchive(outputFile); err != nil {
			mainStatus = "Auto unzipping failed!"
			mainStatusColor = RED
			giu.Update()
			return
		}

		if err := os.Remove(outputFile); err != nil {
			panic(err)
		}
	}

	// All done, reset the UI
	oldKept := kept
	resetUI()
	kept = oldKept

	// If the user chose to keep a corrupted/modified file, let them know
	if kept {
		mainStatus = "The input file was modified. Please be careful"
		mainStatusColor = YELLOW
	} else {
		mainStatus = "Completed"
		mainStatusColor = GREEN
	}
}

// If the OS denies reading or writing to a file
func accessDenied(s string) {
	mainStatus = s + " access denied by operating system"
	mainStatusColor = RED
}

// If there isn't enough disk space
func insufficientSpace(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	mainStatus = "Insufficient disk space"
	mainStatusColor = RED
}

// If corruption is detected during decryption
func broken(fin *os.File, fout *os.File, message string, keepOutput bool) {
	fin.Close()
	fout.Close()
	mainStatus = message
	mainStatusColor = RED

	// Clean up files since decryption failed
	if recombine {
		os.Remove(inputFile)
	}
	if !keepOutput {
		os.Remove(outputFile)
	}
}

// Stop working if user hits "Cancel"
func cancel(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	mainStatus = "Operation cancelled by user"
	mainStatusColor = WHITE
}

// Reset the UI to a clean state with nothing selected or checked
func resetUI() {
	imgui.ClearActiveID()
	mode = ""

	inputFile = ""
	inputFileOld = ""
	outputFile = ""
	onlyFiles = nil
	onlyFolders = nil
	allFiles = nil
	inputLabel = "Drop files and folders into this window"

	password = ""
	cpassword = ""
	passwordState = giu.InputTextFlagsPassword
	passwordStateLabel = "Show"

	passgenLength = 32
	passgenUpper = true
	passgenLower = true
	passgenNums = true
	passgenSymbols = true
	passgenCopy = true

	keyfile = false
	keyfiles = nil
	keyfileOrdered = false
	keyfileLabel = "None selected"

	comments = ""
	commentsLabel = "Comments:"
	commentsDisabled = false

	paranoid = false
	reedsolo = false
	deniability = false
	recursively = false
	split = false
	splitSize = ""
	splitSelected = 1
	recombine = false
	compress = false
	delete = false
	autoUnzip = false
	sameLevel = false
	keep = false
	kept = false

	startLabel = "Start"
	mainStatus = "Ready"
	mainStatusColor = WHITE
	popupStatus = ""
	requiredFreeSpace = 0

	progress = 0
	progressInfo = ""
	giu.Update()
}

// Reed-Solomon encoder
func rsEncode(rs *infectious.FEC, data []byte) []byte {
	res := make([]byte, rs.Total())
	rs.Encode(data, func(s infectious.Share) {
		res[s.Number] = s.Data[0]
	})
	return res
}

// Reed-Solomon decoder
func rsDecode(rs *infectious.FEC, data []byte) ([]byte, error) {
	// If fast decode, just return the first 128 bytes
	if rs.Total() == 136 && fastDecode {
		return data[:128], nil
	}

	tmp := make([]infectious.Share, rs.Total())
	for i := range rs.Total() {
		tmp[i].Number = i
		tmp[i].Data = append(tmp[i].Data, data[i])
	}
	res, err := rs.Decode(nil, tmp)

	// Force decode the data but return the error as well
	if err != nil {
		if rs.Total() == 136 {
			return data[:128], err
		}
		return data[:rs.Total()/3], err
	}

	// No issues, return the decoded data
	return res, nil
}

// PKCS#7 pad (for use with Reed-Solomon)
func pad(data []byte) []byte {
	padLen := 128 - len(data)%128
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// PKCS#7 unpad
func unpad(data []byte) []byte {
	padLen := int(data[127])
	return data[:128-padLen]
}

// Generate a cryptographically secure password
func genPassword() string {
	chars := ""
	if passgenUpper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if passgenLower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if passgenNums {
		chars += "1234567890"
	}
	if passgenSymbols {
		chars += "-=_+!@#$^&()?<>"
	}
	tmp := make([]byte, passgenLength)
	for i := range int(passgenLength) {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		tmp[i] = chars[j.Int64()]
	}
	if passgenCopy {
		giu.Context.GetPlatform().SetClipboard(string(tmp))
	}
	return string(tmp)
}

// Convert done, total, and starting time to progress, speed, and ETA
func statify(done int64, total int64, start time.Time) (float32, float64, string) {
	progress := float32(done) / float32(total)
	elapsed := float64(time.Since(start)) / float64(MiB) / 1000
	speed := float64(done) / elapsed / float64(MiB)
	eta := int(math.Floor(float64(total-done) / (speed * float64(MiB))))
	return float32(math.Min(float64(progress), 1)), speed, timeify(eta)
}

// Convert seconds to HH:MM:SS
func timeify(seconds int) string {
	hours := int(math.Floor(float64(seconds) / 3600))
	seconds %= 3600
	minutes := int(math.Floor(float64(seconds) / 60))
	seconds %= 60
	hours = int(math.Max(float64(hours), 0))
	minutes = int(math.Max(float64(minutes), 0))
	seconds = int(math.Max(float64(seconds), 0))
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// Convert bytes to KiB, MiB, etc.
func sizeify(size int64) string {
	if size >= int64(TiB) {
		return fmt.Sprintf("%.2f TiB", float64(size)/float64(TiB))
	} else if size >= int64(GiB) {
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	} else if size >= int64(MiB) {
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	} else {
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	}
}

func unpackArchive(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	var totalSize int64
	for _, f := range reader.File {
		totalSize += int64(f.UncompressedSize64)
	}

	var extractDir string
	if sameLevel {
		extractDir = filepath.Dir(zipPath)
	} else {
		extractDir = filepath.Join(filepath.Dir(zipPath), strings.TrimSuffix(filepath.Base(zipPath), ".zip"))
	}

	var done int64
	startTime := time.Now()

	for _, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}
		outPath := filepath.Join(extractDir, f.Name)

		// Make directory if current entry is a folder
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(outPath, 0700); err != nil {
				return err
			}
		}
	}

	for i, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}

		// Already handled above
		if f.FileInfo().IsDir() {
			continue
		}

		outPath := filepath.Join(extractDir, f.Name)

		// Otherwise create necessary parent directories
		if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
			return err
		}

		// Open the file inside the archive
		fileInArchive, err := f.Open()
		if err != nil {
			return err
		}
		defer fileInArchive.Close()

		dstFile, err := os.Create(outPath)
		if err != nil {
			return err
		}

		// Read from zip in chunks to update progress
		buffer := make([]byte, MiB)
		for {
			n, readErr := fileInArchive.Read(buffer)
			if n > 0 {
				_, writeErr := dstFile.Write(buffer[:n])
				if writeErr != nil {
					dstFile.Close()
					os.Remove(dstFile.Name())
					return writeErr
				}

				done += int64(n)
				progress, speed, eta = statify(done, totalSize, startTime)
				progressInfo = fmt.Sprintf("%d/%d", i+1, len(reader.File))
				popupStatus = fmt.Sprintf("Unpacking at %.2f MiB/s (ETA: %s)", speed, eta)
				giu.Update()
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				dstFile.Close()
				return readErr
			}
		}
		dstFile.Close()
	}

	return nil
}

func main() {
	if rsErr1 != nil || rsErr2 != nil || rsErr3 != nil || rsErr4 != nil || rsErr5 != nil || rsErr6 != nil || rsErr7 != nil {
		panic(errors.New("rs failed to init"))
	}
	// Create the main window
	window = giu.NewMasterWindow("Picocrypt "+version[1:], 318, 507, giu.MasterWindowFlagsNotResizable)

	// Start the dialog module
	dialog.Init()

	// Set callbacks
	window.SetDropCallback(onDrop)
	window.SetCloseCallback(func() bool {
		return !working && !showProgress
	})

	// Set universal DPI
	dpi = giu.Context.GetPlatform().GetContentScale()

	// Simulate dropping command line arguments
	flag.Parse()
	if flag.NArg() > 0 {
		onDrop(flag.Args())
	}

	// Start the UI
	window.Run(draw)
}

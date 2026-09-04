// Command demogif renders docs/demo/transcript.txt into docs/demo.gif.
//
// The transcript is real agentgate output, captured from the binary; this
// program only draws it the way a terminal would, with a typing animation for
// the commands and a pause per line of output. Run it with `make demo`.
//
// Transcript format, one entry per line:
//
//	$ command          typed character by character, then executed
//	^C                 shown as an interrupt
//	#sleep 800         pause, in milliseconds
//	#clear             clear the screen, as `clear` would
//	anything else      a line of output, ANSI SGR colours honoured
package main

import (
	"bufio"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"log"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

// Terminal geometry.
const (
	cols       = 100
	rows       = 21
	fontSize   = 15
	lineHeight = 23
	padX       = 18
	padY       = 14
	titleBar   = 36
)

// Colours: a dark terminal that reads well on GitHub in both themes.
var (
	cBg     = color.RGBA{0x12, 0x14, 0x19, 0xff}
	cChrome = color.RGBA{0x1d, 0x20, 0x27, 0xff}
	cFg     = color.RGBA{0xe6, 0xe8, 0xeb, 0xff}
	cDim    = color.RGBA{0x8a, 0x91, 0x9c, 0xff}
	cRed    = color.RGBA{0xff, 0x6b, 0x6b, 0xff}
	cGreen  = color.RGBA{0x7e, 0xd3, 0x21, 0xff}
	cYellow = color.RGBA{0xf5, 0xc5, 0x42, 0xff}
	cPurple = color.RGBA{0xc7, 0x92, 0xea, 0xff}
	cCyan   = color.RGBA{0x62, 0xc9, 0xff, 0xff}
	cPrompt = color.RGBA{0x7e, 0xd3, 0x21, 0xff}
	cDot1   = color.RGBA{0xff, 0x5f, 0x57, 0xff}
	cDot2   = color.RGBA{0xfe, 0xbc, 0x2e, 0xff}
	cDot3   = color.RGBA{0x28, 0xc8, 0x40, 0xff}
)

// span is a run of text in one colour.
type span struct {
	text string
	col  color.RGBA
}

// entry is one parsed transcript line.
type entry struct {
	kind  string // cmd, out, sleep, interrupt
	spans []span
	text  string
	ms    int
}

func main() {
	in := flag.String("in", "docs/demo/story.txt", "transcript to render")
	out := flag.String("out", "docs/demo/story.gif", "where to write the GIF")
	flag.Parse()

	entries, err := parse(*in)
	if err != nil {
		log.Fatal(err)
	}
	face, err := opentype.NewFace(must(opentype.Parse(gomono.TTF)), &opentype.FaceOptions{
		Size: fontSize, DPI: 72, Hinting: font.HintingFull,
	})
	if err != nil {
		log.Fatal(err)
	}
	r := newRenderer(face)
	anim := r.animate(entries)
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	if err := gif.EncodeAll(f, anim); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	st, _ := os.Stat(*out)
	fmt.Printf("wrote %s: %d frames, %d KB\n", *out, len(anim.Image), st.Size()/1024)
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func parse(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "$ "):
			out = append(out, entry{kind: "cmd", text: strings.TrimPrefix(line, "$ ")})
		case line == "^C":
			out = append(out, entry{kind: "interrupt"})
		case line == "#clear":
			out = append(out, entry{kind: "clear"})
		case strings.HasPrefix(line, "#sleep "):
			ms, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "#sleep ")))
			if err != nil {
				return nil, fmt.Errorf("bad sleep: %q", line)
			}
			out = append(out, entry{kind: "sleep", ms: ms})
		default:
			out = append(out, entry{kind: "out", spans: parseANSI(line)})
		}
	}
	return out, sc.Err()
}

// parseANSI turns the SGR sequences agentgate emits into coloured spans.
func parseANSI(s string) []span {
	var (
		spans []span
		cur   = cFg
		buf   strings.Builder
	)
	flush := func() {
		if buf.Len() > 0 {
			spans = append(spans, span{text: buf.String(), col: cur})
			buf.Reset()
		}
	}
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			end := strings.IndexByte(s[i:], 'm')
			if end < 0 {
				break
			}
			code := s[i+2 : i+end]
			flush()
			switch code {
			case "0", "":
				cur = cFg
			case "2":
				cur = cDim
			case "31", "31;1":
				cur = cRed
			case "32":
				cur = cGreen
			case "33", "33;1":
				cur = cYellow
			case "35":
				cur = cPurple
			case "36":
				cur = cCyan
			}
			i += end + 1
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		buf.WriteRune(r)
		i += size
	}
	flush()
	return spans
}

type renderer struct {
	face    font.Face
	cellW   int
	width   int
	height  int
	palette color.Palette
	lines   [][]span
}

func newRenderer(face font.Face) *renderer {
	adv, _ := face.GlyphAdvance('M')
	r := &renderer{face: face, cellW: adv.Ceil()}
	r.width = padX*2 + cols*r.cellW
	r.height = titleBar + padY*2 + rows*lineHeight
	r.palette = buildPalette()
	return r
}

// buildPalette blends every text colour towards the background in a few
// steps, so anti-aliased glyph edges have somewhere to land.
func buildPalette() color.Palette {
	pal := color.Palette{cBg, cChrome, cDot1, cDot2, cDot3}
	for _, c := range []color.RGBA{cFg, cDim, cRed, cGreen, cYellow, cPurple, cCyan, cPrompt} {
		for _, t := range []float64{1, 0.8, 0.6, 0.4, 0.25, 0.12} {
			pal = append(pal, blend(c, cBg, t))
		}
	}
	return pal
}

func blend(a, b color.RGBA, t float64) color.RGBA {
	mix := func(x, y uint8) uint8 { return uint8(float64(x)*t + float64(y)*(1-t) + 0.5) }
	return color.RGBA{mix(a.R, b.R), mix(a.G, b.G), mix(a.B, b.B), 0xff}
}

// blank returns a frame with the window chrome and no text.
func (r *renderer) blank() *image.Paletted {
	img := image.NewPaletted(image.Rect(0, 0, r.width, r.height), r.palette)
	draw.Draw(img, img.Bounds(), &image.Uniform{cBg}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(0, 0, r.width, titleBar), &image.Uniform{cChrome}, image.Point{}, draw.Src)
	for i, c := range []color.RGBA{cDot1, cDot2, cDot3} {
		circle(img, 20+i*22, titleBar/2, 6, c)
	}
	title := "agentgate"
	d := &font.Drawer{Dst: img, Src: &image.Uniform{cDim}, Face: r.face}
	w := d.MeasureString(title).Ceil()
	d.Dot = fixed.P((r.width-w)/2, titleBar/2+fontSize/2-2)
	d.DrawString(title)
	return img
}

func circle(img draw.Image, cx, cy, radius int, c color.Color) {
	for y := -radius; y <= radius; y++ {
		for x := -radius; x <= radius; x++ {
			if x*x+y*y <= radius*radius {
				img.Set(cx+x, cy+y, c)
			}
		}
	}
}

// frame draws the visible lines, plus an optional partially typed command
// with a cursor. Long lines wrap at the terminal width, as they would in a
// terminal, and the screen scrolls when it is full.
func (r *renderer) frame(typing string, cursor bool) *image.Paletted {
	img := r.blank()
	logical := r.lines
	if typing != "" || cursor {
		logical = append(append([][]span{}, r.lines...), []span{{"$ ", cPrompt}, {typing, cFg}})
	}
	var visible [][]span
	for _, line := range logical {
		visible = append(visible, wrap(line, cols)...)
	}
	if len(visible) > rows {
		visible = visible[len(visible)-rows:]
	}
	for i, line := range visible {
		x := padX
		y := titleBar + padY + i*lineHeight + fontSize
		for _, sp := range line {
			d := &font.Drawer{Dst: img, Src: &image.Uniform{sp.col}, Face: r.face, Dot: fixed.P(x, y)}
			d.DrawString(sp.text)
			x += utf8.RuneCountInString(sp.text) * r.cellW
		}
		if cursor && i == len(visible)-1 {
			draw.Draw(img, image.Rect(x+1, y-fontSize+3, x+r.cellW-1, y+3), &image.Uniform{cFg}, image.Point{}, draw.Src)
		}
	}
	return img
}

// wrap splits one logical line into visual lines of at most width cells,
// keeping each cell's colour.
func wrap(line []span, width int) [][]span {
	var (
		out  [][]span
		cur  []span
		used int
	)
	for _, sp := range line {
		runes := []rune(sp.text)
		for len(runes) > 0 {
			room := width - used
			if room <= 0 {
				out = append(out, cur)
				cur, used = nil, 0
				room = width
			}
			take := len(runes)
			if take > room {
				take = room
			}
			cur = append(cur, span{text: string(runes[:take]), col: sp.col})
			used += take
			runes = runes[take:]
		}
	}
	if len(cur) > 0 || len(out) == 0 {
		out = append(out, cur)
	}
	return out
}

// animate plays the transcript into GIF frames. Each frame is stored as the
// rectangle that changed since the previous one, which keeps the file small:
// a typing frame is one line, not a whole screen.
func (r *renderer) animate(entries []entry) *gif.GIF {
	anim := &gif.GIF{LoopCount: 0}
	var prev *image.Paletted
	add := func(img *image.Paletted, delayMS int) {
		delay := delayMS / 10
		if delay < 2 {
			delay = 2
		}
		if prev == nil {
			anim.Image = append(anim.Image, img)
			anim.Delay = append(anim.Delay, delay)
			anim.Disposal = append(anim.Disposal, gif.DisposalNone)
			prev = img
			return
		}
		rect := changed(prev, img)
		if rect.Empty() {
			// Nothing moved: lengthen the previous frame instead.
			anim.Delay[len(anim.Delay)-1] += delay
			return
		}
		sub := img.SubImage(rect).(*image.Paletted)
		anim.Image = append(anim.Image, sub)
		anim.Delay = append(anim.Delay, delay)
		anim.Disposal = append(anim.Disposal, gif.DisposalNone)
		prev = img
	}

	add(r.frame("", true), 600)
	for _, e := range entries {
		switch e.kind {
		case "cmd":
			for i := 1; i <= len(e.text); i++ {
				add(r.frame(e.text[:i], true), 45)
			}
			add(r.frame(e.text, true), 350)
			r.lines = append(r.lines, []span{{"$ ", cPrompt}, {e.text, cFg}})
			add(r.frame("", false), 250)
		case "out":
			r.lines = append(r.lines, e.spans)
			delay := 420
			if len(e.spans) > 0 && (strings.Contains(e.spans[0].text, "FROZEN") || strings.Contains(spansText(e.spans), "TRAP")) {
				delay = 1300
			}
			add(r.frame("", false), delay)
		case "interrupt":
			r.lines = append(r.lines, []span{{"^C", cDim}})
			add(r.frame("", false), 400)
		case "sleep":
			add(r.frame("", false), e.ms)
		case "clear":
			r.lines = nil
			add(r.frame("", true), 500)
		}
	}
	add(r.frame("", true), 2500)
	return anim
}

func spansText(spans []span) string {
	var b strings.Builder
	for _, s := range spans {
		b.WriteString(s.text)
	}
	return b.String()
}

// changed returns the bounding box of the pixels that differ between a and b.
func changed(a, b *image.Paletted) image.Rectangle {
	bounds := a.Bounds()
	minX, minY, maxX, maxY := bounds.Max.X, bounds.Max.Y, bounds.Min.X, bounds.Min.Y
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		rowA := a.Pix[(y-bounds.Min.Y)*a.Stride : (y-bounds.Min.Y+1)*a.Stride]
		rowB := b.Pix[(y-bounds.Min.Y)*b.Stride : (y-bounds.Min.Y+1)*b.Stride]
		for x := range rowA {
			if rowA[x] != rowB[x] {
				if x < minX {
					minX = x
				}
				if x+1 > maxX {
					maxX = x + 1
				}
				if y < minY {
					minY = y
				}
				if y+1 > maxY {
					maxY = y + 1
				}
			}
		}
	}
	if minX >= maxX || minY >= maxY {
		return image.Rectangle{}
	}
	return image.Rect(minX, minY, maxX, maxY)
}

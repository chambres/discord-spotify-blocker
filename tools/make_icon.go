package main

import (
    "bytes"
    "fmt"
    "image"
    "image/png"
    "log"
    "math"
    "os"

    ico "github.com/sergeymakinen/go-ico"
    xdraw "golang.org/x/image/draw"
)

func scaleImage(src image.Image, size int) *image.NRGBA {
    srcBounds := src.Bounds()
    srcW := srcBounds.Dx()
    srcH := srcBounds.Dy()
    scale := math.Min(float64(size)/float64(srcW), float64(size)/float64(srcH))
    newW := int(math.Round(float64(srcW) * scale))
    newH := int(math.Round(float64(srcH) * scale))

    dst := image.NewNRGBA(image.Rect(0, 0, size, size))
    offX := (size - newW) / 2
    offY := (size - newH) / 2
    dr := image.Rect(offX, offY, offX+newW, offY+newH)
    xdraw.CatmullRom.Scale(dst, dr, src, srcBounds, xdraw.Over, nil)
    return dst
}

func main() {
    // Expect spotify-xxl.png in current directory
    f, err := os.Open("spotify-xxl.png")
    if err != nil {
        log.Fatalf("failed to open spotify-xxl.png: %v", err)
    }
    defer f.Close()
    src, err := png.Decode(f)
    if err != nil {
        log.Fatalf("failed to decode PNG: %v", err)
    }

    // Generate a single 256x256 image for the ICO (widely supported and good quality)
    dst := scaleImage(src, 256)
    var buf bytes.Buffer
    if err := ico.Encode(&buf, dst); err != nil {
        log.Fatalf("failed to encode ico: %v", err)
    }

    out := "icon.ico"
    if err := os.WriteFile(out, buf.Bytes(), 0644); err != nil {
        log.Fatalf("failed to write %s: %v", out, err)
    }

    fmt.Println("Wrote icon.ico (256x256)")
}

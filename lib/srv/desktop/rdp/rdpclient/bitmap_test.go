package rdpclient

import (
	"bufio"
	"image"
	"os"
	"testing"

	"github.com/gravitational/teleport/lib/srv/desktop/tdp"
)

func loadBitmaps(b *testing.B) [][]byte {
	b.Helper()

	f, err := os.Open("bitmaps.txt")
	if err != nil {
		b.Fatal(err)
	}

	var result [][]byte

	s := bufio.NewScanner(f)
	for s.Scan() {
		b := s.Bytes()
		if len(b)%4 != 0 {
			continue
		}
		b2 := make([]byte, len(b))
		copy(b2, b)
		result = append(result, b2)
	}

	if err := s.Err(); err != nil {
		b.Fatal(err)
	}

	if len(result) == 0 {
		b.Fatal("got no bitmaps")
	}

	return result
}

var frame tdp.PNGFrame

func BenchmarkOriginalApproach(b *testing.B) {
	b.StopTimer()
	enc := tdp.PNGEncoder()
	bitmaps := loadBitmaps(b)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, bitmap := range bitmaps {
			for i := 0; i < len(bitmap); i += 4 {
				bitmap[i], bitmap[i+2], bitmap[i+3] = bitmap[i+2], bitmap[i], 255
			}
			img := image.NewNRGBA(image.Rectangle{
				Min: image.Pt(0, 0),
				Max: image.Pt(65, 65),
			})
			copy(img.Pix, bitmap)

			frame = tdp.NewPNG(img, enc)
		}
	}
}

func BenchmarkRGBA(b *testing.B) {
	b.StopTimer()
	enc := tdp.PNGEncoder()
	bitmaps := loadBitmaps(b)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, bitmap := range bitmaps {
			for i := 0; i < len(bitmap); i += 4 {
				bitmap[i], bitmap[i+2] = bitmap[i+2], bitmap[i]
			}
			img := image.NewRGBA(image.Rectangle{
				Min: image.Pt(704, 448),
				Max: image.Pt(767+1, 511+1),
			})
			copy(img.Pix, bitmap)

			frame = tdp.NewPNG(img, enc)
		}
	}
}

func BenchmarkRGBAReuseImg(b *testing.B) {
	b.StopTimer()
	enc := tdp.PNGEncoder()
	bitmaps := loadBitmaps(b)
	pooled := image.NewRGBA(image.Rectangle{
		Min: image.Pt(0, 0),
		Max: image.Pt(64, 64),
	})
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, bitmap := range bitmaps {
			for i := 0; i < len(bitmap); i += 4 {
				bitmap[i], bitmap[i+2] = bitmap[i+2], bitmap[i]
			}
			// pooled.Rect = image.Rectangle{
			// 	Min: image.Pt(704, 448),
			// 	Max: image.Pt(767+1, 511+1),
			// }
			copy(pooled.Pix, bitmap)

			frame = tdp.NewPNG(pooled, enc)
		}
	}
}

func BenchmarkRGBANoSwap(b *testing.B) {
	b.StopTimer()
	enc := tdp.PNGEncoder()
	bitmaps := loadBitmaps(b)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, bitmap := range bitmaps {
			img := image.NewRGBA(image.Rectangle{
				Min: image.Pt(0, 0),
				Max: image.Pt(64, 64),
			})
			copy(img.Pix, bitmap)

			frame = tdp.NewPNG(img, enc)
		}
	}
}

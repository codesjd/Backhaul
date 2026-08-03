package network

import "math/rand"

// browserUserAgents is a pool of realistic User-Agent strings from various
// browsers/platforms, used to avoid a single static, easily fingerprinted
// value on outbound requests.
var browserUserAgents = []string{
	// Chrome
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Mobile Safari/537.36",
	// Firefox
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0) Gecko/20100101 Firefox/102.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
	"Mozilla/5.0 (Linux; Android 10; Pixel 4 XL) Gecko/20100101 Firefox/96.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) Gecko/20100101 Firefox/90.0",
	// Safari
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	// Edge
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 Edg/95.0.1020.40",
	"Mozilla/5.0 (Linux; Android 11; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.210 Mobile Safari/537.36 EdgA/46.3.4.5155",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.44",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183",
	// Opera
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 OPR/97.0.4719.63",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 OPR/98.0.4759.15",
	"Mozilla/5.0 (Linux; Android 10; SM-N975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36 OPR/65.2.3381.61420",
	"Mozilla/5.0 (Linux; Android 11; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 Mobile Safari/537.36 OPR/71.2.3767.68577",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/99.0.4759.21",
	// Older Browsers
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
}

// RandomUserAgent returns a random entry from browserUserAgents.
func RandomUserAgent() string {
	return browserUserAgents[rand.Intn(len(browserUserAgents))]
}

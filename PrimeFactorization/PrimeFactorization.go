package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	primelibs "../mysolution/primelibs"
)

func main() {
	if len(os.Args) < 2 {
		printMsgAndExit(os.Args[0])
	}

	n, result := new(big.Int).SetString(os.Args[1], 10)
	if n == nil || result == false {
		fmt.Printf("%s ... big.SetString() error.\n", os.Args[1])
		os.Exit(1)
	}

	timeStart := time.Now()

	bitCount := primelibs.GetBitLength(*n, 5000)
	fmt.Printf("%s < pow(2, %d) ... %d bit\n", n.String(), bitCount, bitCount)
	resultArray := primelibs.CalcPrimes(n)
	fmt.Printf("n = %s, primes = [%s]\n", n.String(), primelibs.ArrayBigIntToString(resultArray))

	timeEnd := time.Now()
	fmt.Printf("Execute time: %.3f [s]\n\n", timeEnd.Sub(timeStart).Seconds())
}

func printMsgAndExit(arg0 string) {
	fmt.Printf("\nUsage: go run %s <n>", getFileNameWithoutExt(arg0)+".go")
	os.Exit(1)
}

func getFileNameWithoutExt(path string) string {
	// Fixed with a nice method given by mattn-san
	//return filepath.Base(path[:len(path)-len(filepath.Ext(path))])
	fmt.Printf("path = %s", path)
	return filepath.Base(path[:len(path)-len(filepath.Ext(path))])
}

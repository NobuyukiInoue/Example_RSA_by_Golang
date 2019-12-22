package mysolution

import (
	"fmt"
	"math/big"
	"strconv"
	"time"

	primelibs "./primelibs"
	rwkeys "./rwkeys"
)

// http://golang.jp/pkg/crypto-rsa

var startTime int

// Start ...
func Start(openFileName string) {
	timeStart := time.Now()

	keyType, _ := rwkeys.GetKeyType(openFileName)
	if keyType == "PRIVATE" {
		procKeyPrivate(openFileName)
		//		procOPENSSHKeyPrivate(openFileName)
	} else if keyType == "PUBLIC" {
		procKeyPublic(openFileName)
	} else {
		fmt.Printf("Could not be determined key type.\n")
	}

	timeEnd := time.Now()
	fmt.Printf("Execute time: %.3f [s]\n\n", timeEnd.Sub(timeStart).Seconds())
}

func procKeyPrivate(openFileName string) {
	keyPrivate, _ := rwkeys.ReadRsaPrivateKey(openFileName)

	fmt.Printf("N ... %d bits\n", primelibs.GetBitLength(*keyPrivate.PublicKey.N, 2048))
	fmt.Printf("N = %s\n", (*keyPrivate.PublicKey.N).String())
	fmt.Printf("D = %s\n", (*keyPrivate.D).String())
	fmt.Printf("P = %s\n", (*keyPrivate.Primes[0]).String())
	fmt.Printf("Q = %s\n", (*keyPrivate.Primes[1]).String())

	PQ := new(big.Int).Mul(keyPrivate.Primes[0], keyPrivate.Primes[1])
	fmt.Printf("P*Q = %s\n", PQ.String())

	isEqual := PQ.Cmp(keyPrivate.PublicKey.N)
	if isEqual == 0 {
		fmt.Printf("N == P*Q\n")
	} else {
		fmt.Printf("N != P*Q\n")
	}

	fmt.Printf("Is N a Prime? .. %s\n", strconv.FormatBool((*keyPrivate.PublicKey.N).ProbablyPrime(1)))
	fmt.Printf("Is D a Prime? .. %s\n", strconv.FormatBool((*keyPrivate.D).ProbablyPrime(1)))
	fmt.Printf("Is P a Prime? .. %s\n", strconv.FormatBool((*keyPrivate.Primes[0]).ProbablyPrime(1)))
	fmt.Printf("Is Q a Prime? .. %s\n", strconv.FormatBool((*keyPrivate.Primes[1]).ProbablyPrime(1)))

	/*
		// Nを素因数分解する
		primes := CalcPrimes(keyPrivate.PublicKey.N)
		fmt.Printf("primes = [%s]\n", ArrayBigIntToString(primes))
	*/
}

func procKeyPublic(openFileName string) {
	keyPublic, _ := rwkeys.ReadRsaPublicKey(openFileName)

	fmt.Printf("N ... %d bits\n", primelibs.GetBitLength(*keyPublic.N, 4097))
	fmt.Printf("N = %s\n", (*keyPublic.N).String())
	fmt.Printf("E = %d\n", keyPublic.E)

	/*
		// Nを素因数分解する
		primes := CalcPrimes(keyPublic.N)
		fmt.Printf("primes = [%s]\n", ArrayBigIntToString(primes))
	*/
}

func procOPENSSHKeyPrivate(openFileName string) {
	keyPrivate, _ := rwkeys.ReadOpenSSHPrivateKey(openFileName)
	fmt.Printf("%d\n", keyPrivate)
}

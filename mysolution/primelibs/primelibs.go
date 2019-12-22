package primelibs

import (
	"math/big"
	"strings"
)

// GetBitLength ...
func GetBitLength(N big.Int, max int64) int {
	var i int64
	for i = 1; i < max; i++ {
		if N.Cmp(BigPow(big.NewInt(2), big.NewInt(i))) < 0 {
			return (int)(i)
		}
	}
	return (int)(-1)
}

// BigPow ... Pow() for BigInt
func BigPow(i, e *big.Int) *big.Int {
	return new(big.Int).Exp(i, e, nil)
}

func mySqrt(x *big.Int) *big.Int {
	for left, right := big.NewInt(0), x; ; {
		// mid := left + (right-left)/2
		temp1 := new(big.Int).Sub(right, left)
		temp2 := new(big.Int).Mul(temp1, big.NewInt(2))
		mid := new(big.Int).Add(left, temp2)
		mid2 := new(big.Int).Mul(mid, mid)
		if mid2.Cmp(x) > 0 {
			right = new(big.Int).Sub(mid, big.NewInt(1))
		} else {
			mid3_1 := new(big.Int).Add(mid, big.NewInt(1))
			mid3 := new(big.Int).Mul(mid3_1, mid3_1)
			if mid3.Cmp(x) > 0 {
				return mid
			} else {
				left = new(big.Int).Add(mid, big.NewInt(1))
			}
		}
	}
}

// CalcPrimes ...
func CalcPrimes(n *big.Int) []*big.Int {
	// 素因数を格納する配列
	results := make([]*big.Int, 0)
	workN := n

	// 2 ～ math.sqrt(n) の数字で割っていく
	//max = int(math.sqrt(n)) + 1
	max := new(big.Int).Add(new(big.Int).Sqrt(n), big.NewInt(1)) // 7.169[s] (n = 12345678901)
	//max := new(big.Int).Add(mySqrt(n), big.NewInt(1)) // 7.241[s] (n = 12345678901)

	for num := big.NewInt(2); num.Cmp(max) != 0; num = new(big.Int).Add(num, big.NewInt(1)) {
		for workNnext, mod := new(big.Int).DivMod(workN, num, new(big.Int)); mod.Cmp(big.NewInt(0)) == 0; workNnext, mod = new(big.Int).DivMod(workN, num, new(big.Int)) {
			results = append(results, num)
			if workN.Cmp(big.NewInt(1)) == 0 {
				break
			}
			workN = workNnext
		}

		if workN.Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	if workN.Cmp(big.NewInt(1)) != 0 {
		results = append(results, workN)
	}

	return results
}

// ArrayBigIntToString ...
func ArrayBigIntToString(primes []*big.Int) string {
	if len(primes) <= 0 {
		return ""
	}
	primesStr := make([]string, len(primes))
	for i := 0; i < len(primes); i++ {
		primesStr[i] = (*primes[i]).String()
	}

	resultStr := strings.Join(primesStr[:], ", ")
	return resultStr
}

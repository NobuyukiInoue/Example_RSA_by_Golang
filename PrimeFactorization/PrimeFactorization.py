# -*- coding: utf-8 -*-

import math
import os
import sys
import time

def main():
    argv = sys.argv
    argc = len(argv)

    if argc < 2:
        exit_msg(argv[0])

    if argv[1].isnumeric() == False:
        print("{0} is not numeric.".format(argv[1]))
        exit(1)

    N = int(argv[1])
    if N <= 0:
        print("{0} is not positive integer.".format(argv[1]))
        exit(1)
    
    for i in range(1, 512 + 1):
        if N < pow(2, i):
            break
    print("{0:d} < pow(2, {1:d}) ... {1:d} bit".format(N, i))

    time0 = time.time()

    primes = trial_division(N)
    time1 = time.time()

    print("n = {0:d}, primes = {1}".format(N, primes))
    print("Execution time : {0:f}[s]".format(time1 - time0))


def exit_msg(argv0):
    print("Usage: python {0} value_N".format(argv0))
    exit(0)


def trial_division(n):
    """Return a list of the prime factors for a natural number."""

    """素因数を格納するリスト"""
    prime_list = []

    """2 ～ math.sqrt(n) の数字で割っていく"""
    tmp = int(math.sqrt(n)) + 1
    for num in range(2,tmp):
        while n % num == 0:
            n //= num
            prime_list.append(num)

    if n != 1:
        prime_list.append(n)

    return prime_list


if __name__ == "__main__":
    main()

package main

import (
	"fmt"
	"os"
	"path/filepath"

	mysolution "./mySolution"
)

func main() {
	if len(os.Args) < 2 {
		printMsgAndExit(os.Args[0])
	}

	// ファイル指定のチェック
	if exists(os.Args[1]) == false {
		fmt.Printf(os.Args[1] + " not found.\n")
		return
	}
	openFileName := os.Args[1]

	mysolution.Start(openFileName)
}

func printMsgAndExit(arg0 string) {
	fmt.Printf("\nUsage: go run %s <key_file>\n", getFileNameWithoutExt(arg0)+".go")
	os.Exit(1)
}

func exists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func getFileNameWithoutExt(path string) string {
	// Fixed with a nice method given by mattn-san
	//return filepath.Base(path[:len(path)-len(filepath.Ext(path))])
	fmt.Printf("path = %s", path)
	return filepath.Base(path[:len(path)-len(filepath.Ext(path))])
}

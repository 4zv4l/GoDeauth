package userIO

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

func completer(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
	switch line {
	case "select":
		return "select", len("select"), true
	case "show":
		return "show", len("show"), true
	case "exit":
		return "exit", len("exit"), true
	}
	return line, pos, false
}

func Prompt(prompt string) string {
	if runtime.GOOS == "windows" {
		scan := bufio.NewScanner(os.Stdin)
		fmt.Print(prompt)
		scan.Scan()
		return scan.Text()
	}
	// set the terminal to raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	// print the prompt
	t := term.NewTerminal(os.Stdin, prompt)
	t.AutoCompleteCallback = completer
	str, err := t.ReadLine()
	if err != nil {
		if err == io.EOF {
			os.Exit(0)
		}
		fmt.Println("err :", err)
		return ""
	}
	return str
}

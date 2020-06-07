// This file is part of aph, a tool for generating Argon2id hashes on the
// command line.
// Copyright (C) 2020 Jordan Ocokoljic.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/JordanOcokoljic/aph"
)

// printAndExit checks if the error is non-nil and if it is prints the error
// and exits the application.
func printAndExit(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func main() {
	args := os.Args[1:]
	if len(args) < 5 {
		fmt.Println("aph: not enough arguments provided")
		os.Exit(1)
	}

	var (
		seconds    int
		threads    int
		memory     int
		length     int
		key        string
		salt       string
		result     aph.ResultSet
		prettySalt string
	)

	seconds, err := aph.ParseTime(args[0])
	printAndExit(err)

	threads, err = strconv.Atoi(args[1])
	printAndExit(err)

	memory, err = aph.ParseMemory(args[2])
	printAndExit(err)

	length, err = strconv.Atoi(args[3])
	printAndExit(err)

	key = args[4]

	switch len(args) {
	case 5:
		result, err = aph.GenerateHash(seconds, threads, memory, length, key)
		printAndExit(err)
		prettySalt = base64.RawStdEncoding.EncodeToString([]byte(result.Salt))
	case 6:
		salt = args[5]
		result, err = aph.GenerateHashWithSalt(
			seconds,
			threads,
			memory,
			length,
			key,
			salt,
		)

		printAndExit(err)
		prettySalt = result.Salt
	}

	fmt.Printf(
		`Generation Results:
Time: %dms
Threads: %d
Memory: %dKB
Length: %d

Key: %s
Salt: %s

Hash: %s
Hash Length: %d
Generation Time: %dms
`,
		result.Time,
		result.Threads,
		result.Memory,
		result.Length,
		result.Key,
		prettySalt,
		result.Hash,
		result.Characters,
		result.Duration.Milliseconds(),
	)
}

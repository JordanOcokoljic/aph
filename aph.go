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

package aph

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/JordanOcokoljic/argon2id"
)

var (
	// ErrorMalformedStamp is returned by the Parse functions when the stamp
	// provided that doesn't match the format necessary for parsing.
	ErrorMalformedStamp = errors.New("aph: provided stamp was malformed")

	// ErrorSplitAtomic is returned by the Parse functions when the stamp
	// provided has a fractional value for an atomic type (KB or ms).
	ErrorSplitAtomic = errors.New("aph: cannot use fractional value with type")
)

var (
	// parseTime is a regex that can determine if a provided timestamp is valid
	// and also extracts the necessary deatils out of the stamp.
	parseTime = regexp.MustCompile("(\\d+(?:\\.\\d+)?)(ms|s)")

	// parseMemory is a regex that can determine if a provided memorystamp is
	// valid and also extracts the necessary details out of the stamp.
	parseMemory = regexp.MustCompile("(\\d+(?:\\.\\d+)?)(KB|MB|GB)")
)

// ResultSet is a collection of information about the generation of a hash, it
// includes details such as how long generation took and what the overall size
// of the hash is.
type ResultSet struct {
	Time       int
	Threads    int
	Memory     int
	Length     int
	Key        string
	Hash       string
	Characters int
	Duration   time.Duration
	Salt       string
}

// ParseTime will take a string in either Xs or Xms where X is an number. It
// will return the corresponding number of milliseconds that the time reprsents
// or an error if the string is malformed.
func ParseTime(stamp string) (int, error) {
	details := parseTime.FindStringSubmatch(stamp)
	if details == nil || len(details) != 3 {
		return 0, ErrorMalformedStamp
	}

	t, err := strconv.ParseFloat(details[1], 64)
	if err != nil {
		return 0, err
	}

	var millis int
	switch details[2] {
	case "ms":
		if math.Trunc(t) != t {
			return 0, ErrorSplitAtomic
		}

		millis = int(t)
	case "s":
		millis = int(t * 1000)
	}

	return millis, nil
}

// ParseMemory will take a string in the form of one of XKB, XMB, or XGB where
// X is a number. It will return the corresponding number of KB that the stamp
// represents or an error if the string is malformed.
func ParseMemory(stamp string) (int, error) {
	details := parseMemory.FindStringSubmatch(stamp)
	if details == nil || len(details) != 3 {
		return 0, ErrorMalformedStamp
	}

	s, err := strconv.ParseFloat(details[1], 64)
	if err != nil {
		return 0, err
	}

	var kilobytes int
	switch details[2] {
	case "KB":
		if math.Trunc(s) != s {
			return 0, ErrorSplitAtomic
		}

		kilobytes = int(s)
	case "MB":
		kilobytes = int(s * 1024)
	case "GB":
		kilobytes = int(s * 1024 * 1024)
	}

	return kilobytes, nil
}

// generateHash will perform the hashing of the password and the generation of
// the ResultSet. It is up to the consumer of generateHash to provide it with
// a valid Parameters object.
func generateHash(
	params argon2id.Parameters,
	password []byte,
) (ResultSet, error) {
	var hash []byte
	var duration time.Duration

	start := time.Now()
	hash, err := argon2id.GenerateFromPassword(password, params)
	duration = time.Since(start)

	if err != nil {
		return ResultSet{}, err
	}

	rs := ResultSet{
		Time:       int(params.Time),
		Threads:    int(params.Threads),
		Memory:     int(params.Memory),
		Length:     int(params.Length),
		Key:        string(password),
		Hash:       string(hash),
		Characters: len(hash),
		Duration:   duration,
		Salt:       string(params.Salt),
	}

	return rs, nil
}

// GenerateHash will generate a hash and store the details and result into a
// ResultSet and return the set.
func GenerateHash(
	seconds int,
	threads int,
	memory int,
	length int,
	key string,
) (ResultSet, error) {
	params, err := argon2id.NewParameters(
		uint32(seconds),
		uint32(memory),
		uint8(threads),
		uint32(length),
	)

	if err != nil {
		return ResultSet{}, err
	}

	return generateHash(params, []byte(key))
}

// GenerateHashWithSalt will generate a hash and use the provided salt and
// store the details and result into a ResultSet and return the set.
func GenerateHashWithSalt(
	seconds int,
	threads int,
	memory int,
	length int,
	key string,
	salt string,
) (ResultSet, error) {
	params, err := argon2id.NewParameters(
		uint32(seconds),
		uint32(memory),
		uint8(threads),
		uint32(length),
	)

	params.Salt = []byte(salt)

	if err != nil {
		return ResultSet{}, err
	}

	return generateHash(params, []byte(key))
}

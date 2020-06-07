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

package aph_test

import (
	"testing"

	"github.com/JordanOcokoljic/aph"
)

func TestParseTime(t *testing.T) {
	tests := []struct {
		name   string
		stamp  string
		millis int
		err    error
	}{
		{
			name:   "OneSecond",
			stamp:  "1s",
			millis: 1000,
			err:    nil,
		},
		{
			name:   "FiveHundredMilliseconds",
			stamp:  "500ms",
			millis: 500,
			err:    nil,
		},
		{
			name:   "PartialSecond",
			stamp:  "0.75s",
			millis: 750,
			err:    nil,
		},
		{
			name:   "MalformedStamp",
			stamp:  "32",
			millis: 0,
			err:    aph.ErrorMalformedStamp,
		},
		{
			name:   "PartialAtomicType",
			stamp:  "0.5ms",
			millis: 0,
			err:    aph.ErrorSplitAtomic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(s *testing.T) {
			millis, err := aph.ParseTime(test.stamp)
			if err != nil && test.err == nil {
				s.Fatalf(err.Error())
			}

			if millis != test.millis {
				s.Errorf("expected %d but was %d", test.millis, millis)
			}

			if test.err != nil && err == nil {
				s.Errorf("expected an error to occur but none did")
			}
		})
	}
}

func TestParseMemory(t *testing.T) {
	tests := []struct {
		name      string
		stamp     string
		kilobytes int
		err       error
	}{
		{
			name:      "InKilobytes",
			stamp:     "500KB",
			kilobytes: 500,
			err:       nil,
		},
		{
			name:      "InMegabytes",
			stamp:     "10MB",
			kilobytes: 10240,
			err:       nil,
		},
		{
			name:      "InGigabytes",
			stamp:     "1GB",
			kilobytes: 1048576,
		},
		{
			name:      "MalformedStamp",
			stamp:     "10B",
			kilobytes: 0,
			err:       aph.ErrorMalformedStamp,
		},
		{
			name:      "PartialAtomicType",
			stamp:     "0.5KB",
			kilobytes: 0,
			err:       aph.ErrorSplitAtomic,
		},
		{
			name:      "PartialMegabytes",
			stamp:     "0.5MB",
			kilobytes: 512,
			err:       nil,
		},
		{
			name:      "PartialGigabytes",
			stamp:     "0.75GB",
			kilobytes: 786432,
			err:       nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(s *testing.T) {
			kilobytes, err := aph.ParseMemory(test.stamp)
			if err != nil && test.err == nil {
				s.Fatalf(err.Error())
			}

			if kilobytes != test.kilobytes {
				s.Errorf("expected %d but was %d", test.kilobytes, kilobytes)
			}

			if test.err != nil && err == nil {
				s.Errorf("expected an error to occur but none did")
			}
		})
	}
}

func TestGenerateHash(t *testing.T) {
	var (
		seconds = 1
		threads = 1
		memory  = 64 * 1024
		length  = 8
		key     = "mypassword"
	)

	rs, err := aph.GenerateHash(seconds, threads, memory, length, key)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if rs.Time != seconds {
		t.Errorf("expected seconds to be %d but was %d", seconds, rs.Time)
	}

	if rs.Threads != threads {
		t.Errorf("expected threads to be %d but was %d", threads, rs.Threads)
	}

	if rs.Memory != memory {
		t.Errorf("expected memory to be %d but was %d", memory, rs.Memory)
	}

	if rs.Length != length {
		t.Errorf("expected length to be %d but was %d", length, rs.Length)
	}

	if rs.Key != key {
		t.Errorf("expected key to be %s but was %s", key, rs.Key)
	}
}

func TestGenerateHashWithSalt(t *testing.T) {
	var (
		seconds     = 1
		threads     = 1
		memory      = 64 * 1024
		length      = 8
		key         = "mypassword"
		salt        = "mysalt"
		expected    = "$argon2id$v=19$m=65536,t=1,p=1$bXlzYWx0$siUWf7GXJ34"
		expectedLen = 51
	)

	rs, err := aph.GenerateHashWithSalt(
		seconds,
		threads,
		memory,
		length,
		key,
		salt,
	)

	if err != nil {
		t.Fatalf(err.Error())
	}

	if rs.Time != seconds {
		t.Errorf("expected seconds to be %d but was %d", seconds, rs.Time)
	}

	if rs.Threads != threads {
		t.Errorf("expected threads to be %d but was %d", threads, rs.Threads)
	}

	if rs.Memory != memory {
		t.Errorf("expected memory to be %d but was %d", memory, rs.Memory)
	}

	if rs.Length != length {
		t.Errorf("expected length to be %d but was %d", length, rs.Length)
	}

	if rs.Key != key {
		t.Errorf("expected key to be %s but was %s", key, rs.Key)
	}

	if rs.Hash != expected {
		t.Errorf("expected hash to be %s but was %s", expected, rs.Hash)
	}

	if rs.Characters != expectedLen {
		t.Errorf(
			"expected characters to be %d but was %d",
			expectedLen,
			rs.Characters,
		)
	}
}

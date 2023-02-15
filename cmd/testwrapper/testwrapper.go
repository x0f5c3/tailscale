// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// testwrapper is a wrapper for retrying flaky tests, it is meant to be called
// in place of 'go test'. It assumes the first argument is the package to test,
// and the rest of the arguments are passed to 'go test'.
//
// Tests that are flaky can use the 'flakytest' subpackage to mark themselves as flaky
// and will be retried on failure.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"tailscale.com/cmd/testwrapper/flakytest"
)

const maxAttempts = 3

type testAttempt struct {
	name          testName
	outcome       string // "pass", "fail", "skip"
	logs          []string
	isMarkedFlaky bool // set if the test is marked as flaky
}

type testName struct {
	pkg  string
	name string
}

type packageTests struct {
	pkg   string
	tests []string
}

var debug = os.Getenv("TS_TESTWRAPPER_DEBUG") != ""

func runTests(ctx context.Context, pt *packageTests, otherArgs []string) []testAttempt {
	args := []string{"test", "-json", pt.pkg}
	args = append(args, otherArgs...)
	if len(pt.tests) > 0 {
		runArg := strings.Join(pt.tests, "|")
		args = append(args, "-run", runArg)
	}
	if debug {
		fmt.Println("running", strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("error creating stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		log.Printf("error starting test: %v", err)
		os.Exit(1)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmd.Wait()
	}()

	jd := json.NewDecoder(r)
	resultMap := make(map[testName]*testAttempt)
	var out []testAttempt
	for {
		var goOutput struct {
			Time    time.Time
			Action  string
			Package string
			Test    string
			Output  string
		}
		if err := jd.Decode(&goOutput); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				break
			}
			panic(err)
		}
		if goOutput.Test == "" {
			continue
		}
		if isSubtest := strings.Contains(goOutput.Test, "/"); isSubtest {
			continue
		}
		name := testName{
			pkg:  goOutput.Package,
			name: goOutput.Test,
		}
		switch goOutput.Action {
		case "start":
			// ignore
		case "run":
			resultMap[name] = &testAttempt{
				name: name,
			}
		case "skip", "pass", "fail":
			resultMap[name].outcome = goOutput.Action
			out = append(out, *resultMap[name])
		case "output":
			if strings.TrimSpace(goOutput.Output) == flakytest.FlakyTestLogMessage {
				resultMap[name].isMarkedFlaky = true
			} else {
				resultMap[name].logs = append(resultMap[name].logs, goOutput.Output)
			}
		}
	}
	<-done
	return out
}

func main() {
	ctx := context.Background()
	if len(os.Args) < 2 {
		fmt.Println("no package specified")
		os.Exit(1)
	}
	pkg, otherArgs := os.Args[1], os.Args[2:]

	toRun := []*packageTests{ // packages still to test
		{pkg: pkg},
	}

	pkgAttempts := make(map[string]int) // tracks how many times we've tried a package

	for len(toRun) > 0 {
		var pt *packageTests
		pt, toRun = toRun[0], toRun[1:]

		toRetry := make(map[string][]string) // pkg -> tests to retry

		failed := false
		for _, tr := range runTests(ctx, pt, otherArgs) {
			if tr.outcome != "fail" {
				continue
			}
			if tr.isMarkedFlaky {
				toRetry[tr.name.pkg] = append(toRetry[tr.name.pkg], tr.name.name)
			} else {
				failed = true
			}
			for _, l := range tr.logs {
				fmt.Fprint(os.Stderr, l)
			}
		}
		if failed {
			os.Exit(1)
		}
		for pkg, tests := range toRetry {
			pkgAttempts[pkg]++
			if pkgAttempts[pkg] >= maxAttempts {
				fmt.Println("Too many attempts for flaky tests:", pkg, tests)
				continue
			}
			fmt.Println("Retrying flaky tests:", pkg, tests)
			toRun = append(toRun, &packageTests{
				pkg:   pkg,
				tests: tests,
			})
		}
	}
	for _, a := range pkgAttempts {
		if a >= maxAttempts {
			os.Exit(1)
		}
	}
	fmt.Println("All tests passed.")
}

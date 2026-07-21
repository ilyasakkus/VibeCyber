// Package cli implements the WebCyber command-line contract.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/webcyber/webcyber/internal/model"
	"github.com/webcyber/webcyber/internal/report"
	"github.com/webcyber/webcyber/internal/scan"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stderr)
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printRootUsage(stdout)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, scan.Version)
		return 0
	}
	if args[0] != "scan" {
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printRootUsage(stderr)
		return 2
	}

	flags := flag.NewFlagSet("webcyber scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	typeValue := flags.String("type", "", "scan type: web, source, mobile, or desktop")
	target := flags.String("target", "", "URL or local file/directory path")
	profileValue := flags.String("profile", string(model.ProfileSafe), "profile: observe or safe")
	formatValue := flags.String("format", string(report.FormatJSON), "output format: json or sarif")
	flags.Usage = func() { printScanUsage(flags.Output()) }
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		printScanUsage(stderr)
		return 2
	}
	scanType := model.ScanType(*typeValue)
	profile := model.Profile(*profileValue)
	outputFormat := report.Format(*formatValue)
	if !scanType.Valid() {
		fmt.Fprintf(stderr, "invalid --type %q (expected web, source, mobile, or desktop)\n", *typeValue)
		return 2
	}
	if *target == "" {
		fmt.Fprintln(stderr, "--target is required")
		return 2
	}
	if !profile.Valid() {
		fmt.Fprintf(stderr, "invalid --profile %q (expected observe or safe)\n", *profileValue)
		return 2
	}
	if !outputFormat.Valid() {
		fmt.Fprintf(stderr, "invalid --format %q (expected json or sarif)\n", *formatValue)
		return 2
	}

	result, scanErr := scan.NewDefault().Scan(ctx, scan.Config{Type: scanType, Target: *target, Profile: profile})
	if err := report.Write(stdout, outputFormat, result); err != nil {
		fmt.Fprintf(stderr, "write report: %v\n", err)
		return 1
	}
	if scanErr != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", scanErr)
		return 1
	}
	return 0
}

func printRootUsage(w io.Writer) {
	fmt.Fprintln(w, "WebCyber - bounded, non-executing security scanner")
	fmt.Fprintln(w, "Usage: webcyber scan --type web|source|mobile|desktop --target <url|path> [--profile observe|safe] [--format json|sarif]")
}

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: webcyber scan --type web|source|mobile|desktop --target <url|path> --profile observe|safe --format json|sarif")
}

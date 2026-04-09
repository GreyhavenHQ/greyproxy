package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xlogger "github.com/greyhavenhq/greyproxy/internal/gostx/logger"
	"github.com/kardianos/service"
)

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

var (
	cfgFile      string
	outputFormat string
	services     stringList
	nodes        stringList
	debug        bool
	trace        bool
	metricsAddr  string
	silentAllow  bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

	args := strings.Join(os.Args[1:], "  ")

	if strings.Contains(args, " -- ") {
		var (
			wg  sync.WaitGroup
			ret int
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for wid, wargs := range strings.Split(" "+args+" ", " -- ") {
			wg.Add(1)
			go func(wid int, wargs string) {
				defer wg.Done()
				defer cancel()
				worker(wid, strings.Split(wargs, "  "), &ctx, &ret)
			}(wid, strings.TrimSpace(wargs))
		}

		wg.Wait()

		os.Exit(ret)
	}
}

func worker(id int, args []string, ctx *context.Context, ret *int) {
	cmd := exec.CommandContext(*ctx, os.Args[0], args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), fmt.Sprintf("_GREYPROXY_ID=%d", id))

	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
	if cmd.ProcessState.Exited() {
		*ret = cmd.ProcessState.ExitCode()
	}
}

func parseFlags() {
	var printVersion bool

	flag.Var(&services, "L", "service list")
	flag.Var(&nodes, "F", "chain node list")
	flag.StringVar(&cfgFile, "C", "", "configuration file")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.StringVar(&outputFormat, "O", "", "output format, one of yaml|json format")
	flag.BoolVar(&debug, "D", false, "debug mode")
	flag.BoolVar(&trace, "DD", false, "trace mode")
	flag.StringVar(&metricsAddr, "metrics", "", "metrics service address")
	flag.BoolVar(&silentAllow, "silent-allow", false, "activate silent allow-all mode until restart")
	flag.Parse()

	if printVersion {
		_, _ = fmt.Fprintf(os.Stdout, "greyproxy %s (%s %s/%s)\n  built:  %s\n  commit: %s\n",
			version, runtime.Version(), runtime.GOOS, runtime.GOARCH, buildTime, gitCommit)
		os.Exit(0)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		os.Args = append(os.Args[:1], os.Args[2:]...)
		parseFlags()

		log := xlogger.NewLogger()
		logger.SetDefault(log)

		p := &program{}
		p.initParser()

		svcConfig := &service.Config{
			Name:        "greyproxy",
			DisplayName: "Greyproxy",
			Description: "Greyproxy network proxy service",
		}

		s, err := service.New(p, svcConfig)
		if err != nil {
			logger.Default().Fatal(err)
		}

		if err := s.Run(); err != nil {
			logger.Default().Fatal(err)
		}

	case "service":
		handleServiceCommand(os.Args[2:])

	case "install":
		handleInstall(os.Args[2:])

	case "uninstall":
		handleUninstall(os.Args[2:])

	case "cert":
		handleCert(os.Args[2:])

	case "-V", "--version":
		_, _ = fmt.Fprintf(os.Stdout, "greyproxy %s (%s %s/%s)\n  built:  %s\n  commit: %s\n",
			version, runtime.Version(), runtime.GOOS, runtime.GOARCH, buildTime, gitCommit)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `greyproxy %s (%s %s/%s)

Usage: greyproxy <command>

Commands:
  serve       Run the proxy server in foreground
  cert        Manage MITM CA certificate (generate/install/uninstall)
  install     Install binary and register as a background service [-f]
  uninstall   Stop service, remove registration and binary [-f]
  service     Manage the OS service (start/stop/restart/status/...)

Run "greyproxy --version" to print version info.
Run "greyproxy service" for service subcommand help.
`, version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

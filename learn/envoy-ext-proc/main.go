// Package main provides a gRPC server for Envoy External Processing.
//
// YOUR TASK: Complete Task 4 to build a working gRPC server that:
// 1. Listens on a configurable port (default: 50051)
// 2. Registers the HeaderProcessor service
// 3. Handles graceful shutdown on SIGINT/SIGTERM
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	port := flag.Int("port", 50051, "gRPC server port")
	logLevel := flag.String("log-level", "info", "Logging level")
	flag.Parse()
	var level slog.Level
	err := level.UnmarshalText([]byte(*logLevel))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: invalid log level:", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		slog.Error("failed to listen", "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)
	processor := NewHeaderProcessor(logger)
	extproc.RegisterExternalProcessorServer(grpcServer, processor)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down...")
		grpcServer.GracefulStop()
	}()

	slog.Info("listening on port", "port", *port)
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

}

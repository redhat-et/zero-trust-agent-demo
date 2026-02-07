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
)

// Ensure these imports are used (remove when you use them)
var (
	_ = net.Listen
	_ = grpc.NewServer
	_ = extproc.RegisterExternalProcessorServer
	_ = signal.Notify
	_ = syscall.SIGTERM
)

func main() {
	// TODO: Task 4 - Parse command line flags
	//
	// Suggested flags:
	// --port: gRPC server port (default: 50051)
	// --log-level: Logging level (default: info)

	port := flag.Int("port", 50051, "gRPC server port")
	flag.Parse()

	// TODO: Create TCP listener
	//
	// lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	// if err != nil {
	//     slog.Error("failed to listen", "error", err)
	//     os.Exit(1)
	// }

	_ = port // Remove when you use

	// TODO: Create gRPC server
	//
	// grpcServer := grpc.NewServer()

	// TODO: Register the HeaderProcessor
	//
	// processor := &HeaderProcessor{}
	// extproc.RegisterExternalProcessorServer(grpcServer, processor)

	// TODO: Handle graceful shutdown
	//
	// go func() {
	//     sigCh := make(chan os.Signal, 1)
	//     signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	//     <-sigCh
	//     slog.Info("shutting down...")
	//     grpcServer.GracefulStop()
	// }()

	// TODO: Start serving
	//
	// slog.Info("starting ext-proc server", "port", *port)
	// if err := grpcServer.Serve(lis); err != nil {
	//     slog.Error("server error", "error", err)
	//     os.Exit(1)
	// }

	fmt.Println("Envoy ext-proc - Task 4: Implement this gRPC server")
	fmt.Println("See README.md for instructions")
	os.Exit(0)
}

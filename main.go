package main

import (
	"fmt"
	"os"
	"text/tabwriter"
)

func main() {
	ports, err := ScanPorts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning ports: %v\n", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PORT\tPROTOCOL\tSTATE\tPID\tPROCESS")
	for _, p := range ports {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\n", p.Port, p.Protocol, p.State, p.PID, p.Process)
	}
	w.Flush()
}

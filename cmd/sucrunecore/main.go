// Sucrunecore is built with -buildmode=c-shared for the Android manager process.
// It must never be loaded in a native guest worker.
package main

func main() {}

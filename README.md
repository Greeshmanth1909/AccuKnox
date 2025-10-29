# AccuKnox
# Requirements
- go version go1.25.3
- linux kernel 6.8.0-86-generic

# Notes
- This was built on a linux/arm64 virtual machine running Ubuntu 24.04
- This project uses cilium's ebpf-go tool chain https://github.com/cilium/ebpf/tree/main

# Instructions to build and run ps1 and ps2
1. run `go generate` to generate necessary scaffolding code
2. build with `go build` this generates a binary named `AccuKnox`
3. for ps1, dropping packets from a specified port: run `sudo ./AccuKnox -p <port number>` the default port is 4040. Please note that it only drops packets from the loop-back
   network interface. This can however be changed to any other network interface in the userspace go code.
4. for ps2, blocking all ports other than a specified port for a process: run `sudo ./AccuKnox -n <process name> -p <port number>`. The desired functionality is achieved by
   intercepting the `connect` systemcall with LSM.


# Problem Statement 3
1. How the highlighted constructs work
```
cnp := make(chan func(), 10)
    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
            }
        }()
    }
    cnp <- func() {
        fmt.Println("HERE1")
    }
```
This code snippet creates a buffered channel of functions. The loop creates a go routine that reads data from the channel into the variable `f`, which is a function and then calls it with `f()`. In the last line, a function that simply prints "HERE1" is pushed to the channel.

2. These constructs are generally used in concurrent programming with go routines
3. The for loop creates 4 go routines that read form the defined channel
4. make(chan func(), 10) creates a buffered channel.
5. "HERE1" will not be printed because the main go routine doesn't wait for the created go routines to execute and exits. This will print if the main routine yields the cpu either with the help of a wait group or by simply waiting for a few seconds.

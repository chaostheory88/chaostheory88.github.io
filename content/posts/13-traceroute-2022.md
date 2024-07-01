---
title: "Writing a simple Traceroute in Go"
date: 2022-11-08
draft: false
toc: false
images:
tags:
  - linux
  - security
  - programming
  - go
  - golang
  - applications
categories:
  - security
  - networking
---

If your question is why, the answer is quite simple: why not? And by the way, my favorite question is: how?

So, how does a traceroute program works in general? (_In this post we're considering traceroute in IPv4 networks_)

Well, basically traceroute exploits a very simple concept. It sends IPv4 packets starting with TTL = 1 to a remote host, continues incrementing it and expects back ICMPv4 TimeExceeded packets from intermediary hosts or an ICMPv4 EchoReply from the destination one.

IPv4 Packet
![ipv4_packet](/ipv4_packet.jpg)

ICMP Packet
![icmp_packet](/icmp_packet.jpg)


So, suppose we’re host `192.168.1.2` and our target is host `10.1.14.10`. And, suppose there are `N` hosts that need to be traversed before reaching our target. What happens then?

`192.168.1.1` forges a series of IPv4 packets that range from `1` to say `M` (where `M` is a tunable parameter to denote the maximum number of hosts to traverse). It sends those packets and maybe in a different thread starts waiting for ICMPv4 messages.

Notice that this explanation is pretty much simplistic and I encourage you to read manual page of [traceroute(8)](https://man7.org/linux/man-pages/man8/traceroute.8.html).

The simple traceroute program we’re going to build uses Linux ICMP sockets. Basically a kind of raw socket where we bind on an address and wait for ICMP packets. There’s a nice [Go package[](https://pkg.go.dev/golang.org/x/net) which will help us opening such kind of sockets and provides us all with all the data structures we need to parse and send packets.

So let’s start! _(Notice that here we will provide most interesting snippets of code, the complete code will be linked at the end of the article)_

First of all we need to import relevant packages we need:
```go
import (
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)
```
Now what?

Well, we create an ICMP socket in the main of our application and start listening on it:

```go
func main() {
    ...
    // start listening for ICMP messages
	c, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	...
}
```

Now that we’ve our connection object, we need a function that waits for packets on it and processes them. Of course we’re going to run this function in a different goroutine. Why? Because later we’re going to send packets from main routine and this routine will be already there to catch responses.

```go
func waitResponses(c *icmp.PacketConn, timeout time.Duration,
	startTime float64, targetHost string, maxTTL int, id int, wg *sync.WaitGroup) {
	wg.Add(1)

	// create a new Timer
	timer := time.NewTimer(timeout)

	// create a map to receive results
	results := make(map[int]Result, 0)
	
	go func() {
		for {
			// Read the response
			reply := make([]byte, 1500)
			n, peer, err := c.ReadFrom(reply)
			if err != nil {
				break
			}

			// Parse the response
			rm, err := icmp.ParseMessage(1, reply[:n])
			if err != nil {
				log.Println("failed to parse ICMPv4 message: ", err)
				break
			}

			// check type of ICMP message
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				t, ok := rm.Body.(*icmp.Echo)
				if !ok {
					log.Println("not an echo reply")
					break
				}

				// we skip if the response does not
				// come from the target host
				if peer.String() != targetHost {
					continue
				}

                // store results in a map keyed by thesequence number
				r := Result{
					IP:            peer.String(),
					HOP:           t.Seq,
					TimeElapsedMS: float64(time.Now().UnixNano()/1000000) - startTime,
				}

				// store the result
				results[t.Seq] = r
			case ipv4.ICMPTypeTimeExceeded:
				// cast to icmp.TimeExceeded
				t, ok := rm.Body.(*icmp.TimeExceeded)
				if !ok {
					log.Println("failed to cast to icmp.TimeExceeded")
					break
				}

				// icmp.TimeExceeded contains the original packet
				// so we grab IPv4 header and ICMP header
				ipHdr, err := icmp.ParseIPv4Header(t.Data)
				if err != nil {
					log.Println("failed to parse IPv4 header", err)
					break
				}

				// grab the ICMP header
				if icmpMsg, err := icmp.ParseMessage(1, t.Data[ipHdr.Len:]); err == nil {
					if msg, ok := icmpMsg.Body.(*icmp.Echo); ok && msg.ID == id {
						r := Result{
							IP:            peer.String(),
							HOP:           msg.Seq,
							TimeElapsedMS: float64(time.Now().UnixNano()/1000000) - startTime,
						}
						results[msg.Seq] = r
					}
				} else {
					log.Println("failed to parse inner ICMPv4 message", err)
				}
			default:
				log.Printf("Unexpected response %+v: %s", rm, peer.String())
			}
		}
	}()

	<-timer.C
	
	// print the results
	for i := 1; i <= maxTTL; i++ {
		if r, ok := results[i]; ok {
			fmt.Printf("%d\t%s\t%.2f ms\n", r.HOP, r.IP, r.TimeElapsedMS)
			if r.IP == targetHost {
				break
			}
		} else {
			fmt.Printf("%d\t*\n", i)
		}
	}

	wg.Done()
}
```

Do not get intimidated by this code, we’re just going to break it down!

First of all, parameters:
* `c` is our packet connection we just created into our main.
* `timeout` is the maximum timeout we’re going to wait for packets to come. We don’t want our program runs forever, right?
* `startTime` is the time in milliseconds from Epoch when we started our program
* `targetHost` is the final host we want to reach with our packets
* `maxTTL` is the maximum number of the TTL we used aka the maximum number of hosts that we could traverse to reach our target
* `id` is a crafted ID that we use to check that’s the reply TimeExceeded packet we’re waiting for, e.g., is one of those we forged (more on this later)
* `wg` is a WaitGroup, we use it so our main routine does not just exits before we finish to process packets or timeout has just expired

We first create some variables we’ll need in this routine:
* a timer to control if we’ve reached a timeout and so we’ve to just return
* a map were we’re going to store a Result objects as values (more in a moment). Key is the TTL of a packet, so we can check in which position of the route it was the traversed host.

```go
// create a new Timer
	timer := time.NewTimer(timeout)

	// create a map to receive results
	results := make(map[int]Result, 0)
```
Here there’s our result type:

```go
type Result struct {
    // IP address of this HOP
	IP            string
	// HOP number (aka initial TTL that produced this host)
	HOP           int
	// How did it take in millisecs for this host to reply our packet
	TimeElapsedMS float64
}
```

Now we create a new goroutine.

```go
go func() {
		for {
			// Read the response
			reply := make([]byte, 1500)
			n, peer, err := c.ReadFrom(reply)
			if err != nil {
				break
			}

			// Parse the response
			rm, err := icmp.ParseMessage(1, reply[:n])
			if err != nil {
				log.Println("failed to parse ICMPv4 message: ", err)
				break
			}
            ...snipped...
	}()
```

We loop reading packets, since IPv4 maximum transfer unit is 1500 bytes, we prepare a buffer large enough to hold it. The ReadFrom function on the c connection object returns us:

* `n` which is the number of byte read from the connection
* `peer` is a net.Addr object which contains IPv4 source address of the packet
* `err` will be not nil if something went wrong while reading the packet

Once we’ve our `reply` buffer filled with our `ICMPv4` packet data we use `icmp.ParseMessage` and give to this function the protocol number (`1` for `ICMPv4`) and a slice of the buffer from start to `n`.

```go
package icmp // import "golang.org/x/net/icmp"

type Message struct {
	Type     Type        // type, either ipv4.ICMPType or ipv6.ICMPType
	Code     int         // code
	Checksum int         // checksum
	Body     MessageBody // body
}
    A Message represents an ICMP message.
```

Since the socket will return us all `ICMPv4` packets observed on the “wire” we now need to check the Message.Type field and start filtering the information we need:

```go
...snipped...
			// check type of ICMP message
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				t, ok := rm.Body.(*icmp.Echo)
				if !ok {
					log.Println("not an echo reply")
					break
				}

				// we skip if the response does not
				// come from the target host
				if peer.String() != targetHost {
					continue
				}

				// store results in a map keyed by thesequence number
				r := Result{
					IP:            peer.String(),
					HOP:           t.Seq,
					TimeElapsedMS: float64(time.Now().UnixNano()/1000000) - startTime,
				}

				// store the result
				results[t.Seq] = r
			...snipped...
```

In case of type `ipv4.ICMPTypeEchoReply` it means that possibly our target host answered us, but we’re not sure yet, since we possibly intercepted a packet coming from an unrelated network event. So, we first cast body of the message to an `icmp.Echo` type, then we check that the peer from which answer is coming is our target host. If not we just continue looping. In case answer from our target host we create a Result struct and we fill it with the source IP of the packet, the sequence number (more on this later) of the ICMPv4 EchoReply which tells us which HOP was in the route and the elapsed time in milliseconds since we started our program.

In case we receive a `ipv4.ICMPTypeTimeExceeded` we’ve to do different things:

```go
case ipv4.ICMPTypeTimeExceeded:
    // cast to icmp.TimeExceeded
    t, ok := rm.Body.(*icmp.TimeExceeded)
    if !ok {
        log.Println("failed to cast to icmp.TimeExceeded")
        break
    }

    // icmp.TimeExceeded contains the original packet
    // so we grab IPv4 header and ICMP header
    ipHdr, err := icmp.ParseIPv4Header(t.Data)
    if err != nil {
        log.Println("failed to parse IPv4 header", err)
        break
    }

    // grab the ICMP header
    if icmpMsg, err := icmp.ParseMessage(1, t.Data[ipHdr.Len:]); err == nil {
        if msg, ok := icmpMsg.Body.(*icmp.Echo); ok && id == msg.ID {
            r := Result{
                IP:            peer.String(),
                HOP:           msg.Seq,
                TimeElapsedMS: float64(time.Now().UnixNano()/1000000) - startTime,
            }
            results[msg.Seq] = r
        }
    } else {
        log.Println("failed to parse inner ICMPv4 message", err)
    }
```


First we cast the body as we did before to the appropriate ICMPv4 message type, in this case `icmp.TimeExceeded`. What happens then? Well, in case of TimeExceeded the original datagram is appended starting from the ICMPv4 message body. So we’ve an IPv4 header followed by the original ICMPv4 message. We first use a facility offered by the icmp package to parse the IPv4 header, we’ll need its length in order to understand where the ICMPv4 payload starts after it. Then we use again our familiar `icmp.ParseMessage` function to get the original ICMPv4 message we sent. We check then that we can cast to `icmp.Echo` and in a positive case, if also the ID matches the one we assigned the original packet, we build a new `Result` structure filling it with necessary information as we did before.

OK, now we miss last part of the puzzle of this dirty function. We’ve either received a reply from target or we incurred in some timeout because we got no response from it.

```go
...snipped...
    // wait for the timer to expire
    <-timer.C

	// print the results
	for i := 1; i <= maxTTL; i++ {
		if r, ok := results[i]; ok {
			fmt.Printf("%d\t%s\t%.2f ms\n", r.HOP, r.IP, r.TimeElapsedMS)
			if r.IP == targetHost {
				break
			}
		} else {
			fmt.Printf("%d\t*\n", i)
		}
	}

	wg.Done()
```

In the code snippet above we block waiting for the timer to expire. In the former situation we print a message signaling that timeout has expired and proceed, in the latter we just proceed. The final part is quite trivial. We iterate keys of our `map[int]Result` starting from the minimum to the maximum TTL (that we equaled to sequence number in our main) and print the results. Since we expect our target host to be the last one in the route, after we match we just stop printing and we signal the main routine we are done.

OK, now before we examine the main routine I’m going to show you a utility function we’re going to use to craft the packet we’re going to send:

```go
func createICMPPacket(id int, seq int) []byte {
	// Create a new ICMP message
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: id, Seq: seq,
			Data: []byte("GO-ROUTE"),
		},
	}
	// Marshal the message
	b, err := m.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	return b
}
```

This function is pretty easy to understand, we create an `icmp.Message` of type `ICMPTypeEcho` and we assign to it an `icmp.Echo` body. The function assigns to the body a custom id and a sequence number that we’ll use to track at which position in the route is a host. We then invoke the `Marshall` method and return a slice of bytes.

Finally our main routine:

```go
// create a custom identifier for the packets
	id := os.Getpid() & 0xffff

	// start time in milliseconds
	startTime := float64(time.Now().UnixNano()) / 1000000

	go waitResponses(c, *timeout,
		startTime, remoteHost.IP.String(), *maxHops, wg)

	for ttl := 1; ttl <= *maxHops; ttl++ {
		// Set the TTL
		if err := c.IPv4PacketConn().SetTTL(ttl); err != nil {
			log.Println("failed to set TTL: ", err)
			continue
		}

		// send N probes for each message
		for i := 0; i < *probes; i++ {

			// Create an ICMP packet
			b := createICMPPacket(id, ttl)

			// Send the packet
			if _, err := c.WriteTo(b, remoteHost); err != nil {
				log.Println("failed to write packet: ", err)
			}
		}
	}

	wg.Wait()
	```

We first register the time we’re starting to send packets and generate a custom ICMPv4 ID for the packets based on our PID, we trim it to 16 bits since it is the maximum size it can fit into the field. Then based on the number of HOPs we want to probe we start iterating on TTL value. For each packet we’re going to send we set the TTL value on the connection, so, from `1` to `maxHops`. Then after TTL has being set we send a certain number of probes (specified from the command line) for each of its values, notice here how we use our `createICMPPacket` function. The value of the sequence ID for each packet is equalized to the current TTL value we’re probing, finally we write the packet on the “wire”.

Lets try it:

```bash
$ sudo ./goroute -host google.com
traceroute to google.com (216.58.209.46), 30 hops max, timeout 2s, start time 2022-10-07T13:52:12+02:00
1	192.168.1.1	4.19 ms
2	*
3	172.18.1.254	10.19 ms
4	172.18.0.72	10.19 ms
5	172.19.184.160	16.19 ms
6	172.19.177.40	18.19 ms
7	172.19.177.8	33.19 ms
8	195.22.192.144	35.19 ms
9	72.14.198.6	31.19 ms
10	209.85.254.219	33.19 ms
11	108.170.232.181	36.19 ms
12	216.58.209.46	35.19 ms
```

OK, now lets see how the original traceroute behaves:
```bash
$ sudo traceroute -I google.com -n
traceroute to google.com (216.58.209.46), 30 hops max, 60 byte packets
 1  192.168.1.1  1.228 ms  3.508 ms  3.504 ms
 2  * * *
 3  172.18.1.254  7.655 ms  12.169 ms  12.166 ms
 4  172.18.0.72  9.643 ms  9.640 ms  9.637 ms
 5  172.19.184.160  13.877 ms  15.833 ms  15.830 ms
 6  172.19.177.40  17.888 ms  16.643 ms  16.426 ms
 7  172.19.177.8  29.721 ms  31.447 ms  31.429 ms
 8  195.22.192.144  29.406 ms  29.403 ms  28.994 ms
 9  72.14.198.6  24.729 ms  25.241 ms  25.318 ms
10  209.85.254.219  26.997 ms  27.152 ms  27.147 ms
11  108.170.232.181  30.354 ms  29.948 ms  30.173 ms
12  216.58.209.46  30.301 ms  30.295 ms  30.293 ms
```

Awesome! We did not miss any host! That’s great!

In conclusion this article just demonstrated how to write a simple traceroute tool in Go. Of course readers are encouraged to check the original [traceroute(8)](https://man7.org/linux/man-pages/man8/traceroute.8.html) – Linux manual page and explore further. What we did here is a very simple and naive version and the original tool has really tons of optimization and mode of operations. For example we used ICMPv4 packets to probe. But the original traceroute program is able to use half-open TCP connections and UDP connections too.